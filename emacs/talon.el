;;; talon.el --- Emacs interface for Talon AI assistant -*- lexical-binding: t -*-

;; Author: Talon
;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: ai, assistant, chat
;;
;; Vanilla Emacs (init.el):
;;   (load-file "/opt/talon/emacs/talon.el")
;;   (global-set-key (kbd "C-c t c") #'talon-chat)
;;   (global-set-key (kbd "C-c t o") #'talon-org-send)
;;
;; Spacemacs (~/.spacemacs, in dotspacemacs/user-config):
;;   (load-file "/opt/talon/emacs/talon.el")
;;   (spacemacs/set-leader-keys "aTc" #'talon-chat)
;;   (spacemacs/set-leader-keys "aTo" #'talon-org-send)
;;
;; Doom Emacs (config.el):
;;   (load (expand-file-name "/opt/talon/emacs/talon.el"))
;;   (map! :leader
;;         :prefix ("T" . "Talon")
;;         :desc "Chat buffer" "c" #'talon-chat
;;         :desc "Send org"    "o" #'talon-org-send)
;;   ;; Evil users: teach evil about the C-c C-c send binding
;;   (after! evil
;;     (evil-define-key '(normal insert) talon-chat-mode-map
;;       (kbd "C-c C-c") #'talon-chat-send))

;;; Code:

(require 'cl-lib)
(require 'url)
(require 'json)
(require 'org)

;; ---------------------------------------------------------------------------
;; Customization

(defgroup talon nil
  "Talon AI assistant interface."
  :group 'tools
  :prefix "talon-")

(defcustom talon-host "localhost"
  "Hostname where Talon is running."
  :type 'string
  :group 'talon)

(defcustom talon-port 8766
  "Port for the Talon Emacs channel HTTP server."
  :type 'integer
  :group 'talon)

(defcustom talon-auth-token nil
  "Bearer token for Talon authentication (matches EMACS_AUTH_TOKEN in .env).
Leave nil if EMACS_AUTH_TOKEN is not set."
  :type '(choice (const nil) string)
  :group 'talon)

(defcustom talon-poll-interval 1.5
  "Seconds between response polls when waiting for a reply."
  :type 'number
  :group 'talon)

(defcustom talon-agent-name "Talon"
  "Display name for the Talon agent (matches ASSISTANT_NAME in .env)."
  :type 'string
  :group 'talon)

(defcustom talon-convert-to-org t
  "When non-nil, convert agent responses to org-mode format.
Uses pandoc when available; falls back to regex substitutions."
  :type 'boolean
  :group 'talon)

(defcustom talon-timestamp-format "%H:%M"
  "Format string for timestamps shown next to agent replies in the chat buffer.
Passed to `format-time-string'.  Set to nil to suppress timestamps."
  :type '(choice (const nil) string)
  :group 'talon)

;; ---------------------------------------------------------------------------
;; Formatting helpers

(defun talon--to-org (text)
  "Convert TEXT (markdown or plain) to org-mode markup.
Tries pandoc -f gfm -t org when available; falls back to regex."
  (if (not talon-convert-to-org)
      text
    (if (executable-find "pandoc")
        (with-temp-buffer
          (insert text)
          (let* ((coding-system-for-read 'utf-8)
                 (coding-system-for-write 'utf-8)
                 (exit (call-process-region
                        (point-min) (point-max)
                        "pandoc" t t nil "-f" "gfm" "-t" "org" "--wrap=none")))
            (if (zerop exit)
                (string-trim (buffer-string))
              text)))
      (talon--md-to-org-regex text))))

;; NOTE: This function expects standard markdown as input (e.g. **bold**, *italic*).
;; Agents responding on this channel must output markdown, not org-mode syntax.
;; If the agent outputs org-mode directly, markers like *bold* will be incorrectly
;; re-converted to /bold/ by the italic rule.
(defun talon--md-to-org-regex (text)
  "Lightweight markdown → org conversion using regexp substitutions."
  (let ((s text))
    ;; Fenced code blocks  ```lang\n…\n```  →  #+begin_src lang\n…\n#+end_src
    ;; (must run before inline-code to avoid mangling backticks)
    (setq s (replace-regexp-in-string
             "```\\([a-zA-Z0-9_-]*\\)\n\\(\\(?:.\\|\n\\)*?\\)```"
             (lambda (m)
               (let ((lang (match-string 1 m))
                     (body (match-string 2 m)))
                 (concat "#+begin_src " (if (string-empty-p lang) "text" lang)
                         "\n" body "#+end_src")))
             s t))
    ;; Bold **text** → *text*, italic *text* → /text/
    ;; Two-pass to prevent the italic regex from re-matching the bold result:
    ;; 1. Mark bold spans with a placeholder (control char \x01)
    (setq s (replace-regexp-in-string "\\*\\*\\(.+?\\)\\*\\*" "\x01\\1\x01" s))
    ;; 2. Convert remaining single-star spans to italic
    (setq s (replace-regexp-in-string "\\*\\(.+?\\)\\*" "/\\1/" s))
    ;; 3. Resolve bold placeholders to org bold markers
    (setq s (replace-regexp-in-string "\x01\\(.+?\\)\x01" "*\\1*" s))
    ;; Strikethrough  ~~text~~ → +text+
    (setq s (replace-regexp-in-string "~~\\(.+?\\)~~" "+\\1+" s))
    ;; Underline  __text__ → _text_
    (setq s (replace-regexp-in-string "__\\(.+?\\)__" "_\\1_" s))
    ;; Inline code  `code` → ~code~
    (setq s (replace-regexp-in-string "`\\([^`]+\\)`" "~\\1~" s))
    ;; ATX headings  ## …  →  ** …
    (setq s (replace-regexp-in-string
             "^\\(#+\\) "
             (lambda (m) (concat (make-string (length (match-string 1 m)) ?*) " "))
             s))
    ;; Links  [text](url) → [[url][text]]
    (setq s (replace-regexp-in-string
             "\\[\\([^]]+\\)\\](\\([^)]+\\))" "[[\\2][\\1]]" s))
    s))

(defun talon--format-timestamp ()
  "Return a formatted timestamp string, or nil if disabled."
  (when talon-timestamp-format
    (format-time-string talon-timestamp-format)))

;; ---------------------------------------------------------------------------
;; Internal state

(defvar talon--poll-timer nil
  "Timer used to poll for responses in the chat buffer.")

(defvar talon--last-timestamp 0
  "Epoch ms of the most recently received message.")

(defvar talon--pending nil
  "Non-nil while waiting for a response.")

(defvar-local talon--thinking-dot-count 0
  "Dot cycle counter for the animated thinking indicator.")

(defvar-local talon--input-beg nil
  "Marker for the start of the current user input area.")

;; ---------------------------------------------------------------------------
;; HTTP helpers

(defun talon--url (path)
  "Return the full URL for PATH on the Talon server."
  (format "http://%s:%d%s" talon-host talon-port path))

(defun talon--headers ()
  "Return alist of HTTP headers for Talon requests."
  (let ((hdrs '(("Content-Type" . "application/json"))))
    (when talon-auth-token
      (push (cons "Authorization" (concat "Bearer " talon-auth-token)) hdrs))
    hdrs))

(defun talon--post (text callback)
  "POST TEXT to Talon and call CALLBACK with the response alist."
  (let* ((url-request-method "POST")
         (url-request-extra-headers (talon--headers))
         (url-request-data (encode-coding-string
                            (json-encode `((text . ,text)))
                            'utf-8)))
    (url-retrieve
     (talon--url "/api/message")
     (lambda (status)
       (if (plist-get status :error)
           (message "Talon: POST error %s" (plist-get status :error))
         (goto-char (point-min))
         (re-search-forward "\n\n" nil t)
         (let ((data (ignore-errors (json-read))))
           (funcall callback data))))
     nil t t)))

(defun talon--poll (since callback)
  "GET messages newer than SINCE (epoch ms) and call CALLBACK with the list."
  (let* ((url-request-method "GET")
         (url-request-extra-headers (talon--headers)))
    (url-retrieve
     (talon--url (format "/api/messages?since=%d" since))
     (lambda (status)
       (unless (plist-get status :error)
         (goto-char (point-min))
         (re-search-forward "\n\n" nil t)
         (let* ((raw  (buffer-substring-no-properties (point) (point-max)))
                (body (decode-coding-string raw 'utf-8))
                (data (ignore-errors (json-read-from-string body)))
                (msgs (cdr (assq 'messages data))))
           (when msgs (funcall callback (append msgs nil))))))
     nil t t)))

;; ---------------------------------------------------------------------------
;; Chat buffer

(defvar talon-chat-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "RET")      #'newline)
    (define-key map (kbd "<return>") #'newline)
    (define-key map (kbd "C-c C-c") #'talon-chat-send)
    map)
  "Keymap for `talon-chat-mode'.")

(define-derived-mode talon-chat-mode org-mode "Talon"
  "Major mode for the Talon chat buffer.
Derives from org-mode so that org markup (headings, bold, code blocks,
etc.) is fontified automatically.  RET and <return> insert plain newlines
for multi-line input; send with C-c C-c."
  (setq-local word-wrap t)
  (visual-line-mode 1)
  ;; Disable org features that conflict with a linear chat buffer
  (setq-local org-return-follows-link nil)
  (setq-local org-cycle-emulate-tab nil)
  ;; Ensure send binding beats org-mode's C-c C-c via the buffer-local map
  (local-set-key (kbd "C-c C-c") #'talon-chat-send))

(defun talon--advance-input-beg ()
  "Move `talon--input-beg' to point-max in the chat buffer."
  (with-current-buffer (talon--chat-buffer)
    (when talon--input-beg (set-marker talon--input-beg nil))
    (setq talon--input-beg (copy-marker (point-max)))))

(defun talon--chat-buffer ()
  "Return the Talon chat buffer, creating it if necessary."
  (or (get-buffer "*Talon*")
      (with-current-buffer (get-buffer-create "*Talon*")
        (talon-chat-mode)
        (set-buffer-file-coding-system 'utf-8)
        (add-hook 'kill-buffer-hook #'talon--stop-poll nil t)
        (talon--insert-header)
        (setq talon--input-beg (copy-marker (point-max)))
        (current-buffer))))

(defun talon--insert-header ()
  "Insert the welcome header into the chat buffer."
  (let ((inhibit-read-only t))
    (insert (propertize
             (format "── Talon (%s) ──────────────────────────────\n\n"
                     talon-agent-name)
             'face 'font-lock-comment-face))))

(defun talon--chat-insert (speaker text)
  "Append SPEAKER: TEXT to the chat buffer."
  (with-current-buffer (talon--chat-buffer)
    (let* ((inhibit-read-only t)
           (is-agent (not (string= speaker "You")))
           (display-text (if is-agent (talon--to-org text) text))
           (ts (talon--format-timestamp))
           (label (if ts (format "%s [%s]" speaker ts) speaker))
           (face  (if is-agent 'font-lock-string-face 'font-lock-keyword-face)))
      (goto-char (point-max))
      (insert (propertize (concat label ": ") 'face face))
      (insert display-text "\n\n")
      (goto-char (point-max))
      (when is-agent
        (talon--advance-input-beg)))))

;;;###autoload
(defun talon-chat ()
  "Open the Talon chat buffer."
  (interactive)
  (pop-to-buffer (talon--chat-buffer))
  (goto-char (point-max)))

(defun talon-chat-send ()
  "Send the accumulated input area as a message to Talon.
Use C-c C-c to send; RET inserts a plain newline for multi-line messages."
  (interactive)
  (when talon--pending
    (message "Talon: waiting for previous response...")
    (cl-return-from talon-chat-send))
  (let* ((beg (if (and talon--input-beg (marker-buffer talon--input-beg))
                  (marker-position talon--input-beg)
                (line-beginning-position)))
         (text (string-trim (buffer-substring-no-properties beg (point-max)))))
    (when (string-empty-p text)
      (user-error "Nothing to send"))
    (let ((inhibit-read-only t))
      (delete-region beg (point-max)))
    (talon--chat-insert "You" text)
    (talon--advance-input-beg)
    (setq talon--pending t)
    (talon--post text
                    (lambda (data)
                      (when data
                        (setq talon--last-timestamp
                              (or (cdr (assq 'timestamp data))
                                  talon--last-timestamp))
                        (talon--start-thinking)
                        (talon--start-poll))))))

(defun talon--start-poll ()
  "Start polling for new messages."
  (talon--stop-poll)
  (setq talon--poll-timer
        (run-with-timer talon-poll-interval talon-poll-interval
                        #'talon--poll-tick)))

(defun talon--stop-poll ()
  "Stop the polling timer."
  (when talon--poll-timer
    (cancel-timer talon--poll-timer)
    (setq talon--poll-timer nil)))

(defun talon--start-thinking ()
  "Insert an animated thinking indicator at the end of the chat buffer."
  (with-current-buffer (talon--chat-buffer)
    (let ((inhibit-read-only t))
      (goto-char (point-max))
      (setq talon--thinking-dot-count 1)
      (insert (propertize (format "%s: .\n\n" talon-agent-name)
                          'talon-thinking t
                          'face 'font-lock-string-face)))))

(defun talon--tick-thinking ()
  "Advance the dot animation in the thinking indicator."
  (let ((buf (get-buffer "*Talon*")))
    (when buf
      (with-current-buffer buf
        (when talon--pending
          (let* ((inhibit-read-only t)
                 (pos (text-property-any (point-min) (point-max)
                                         'talon-thinking t)))
            (when pos
              (let* ((end (or (next-single-property-change
                               pos 'talon-thinking) (point-max)))
                     (n (1+ (mod talon--thinking-dot-count 3))))
                (setq talon--thinking-dot-count n)
                (delete-region pos end)
                (save-excursion
                  (goto-char pos)
                  (insert (propertize
                           (format "%s: %s\n\n" talon-agent-name
                                   (make-string n ?.))
                           'talon-thinking t
                           'face 'font-lock-string-face)))))))))))

(defun talon--clear-thinking ()
  "Remove the thinking indicator from the chat buffer."
  (let ((buf (get-buffer "*Talon*")))
    (when buf
      (with-current-buffer buf
        (let* ((inhibit-read-only t)
               (pos (text-property-any (point-min) (point-max)
                                       'talon-thinking t)))
          (when pos
            (delete-region pos (or (next-single-property-change
                                    pos 'talon-thinking) (point-max)))))))))

(defun talon--poll-tick ()
  "Poll for new messages and insert them into the chat buffer."
  (talon--tick-thinking)
  (talon--poll
   talon--last-timestamp
   (lambda (msgs)
     (dolist (msg msgs)
       (let ((text (cdr (assq 'text msg)))
             (ts   (cdr (assq 'timestamp msg))))
         (when (and text (> ts talon--last-timestamp))
           (setq talon--last-timestamp ts)
           (talon--clear-thinking)
           (talon--chat-insert talon-agent-name text))))
     (when msgs
       (setq talon--pending nil)
       (talon--stop-poll)))))

;; ---------------------------------------------------------------------------
;; Org integration

;;;###autoload
(defun talon-org-send ()
  "Send the current org subtree to Talon and insert the response as a child.

If a region is active, send the region text instead."
  (interactive)
  (unless (derived-mode-p 'org-mode)
    (user-error "Not in an org-mode buffer"))
  (let ((text (if (use-region-p)
                  (buffer-substring-no-properties (region-beginning) (region-end))
                (talon--org-subtree-text))))
    (when (string-empty-p (string-trim text))
      (user-error "Nothing to send"))
    (message "Talon: sending to %s..." talon-agent-name)
    (let ((marker (point-marker))
          (buf    (current-buffer)))
      (talon--post
       text
       (lambda (data)
         (let* ((ts (or (cdr (assq 'timestamp data)) (talon--now-ms)))
                (level (with-current-buffer buf
                         (save-excursion (goto-char marker) (org-outline-level))))
                (ph (with-current-buffer buf
                      (save-excursion
                        (goto-char marker)
                        (talon--org-insert-placeholder level)))))
           (talon--poll-until-response
            ts
            (lambda (response)
              (with-current-buffer buf
                (save-excursion
                  (when (marker-buffer ph)
                    (let* ((inhibit-read-only t)
                           (beg (marker-position ph))
                           (end (save-excursion
                                  (goto-char (1+ beg))
                                  (org-next-visible-heading 1)
                                  (point))))
                      (delete-region beg end))
                    (set-marker ph nil))
                  (goto-char marker)
                  (talon--org-insert-response response))))
            (lambda ()
              (message "Talon: timed out waiting for response")
              (when (marker-buffer ph)
                (with-current-buffer (marker-buffer ph)
                  (let* ((inhibit-read-only t)
                         (beg (marker-position ph))
                         (end (save-excursion
                                (goto-char (1+ beg))
                                (org-next-visible-heading 1)
                                (point))))
                    (delete-region beg end))
                  (set-marker ph nil)))))))))))

(defun talon--org-insert-placeholder (level)
  "Insert a processing child heading at LEVEL+1 and return a marker at its start."
  (org-back-to-heading t)
  (org-end-of-subtree t t)
  (let ((beg (point)))
    (insert "\n" (make-string (1+ level) ?*) " "
            talon-agent-name " [processing...]\n\n")
    (copy-marker beg)))

(defun talon--org-subtree-text ()
  "Return the text of the org subtree at point (heading + body)."
  (org-with-wide-buffer
   (org-back-to-heading t)
   (let ((start (point))
         (end   (progn (org-end-of-subtree t t) (point))))
     (buffer-substring-no-properties start end))))

(defun talon--org-insert-response (text)
  "Insert TEXT as a child org heading under the current subtree."
  (org-back-to-heading t)
  (let* ((level (org-outline-level))
         (child-stars (make-string (1+ level) ?*))
         (timestamp (format-time-string "[%Y-%m-%d %a %H:%M]"))
         (body (talon--to-org text)))
    (org-end-of-subtree t t)
    (insert "\n" child-stars " " talon-agent-name " " timestamp "\n"
            body "\n")))

(defun talon--now-ms ()
  "Return current time as milliseconds since epoch."
  (let ((time (current-time)))
    (+ (* (+ (* (car time) 65536) (cadr time)) 1000)
       (/ (caddr time) 1000))))

(defun talon--poll-until-response (since callback timeout-fn &optional attempts)
  "Poll until a message newer than SINCE arrives, then call CALLBACK.
Calls TIMEOUT-FN after 60 attempts (~90s)."
  (let ((n (or attempts 0)))
    (if (>= n 60)
        (funcall timeout-fn)
      (talon--poll
       since
       (lambda (msgs)
         (let ((fresh (seq-filter (lambda (m) (> (cdr (assq 'timestamp m)) since))
                                  msgs)))
           (if fresh
               (let ((text (mapconcat (lambda (m) (cdr (assq 'text m)))
                                      fresh "\n")))
                 (funcall callback text))
             (run-with-timer talon-poll-interval nil
                             #'talon--poll-until-response
                             since callback timeout-fn (1+ n)))))))))

;; ---------------------------------------------------------------------------

(provide 'talon)
;;; talon.el ends here
