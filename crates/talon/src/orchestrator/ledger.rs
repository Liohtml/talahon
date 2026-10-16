//! What a running message container was handed and what it has answered.
//!
//! A message run starts with a prompt (the lane's pending messages) and may
//! receive follow-ups while it runs, each as an IPC input file. The agent
//! ends every turn with a success frame that names the input files the turn
//! consumed, so the host knows exactly which messages were answered — a
//! follow-up taken into the running turn is answered by that turn, one that
//! arrived while the agent was idle by the next one. Everything else is not
//! answered when the run ends: the turn that took it died (timeout, run
//! limit, out of memory) or the container closed before reading it.
//!
//! The ledger keeps the *committed* cursor: the newest message such that it
//! and every message before it were answered. While the run is in flight
//! that cursor is what gets persisted (a host crash re-runs what was not
//! answered), and when the run ends without answering everything the lane's
//! cursor goes back to it, so the rest runs again.

/// One message run's ledger.
#[derive(Debug)]
pub(crate) struct LaneLedger {
    committed: String,
    prompt_cursor: String,
    prompt_answered: bool,
    piped: Vec<Piped>,
    sealed: bool,
}

#[derive(Debug)]
struct Piped {
    file: String,
    cursor: String,
    answered: bool,
    /// The channel was told that a turn starts for this follow-up.
    signalled: bool,
    /// The channel was told that its turn completed.
    completed: bool,
}

impl LaneLedger {
    /// A run whose prompt holds the messages after `previous` up to
    /// `prompt_cursor`.
    pub(crate) fn new(previous: String, prompt_cursor: String) -> Self {
        Self {
            committed: previous,
            prompt_cursor,
            prompt_answered: false,
            piped: Vec::new(),
            sealed: false,
        }
    }

    /// The run is over: nothing more may be piped into it.
    pub(crate) fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// A follow-up was written as input file `file`; `cursor` is its newest
    /// message.
    pub(crate) fn record_pipe(&mut self, file: String, cursor: String) {
        self.piped.push(Piped {
            file,
            cursor,
            answered: false,
            signalled: false,
            completed: false,
        });
    }

    /// The channel was told that a turn starts for the follow-up in `file`.
    /// Returns whether that turn has already been answered, in which case
    /// the caller reports its completion (it was held back until now).
    pub(crate) fn signalled(&mut self, file: &str) -> bool {
        let Some(p) = self.piped.iter_mut().find(|p| p.file == file) else {
            return false;
        };
        p.signalled = true;
        if p.answered && !p.completed {
            p.completed = true;
            true
        } else {
            false
        }
    }

    /// A turn ended with a success frame naming the input files it
    /// consumed (`None`: an agent that does not report them, whose frames
    /// answer everything piped so far). Returns how many turn completions
    /// to report to the channel now: the prompt's (first frame) and one per
    /// follow-up answered whose turn start was already signalled.
    pub(crate) fn turn_answered(&mut self, consumed: Option<&[String]>) -> usize {
        let mut completions = 0;
        if !self.prompt_answered {
            self.prompt_answered = true;
            completions += 1;
        }
        for p in self.piped.iter_mut().filter(|p| !p.answered) {
            if consumed.is_none_or(|files| files.contains(&p.file)) {
                p.answered = true;
                if p.signalled {
                    p.completed = true;
                    completions += 1;
                }
            }
        }
        self.recompute();
        completions
    }

    /// The run ended; seal the ledger. A run that ended cleanly answered
    /// its prompt even if it reported no turn.
    pub(crate) fn finish(&mut self, clean: bool) {
        self.sealed = true;
        if clean {
            self.prompt_answered = true;
        }
        self.recompute();
    }

    /// Cursor through which every message was answered.
    pub(crate) fn committed(&self) -> &str {
        &self.committed
    }

    /// Every message the run was handed has been answered.
    pub(crate) fn all_answered(&self) -> bool {
        self.prompt_answered && self.piped.iter().all(|p| p.answered)
    }

    fn recompute(&mut self) {
        if !self.prompt_answered {
            return;
        }
        let mut committed = &self.prompt_cursor;
        for p in &self.piped {
            if !p.answered {
                break;
            }
            committed = &p.cursor;
        }
        self.committed.clone_from(committed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    #[test]
    fn follow_ups_are_committed_only_when_answered() {
        let mut l = LaneLedger::new("t0".into(), "t1".into());
        assert_eq!(l.committed(), "t0");
        l.record_pipe("a.json".into(), "t2".into());
        assert!(!l.signalled("a.json"));
        l.record_pipe("b.json".into(), "t3".into());
        assert!(!l.signalled("b.json"));
        // Turn 1 answered the prompt and took `a` in.
        assert_eq!(l.turn_answered(Some(&files(&["a.json"]))), 2);
        assert_eq!(l.committed(), "t2");
        assert!(!l.all_answered());
        // The run dies before `b` is answered: the lane goes back to t2.
        l.finish(false);
        assert!(l.is_sealed());
        assert_eq!(l.committed(), "t2");
        assert!(!l.all_answered());
    }

    #[test]
    fn a_completion_waits_for_its_turn_start() {
        let mut l = LaneLedger::new(String::new(), "t1".into());
        l.record_pipe("a.json".into(), "t2".into());
        // Answered before the channel heard that its turn started.
        assert_eq!(l.turn_answered(Some(&files(&["a.json"]))), 1);
        assert!(l.signalled("a.json"));
        assert!(!l.signalled("a.json"));
        assert_eq!(l.turn_answered(Some(&[])), 0);
        assert!(l.all_answered());
        assert_eq!(l.committed(), "t2");
    }

    #[test]
    fn an_error_before_any_answer_keeps_the_previous_cursor() {
        let mut l = LaneLedger::new("t0".into(), "t1".into());
        l.finish(false);
        assert_eq!(l.committed(), "t0");
        assert!(!l.all_answered());
        // A clean end answers the prompt even without a frame.
        let mut l = LaneLedger::new("t0".into(), "t1".into());
        l.finish(true);
        assert_eq!(l.committed(), "t1");
        assert!(l.all_answered());
    }

    #[test]
    fn unknown_and_unread_files_answer_nothing() {
        let mut l = LaneLedger::new("t0".into(), "t1".into());
        l.record_pipe("a.json".into(), "t2".into());
        l.signalled("a.json");
        assert_eq!(l.turn_answered(Some(&files(&["old.json"]))), 1);
        assert_eq!(l.committed(), "t1");
        // The container closed without reading `a`.
        l.finish(true);
        assert_eq!(l.committed(), "t1");
        assert!(!l.all_answered());
    }

    #[test]
    fn agents_without_reports_answer_everything_piped_so_far() {
        let mut l = LaneLedger::new("t0".into(), "t1".into());
        l.record_pipe("a.json".into(), "t2".into());
        l.signalled("a.json");
        assert_eq!(l.turn_answered(None), 2);
        l.record_pipe("b.json".into(), "t3".into());
        l.finish(true);
        assert_eq!(l.committed(), "t2");
        assert!(!l.all_answered());
    }
}
