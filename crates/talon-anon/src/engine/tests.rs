//! Engine tests: the Python proxy's behaviour first, then the extensions.

use super::*;
use serde_json::json;

const SHIPPED: &str = include_str!("../../fields.yaml");

/// The original (pre-Rust) fields.yaml semantics in miniature.
const PY_YAML: &str = r#"
categories:
  user:
    token_prefix: "USER"
    fields: [data_win_eventdata_user, data_win_eventdata_targetUserName]
  hostname:
    token_prefix: "HOST"
    fields: [agent_name]
  email:
    token_prefix: "EMAIL"
    fields: [data_win_eventdata_targetUserName, data_office365_UserId]
internal_ip_token_prefix: "IP_INT"
scan_user_paths: true
scan_inline_ips: true
preserve_fields: [data_win_eventdata_hashes, rule_description, data_win_eventdata_commandLine, data_srcip]
"#;

fn anon(yaml: &str) -> Anonymizer {
    Anonymizer::new(Arc::new(CompiledConfig::from_yaml_str(yaml).unwrap()))
}

fn shipped() -> Anonymizer {
    anon(SHIPPED)
}

fn text(a: &mut Anonymizer, s: &str) -> String {
    a.anonymize_text(s)
}

// ---------------------------------------------------------------------------
// Ported Python behaviour
// ---------------------------------------------------------------------------

#[test]
fn py_field_mapping_replaces_whole_value() {
    let mut a = anon(PY_YAML);
    let mut doc = json!({"data_win_eventdata_user": "john.doe", "agent_name": "WORKSTATION-01", "other": "x"});
    assert!(a.anonymize_json(&mut doc));
    assert_eq!(
        doc,
        json!({"data_win_eventdata_user": "USER_1", "agent_name": "HOST_1", "other": "x"})
    );
}

#[test]
fn py_later_category_wins_without_value_pattern() {
    let mut a = anon(PY_YAML);
    assert_eq!(
        a.anonymize_field("data_win_eventdata_targetUserName", "jdoe"),
        "EMAIL_1"
    );
}

#[test]
fn py_field_lookup_is_case_insensitive() {
    let mut a = anon(PY_YAML);
    assert_eq!(
        a.anonymize_field("DATA_WIN_EVENTDATA_USER", "bob"),
        "USER_1"
    );
    assert_eq!(a.anonymize_field("Agent_Name", "ws"), "HOST_1");
}

#[test]
fn py_preserved_fields_are_untouched() {
    let mut a = anon(PY_YAML);
    let mut doc = json!({
        "rule_description": "Logon from 10.0.0.5",
        "data_win_eventdata_commandLine": "type C:\\Users\\bob\\x.txt",
        "data_srcip": "192.168.1.10",
        "data_win_eventdata_hashes": "SHA256=AB12"
    });
    let before = doc.clone();
    assert!(!a.anonymize_json(&mut doc));
    assert_eq!(doc, before);
}

#[test]
fn py_inline_ips_internal_only() {
    let mut a = anon(PY_YAML);
    assert_eq!(
        text(
            &mut a,
            "Process connected to 10.0.1.55 on port 4444, then 8.8.8.8 and 10.0.1.55"
        ),
        "Process connected to IP_INT_1 on port 4444, then 8.8.8.8 and IP_INT_1"
    );
    assert_eq!(
        text(&mut a, "lo 127.0.0.1 ll 169.254.3.4 pub 1.1.1.1"),
        "lo IP_INT_2 ll IP_INT_3 pub 1.1.1.1"
    );
}

#[test]
fn py_windows_and_linux_user_paths() {
    let mut a = anon(PY_YAML);
    assert_eq!(
        text(&mut a, r"C:\Users\john.doe\AppData\Local\Temp\evil.exe"),
        r"C:\Users\USER_1\AppData\Local\Temp\evil.exe"
    );
    assert_eq!(
        text(&mut a, r"c:\users\john.doe\Desktop"),
        r"c:\users\USER_1\Desktop"
    );
    assert_eq!(
        text(&mut a, "/home/john.doe/.ssh/id_rsa"),
        "/home/USER_1/.ssh/id_rsa"
    );
    assert_eq!(text(&mut a, "/home/alice/x"), "/home/USER_2/x");
}

#[test]
fn py_lists_and_nested_objects() {
    let mut a = anon(PY_YAML);
    let mut doc =
        json!([{"agent_name": "A"}, {"agent_name": "B", "msg": ["see 10.0.0.1"]}, 5, null, true]);
    a.anonymize_json(&mut doc);
    assert_eq!(
        doc,
        json!([{"agent_name": "HOST_1"}, {"agent_name": "HOST_2", "msg": ["see IP_INT_1"]}, 5, null, true])
    );
}

#[test]
fn py_content_blocks_json_text_and_other_types() {
    let mut a = anon(PY_YAML);
    let mut content = vec![
        json!({"type": "text", "text": "{\"agent_name\": \"WS01\", \"n\": 3}"}),
        json!({"type": "text", "text": "plain 192.168.1.5"}),
        json!({"type": "image", "data": "aGVsbG8vaG9tZS9ib2Iv", "mimeType": "image/png"}),
    ];
    assert!(a.anonymize_content_blocks(&mut content, &FieldHints::new()));
    let parsed: Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(parsed, json!({"agent_name": "HOST_1", "n": 3}));
    assert_eq!(content[1]["text"], "plain IP_INT_1");
    assert_eq!(content[2]["data"], "aGVsbG8vaG9tZS9ib2Iv");
}

#[test]
fn py_tokens_consistent_and_reversible() {
    let mut a = anon(PY_YAML);
    let t1 = a.anonymize_field("agent_name", "WORKSTATION-01");
    let t2 = a.anonymize_field("agent_name", "WORKSTATION-01");
    assert_eq!(t1, t2);
    let ip = text(&mut a, "10.9.8.7");
    let report = format!("{t1} talked to {ip}");
    assert_eq!(
        a.deanonymize_text(&report),
        "WORKSTATION-01 talked to 10.9.8.7"
    );
}

#[test]
fn py_blank_values_untouched() {
    let mut a = anon(PY_YAML);
    let mut doc = json!({"agent_name": "", "data_win_eventdata_user": "  "});
    assert!(!a.anonymize_json(&mut doc));
}

// ---------------------------------------------------------------------------
// Field matching improvements
// ---------------------------------------------------------------------------

#[test]
fn nested_opensearch_hits_are_field_matched() {
    let mut a = shipped();
    let mut doc = json!({"hits": {"total": 1, "hits": [{
        "_index": "wazuh-alerts-4.x-2024.01.01",
        "_id": "a1",
        "_source": {
            "agent": {"name": "WS-FIN-01", "id": "007", "ip": "10.1.2.3"},
            "data": {"win": {"eventdata": {
                "targetUserName": "john.doe",
                "image": "C:\\Users\\john.doe\\AppData\\evil.exe",
                "hashes": "SHA256=ABCDEF0123,MD5=0011",
                "destinationIp": "8.8.8.8",
                "queryName": "evil.example.com"
            }, "system": {"eventID": "4624", "computer": "WS-FIN-01.corp.local"}}},
            "rule": {"description": "Logon from 10.1.2.3", "level": 12, "groups": ["windows", "authentication_success"]},
            "full_log": "An account was logged on: john.doe from 10.1.2.3"
        }
    }]}});
    a.anonymize_json(&mut doc);
    let s = doc.to_string();
    for leaked in ["john.doe", "WS-FIN-01", "10.1.2.3", "corp.local"] {
        assert!(!s.contains(leaked), "{leaked} leaked: {s}");
    }
    let src = &doc["hits"]["hits"][0]["_source"];
    assert_eq!(src["agent"]["name"], "HOST_1");
    assert_eq!(src["agent"]["id"], "007");
    assert_eq!(src["data"]["win"]["eventdata"]["targetUserName"], "USER_1");
    assert_eq!(
        src["data"]["win"]["eventdata"]["image"],
        "C:\\Users\\USER_1\\AppData\\evil.exe"
    );
    assert_eq!(
        src["data"]["win"]["eventdata"]["hashes"],
        "SHA256=ABCDEF0123,MD5=0011"
    );
    assert_eq!(src["data"]["win"]["eventdata"]["destinationIp"], "8.8.8.8");
    assert_eq!(
        src["data"]["win"]["eventdata"]["queryName"],
        "evil.example.com"
    );
    assert_eq!(src["data"]["win"]["system"]["eventID"], "4624");
    assert_eq!(
        src["data"]["win"]["system"]["computer"],
        "HOST_1.DOMAIN_INT_1"
    );
    assert_eq!(
        src["rule"]["description"], "Logon from IP_INT_1",
        "interpolated rule text is scanned"
    );
    assert_eq!(
        src["rule"]["groups"],
        json!(["windows", "authentication_success"])
    );
    assert_eq!(src["rule"]["level"], 12);
    assert_eq!(
        src["full_log"],
        "An account was logged on: USER_1 from IP_INT_1"
    );
    assert_eq!(
        doc["hits"]["hits"][0]["_index"],
        "wazuh-alerts-4.x-2024.01.01"
    );
}

#[test]
fn list_elements_inherit_their_field() {
    let mut a = shipped();
    let mut doc = json!({"related": {"user": ["alice", "bob"], "hosts": ["srv1"]}});
    a.anonymize_json(&mut doc);
    assert_eq!(
        doc,
        json!({"related": {"user": ["USER_1", "USER_2"], "hosts": ["HOST_1"]}})
    );
}

#[test]
fn value_pattern_splits_user_and_email() {
    let mut a = shipped();
    assert_eq!(
        a.anonymize_field("data_win_eventdata_targetUserName", "jdoe"),
        "USER_1"
    );
    assert_eq!(
        a.anonymize_field("data_win_eventdata_targetUserName", "j.doe@corp.com"),
        "EMAIL_1"
    );
    assert_eq!(
        a.anonymize_field("data.win.eventdata.targetUserName", "JDOE"),
        "USER_1"
    );
}

#[test]
fn domain_user_values_split_into_domain_and_user() {
    let mut a = shipped();
    assert_eq!(
        a.anonymize_field("data_win_eventdata_user", r"CORP\jsmith"),
        r"DOMAIN_INT_1\USER_1"
    );
    assert_eq!(
        a.anonymize_field("data_win_eventdata_targetUserName", "jsmith"),
        "USER_1"
    );
    assert_eq!(
        a.anonymize_field("data_win_eventdata_subjectDomainName", "CORP"),
        "DOMAIN_INT_1"
    );
    assert_eq!(
        a.anonymize_field("data_win_eventdata_user", r"NT AUTHORITY\SYSTEM"),
        r"NT AUTHORITY\SYSTEM"
    );
    assert_eq!(
        a.anonymize_field("data_win_eventdata_user", r"WORKGROUP\kim"),
        r"WORKGROUP\USER_2"
    );
}

#[test]
fn keep_values_and_placeholders_are_not_tokenized() {
    let mut a = shipped();
    for v in ["SYSTEM", "-", "ANONYMOUS LOGON", "root", "n/a"] {
        assert_eq!(a.anonymize_field("data_win_eventdata_targetUserName", v), v);
    }
    assert!(a.map().is_empty());
}

#[test]
fn host_fields_keep_public_ips_and_tokenize_internal_ones() {
    let mut a = shipped();
    assert_eq!(a.anonymize_field("agent_name", "8.8.4.4"), "8.8.4.4");
    assert_eq!(a.anonymize_field("agent_name", "10.0.0.9"), "IP_INT_1");
    assert_eq!(text(&mut a, "ping 10.0.0.9"), "ping IP_INT_1");
    assert_eq!(
        a.anonymize_field("agent_name", "web01.example.com"),
        "HOST_1"
    );
}

#[test]
fn verbatim_vs_scanned_preserved_fields() {
    let mut a = shipped();
    let mut doc = json!({
        "data_win_eventdata_commandLine": "net use \\\\fs01\\share /user:CORP\\bob && type C:\\Users\\bob\\x",
        "data_srcip": "192.168.5.5",
        "data_dstip": "1.2.3.4",
        "rule_groups": ["10.0.0.1"],
        "data_win_eventdata_hashes": "SHA1=C:\\Users\\bob\\"
    });
    a.anonymize_json(&mut doc);
    assert_eq!(
        doc["data_win_eventdata_commandLine"],
        "net use \\\\HOST_1\\share /user:DOMAIN_INT_1\\USER_1 && type C:\\Users\\USER_1\\x"
    );
    assert_eq!(doc["data_srcip"], "IP_INT_1");
    assert_eq!(doc["data_dstip"], "1.2.3.4");
    assert_eq!(doc["rule_groups"], json!(["10.0.0.1"]));
    assert_eq!(doc["data_win_eventdata_hashes"], "SHA1=C:\\Users\\bob\\");
}

#[test]
fn json_inside_string_values_is_parsed() {
    let mut a = shipped();
    let mut doc = json!({"full_log": "{\"win\":{\"eventdata\":{\"targetUserName\":\"jdoe\",\"ip\":\"10.0.0.3\"}}}"});
    a.anonymize_json(&mut doc);
    let inner: Value = serde_json::from_str(doc["full_log"].as_str().unwrap()).unwrap();
    assert_eq!(
        inner,
        json!({"win": {"eventdata": {"targetUserName": "USER_1", "ip": "IP_INT_1"}}})
    );
}

#[test]
fn deep_nesting_is_removed_not_leaked() {
    let mut a = shipped();
    let mut v = json!("10.0.0.1");
    for _ in 0..(MAX_DEPTH + 5) {
        v = json!([v]);
    }
    assert!(a.anonymize_json(&mut v));
    let s = v.to_string();
    assert!(!s.contains("10.0.0.1"));
    assert!(s.contains(DEPTH_PLACEHOLDER));
}

// ---------------------------------------------------------------------------
// Free-text detectors
// ---------------------------------------------------------------------------

#[test]
fn emails_in_free_text() {
    let mut a = shipped();
    assert_eq!(
        text(
            &mut a,
            "mail john.doe@acme.com, cc <Jane+x@corp.example.org>"
        ),
        "mail EMAIL_1, cc <EMAIL_2>"
    );
    assert_eq!(
        text(&mut a, "icon@2x.png and logo@3x.jpg"),
        "icon@2x.png and logo@3x.jpg"
    );
    assert_eq!(text(&mut a, "JOHN.DOE@ACME.COM"), "EMAIL_1");
}

#[test]
fn domain_user_in_free_text() {
    let mut a = shipped();
    assert_eq!(
        text(&mut a, r"Logon by CORP\jsmith succeeded"),
        r"Logon by DOMAIN_INT_1\USER_1 succeeded"
    );
    assert_eq!(
        text(&mut a, r"User: DESKTOP-AB12\alice."),
        r"User: DOMAIN_INT_2\USER_2."
    );
    for keep in [
        r"C:\Windows\System32\cmd.exe",
        r"HKLM\Software\Microsoft\Windows",
        r"NT AUTHORITY\SYSTEM",
        r"BUILTIN\Administrators",
        r"Window Manager\DWM-1",
        r"path Users\bob\Desktop",
        r"2024\report",
    ] {
        assert_eq!(text(&mut a, keep), keep);
    }
    assert_eq!(
        text(&mut a, r#""user":"CORP\\jsmith""#),
        r#""user":"DOMAIN_INT_1\\USER_1""#
    );
}

#[test]
fn unc_hosts() {
    let mut a = shipped();
    assert_eq!(
        text(&mut a, r"copy \\fileserver01\share\x.doc"),
        r"copy \\HOST_1\share\x.doc"
    );
    assert_eq!(text(&mut a, r"\\10.0.0.5\c$"), r"\\IP_INT_1\c$");
    assert_eq!(text(&mut a, r"\\8.8.8.8\pub"), r"\\8.8.8.8\pub");
    assert_eq!(text(&mut a, r"\\localhost\c$"), r"\\localhost\c$");
    assert_eq!(
        text(&mut a, r"\\?\C:\x and \\.\pipe\lsass"),
        r"\\?\C:\x and \\.\pipe\lsass"
    );
    assert_eq!(
        text(&mut a, r"C:\\Windows\\System32"),
        r"C:\\Windows\\System32"
    );
    assert_eq!(
        text(&mut a, r"\\FS01.corp.local\it"),
        r"\\HOST_2.DOMAIN_INT_1\it"
    );
}

#[test]
fn profile_paths_extended() {
    let mut a = shipped();
    assert_eq!(
        text(&mut a, "/Users/alice/Library/x"),
        "/Users/USER_1/Library/x"
    );
    assert_eq!(
        text(&mut a, r"%SystemDrive%\Users\bob\x"),
        r"%SystemDrive%\Users\USER_2\x"
    );
    assert_eq!(
        text(&mut a, r"C:\Users\Public\x.exe"),
        r"C:\Users\Public\x.exe"
    );
    assert_eq!(
        text(&mut a, r"USERPROFILE=C:\Users\carol"),
        r"USERPROFILE=C:\Users\USER_3"
    );
    assert_eq!(
        text(&mut a, r"D:/Users/John Smith/doc"),
        r"D:/Users/USER_4/doc"
    );
    assert_eq!(
        text(&mut a, r"C:\\Users\\dave\\AppData"),
        r"C:\\Users\\USER_5\\AppData"
    );
    assert_eq!(text(&mut a, "HOME=/home/erin"), "HOME=/home/USER_6");
    assert_eq!(text(&mut a, "see /home/erin."), "see /home/USER_6.");
    for keep in [
        "https://github.com/Users/frank/repo",
        "https://evil.com/home/index.html",
        "/var/lib/users/x/",
    ] {
        assert_eq!(text(&mut a, keep), keep);
    }
    assert_eq!(text(&mut a, "file:///home/gina/x"), "file:///home/USER_7/x");
}

#[test]
fn sids_keep_the_rid() {
    let mut a = shipped();
    assert_eq!(
        text(&mut a, "S-1-5-21-1111111-2222222-3333333-1104"),
        "SID_1-1104"
    );
    assert_eq!(
        text(&mut a, "admin S-1-5-21-1111111-2222222-3333333-500"),
        "admin SID_1-500"
    );
    assert_eq!(text(&mut a, "S-1-12-1-1-2-3-4"), "SID_2");
    assert_eq!(
        text(&mut a, "S-1-5-18 S-1-5-32-544"),
        "S-1-5-18 S-1-5-32-544"
    );
    assert_eq!(
        a.deanonymize_text("SID_1-500"),
        "S-1-5-21-1111111-2222222-3333333-500"
    );
}

#[test]
fn macs() {
    let mut a = shipped();
    assert_eq!(text(&mut a, "mac 00:1A:2B:3C:4D:5E."), "mac MAC_1.");
    assert_eq!(
        text(&mut a, "AA-BB-CC-DD-EE-01 0011.2233.4455"),
        "MAC_2 MAC_3"
    );
    assert_eq!(
        text(&mut a, "ff:ff:ff:ff:ff:ff 00:00:00:00:00:00"),
        "ff:ff:ff:ff:ff:ff 00:00:00:00:00:00"
    );
    assert_eq!(text(&mut a, "00-11-22-33-44-55-66"), "00-11-22-33-44-55-66");
    assert_eq!(
        text(&mut a, "123e4567-e89b-12d3-a456-426614174000"),
        "123e4567-e89b-12d3-a456-426614174000"
    );
}

#[test]
fn ipv6() {
    let mut a = shipped();
    assert_eq!(
        text(&mut a, "from fe80::1ff:fe23:4567:890a%eth0 ok"),
        "from IP_INT_1 ok"
    );
    assert_eq!(text(&mut a, "[fd12:3456:789a::1]:443"), "[IP_INT_2]:443");
    assert_eq!(
        text(&mut a, "mapped ::ffff:192.168.1.10."),
        "mapped IP_INT_3."
    );
    assert_eq!(text(&mut a, "addr:fe80::1"), "addr:IP_INT_4");
    for keep in [
        "2606:4700:4700::1111",
        "at 10:20:30 and 12:00",
        "std::vector",
        "::",
    ] {
        assert_eq!(text(&mut a, keep), keep);
    }
}

#[test]
fn internal_fqdns() {
    let yaml = SHIPPED.replace("internal_domains: []", "internal_domains: [acme.example]");
    let mut fresh = anon(&yaml);
    for keep in [
        "www.google.com",
        "ws01.corp.local.evil.com",
        "local admin",
        "x.localhost",
        "printer.home.arpa.example.net",
        "acme.example.org",
    ] {
        assert_eq!(text(&mut fresh, keep), keep);
    }
    assert!(fresh.map().is_empty());

    let mut a = anon(&yaml);
    assert_eq!(
        text(&mut a, "dc01.corp.local replied"),
        "HOST_1.DOMAIN_INT_1 replied"
    );
    assert_eq!(text(&mut a, "domain corp.local"), "domain DOMAIN_INT_1");
    assert_eq!(
        text(&mut a, "web.acme.example and acme.example"),
        "HOST_2.DOMAIN_INT_2 and DOMAIN_INT_2"
    );
    assert_eq!(text(&mut a, "DC01.CORP.LOCAL"), "HOST_1.DOMAIN_INT_1");
    // a known internal domain is still hidden when embedded in a crafted name
    assert_eq!(
        text(&mut a, "ws01.corp.local.evil.com"),
        "ws01.DOMAIN_INT_1.evil.com"
    );
    assert_eq!(text(&mut a, "printer.home.arpa"), "DOMAIN_INT_3");
    assert_eq!(
        a.deanonymize_text("HOST_2.DOMAIN_INT_2"),
        "web.acme.example"
    );
}

#[test]
fn public_values_and_hashes_untouched() {
    let mut a = shipped();
    let samples = [
        "8.8.8.8 1.1.1.1 2001:4860:4860::8888",
        "https://evil.example.com/payload.exe",
        "SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "MD5=d41d8cd98f00b204e9800998ecf8427e",
        "T1059.001 rule 92052 level 12",
        "2024-01-01T10:00:00.000+0000",
    ];
    for s in samples {
        assert_eq!(text(&mut a, s), s);
    }
}

// ---------------------------------------------------------------------------
// Sweep, idempotency, documents
// ---------------------------------------------------------------------------

#[test]
fn sweep_replaces_known_values_in_free_text_regardless_of_key_order() {
    let mut a = shipped();
    let mut doc = json!({
        "a_message": "Failed password for jdoe from WS-07; JDOE retried",
        "data_win_eventdata_targetUserName": "jdoe",
        "agent_name": "WS-07"
    });
    a.anonymize_json(&mut doc);
    assert_eq!(
        doc["a_message"],
        "Failed password for USER_1 from HOST_1; USER_1 retried"
    );
}

#[test]
fn sweep_respects_word_boundaries_and_min_length() {
    let mut a = shipped();
    a.anonymize_field("data_srcuser", "ann");
    a.anonymize_field("data_srcuser", "al");
    a.anonymize_field("data_srcuser", "1001");
    assert_eq!(
        text(&mut a, "annual report by ann's team"),
        "annual report by USER_1's team"
    );
    assert_eq!(text(&mut a, "al and 1001"), "al and 1001");
}

#[test]
fn sweep_index_handles_growth_and_rebuilds() {
    let mut a = shipped();
    for i in 0..(SWEEP_EXTRA_LIMIT * 2 + 3) {
        a.anonymize_field("data_srcuser", &format!("person{i}"));
        let out = text(&mut a, &format!("seen person{i} and person0"));
        assert_eq!(out, format!("seen USER_{} and USER_1", i + 1));
    }
}

#[test]
fn anonymization_is_idempotent() {
    let mut a = shipped();
    let input = r"CORP\jsmith on dc01.corp.local (10.0.0.4, fe80::1) wrote C:\Users\jsmith\x to \\fs\s mail jsmith@corp.com S-1-5-21-1-2-3-1104 00:11:22:33:44:55";
    let once = text(&mut a, input);
    let n = a.map().len();
    let twice = text(&mut a, &once);
    assert_eq!(once, twice);
    assert_eq!(a.map().len(), n, "no tokens allocated for tokens");
    assert_eq!(a.deanonymize_text(&once), input);
}

#[test]
fn embedded_json_in_text_content_is_field_matched() {
    let mut a = shipped();
    let t = "Search results from wazuh-*: {\"hits\":[{\"_source\":{\"agent\":{\"name\":\"WS9\"}}}]} (1 hit) [INFO] done";
    let out = a.anonymize_text_content(t, &FieldHints::new());
    assert_eq!(
        out,
        "Search results from wazuh-*: {\"hits\":[{\"_source\":{\"agent\":{\"name\":\"HOST_1\"}}}]} (1 hit) [INFO] done"
    );
    let pretty = "{\n  \"agent_name\": \"WS9\"\n}\n";
    assert_eq!(
        a.anonymize_text_content(pretty, &FieldHints::new()),
        "{\"agent_name\":\"HOST_1\"}\n"
    );
    let unchanged = "{\n  \"rule_id\": \"1\"\n}";
    assert_eq!(
        a.anonymize_text_content(unchanged, &FieldHints::new()),
        unchanged
    );
}

#[test]
fn tool_result_covers_structured_content_and_resources() {
    let mut a = shipped();
    let mut result = json!({
        "content": [
            {"type": "text", "text": "user jdoe seen"},
            {"type": "resource", "resource": {"uri": "file:///home/jdoe/r.txt", "mimeType": "text/plain", "text": "{\"data_dstuser\":\"jdoe\"}"}},
            {"type": "resource_link", "uri": "file:///home/kim/x", "name": "x"},
            {"type": "image", "data": "L2hvbWUvYm9iLw==", "mimeType": "image/png"}
        ],
        "structuredContent": {"agent": {"name": "WS1"}, "user": {"name": "jdoe"}},
        "isError": false,
        "_meta": {"note": "from 10.0.0.8"}
    });
    assert!(a.anonymize_tool_result(&mut result, &FieldHints::new()));
    assert_eq!(
        result["content"][0]["text"], "user USER_1 seen",
        "structured field learned before sweeping text"
    );
    assert_eq!(
        result["content"][1]["resource"]["text"],
        "{\"data_dstuser\":\"USER_1\"}"
    );
    assert_eq!(
        result["content"][1]["resource"]["uri"],
        "file:///home/USER_1/r.txt"
    );
    assert_eq!(result["content"][2]["uri"], "file:///home/USER_2/x");
    assert_eq!(result["content"][3]["data"], "L2hvbWUvYm9iLw==");
    assert_eq!(
        result["structuredContent"],
        json!({"agent": {"name": "HOST_1"}, "user": {"name": "USER_1"}})
    );
    assert_eq!(result["isError"], false);
    assert_eq!(result["_meta"]["note"], "from IP_INT_1");
}

#[test]
fn aggregation_hints_tokenize_bucket_keys() {
    let args = json!({"index": "wazuh-*", "body": {"size": 0, "aggs": {
        "by_user": {"terms": {"field": "data.win.eventdata.targetUserName", "size": 10},
                    "aggs": {"by_host": {"terms": {"field": "agent.name"}}, "per_day": {"date_histogram": {"field": "@timestamp"}}}},
        "combo": {"composite": {"sources": [{"src_host": {"terms": {"field": "agent.name"}}}]}}
    }}});
    let hints = FieldHints::from_arguments(&args);
    assert_eq!(
        hints.get("by_user"),
        Some("data.win.eventdata.targetUserName")
    );
    assert_eq!(hints.get("src_host"), Some("agent.name"));
    let as_string = FieldHints::from_arguments(&json!({"body": args["body"].to_string()}));
    assert_eq!(as_string, hints);

    let mut a = shipped();
    let mut resp = json!({"aggregations": {
        "by_user": {"buckets": [{"key": "jdoe", "doc_count": 3,
            "by_host": {"buckets": [{"key": "WS1", "doc_count": 3}]},
            "per_day": {"buckets": [{"key": 1704067200000u64, "key_as_string": "2024-01-01T00:00:00.000Z"}]}}]},
        "combo": {"after_key": {"src_host": "WS2"}, "buckets": [{"key": {"src_host": "WS2"}, "doc_count": 1}]}
    }});
    a.anonymize_json_with_hints(&mut resp, &hints);
    let b = &resp["aggregations"]["by_user"]["buckets"][0];
    assert_eq!(b["key"], "USER_1");
    assert_eq!(b["by_host"]["buckets"][0]["key"], "HOST_1");
    assert_eq!(
        b["per_day"]["buckets"][0]["key_as_string"],
        "2024-01-01T00:00:00.000Z"
    );
    assert_eq!(
        resp["aggregations"]["combo"]["after_key"]["src_host"],
        "HOST_2"
    );
    assert_eq!(
        resp["aggregations"]["combo"]["buckets"][0]["key"]["src_host"],
        "HOST_2"
    );

    let mut plain = shipped();
    let mut unhinted = json!({"aggregations": {"by_user": {"buckets": [{"key": "jdoe"}]}}});
    plain.anonymize_json(&mut unhinted);
    assert_eq!(
        unhinted["aggregations"]["by_user"]["buckets"][0]["key"], "jdoe",
        "no hint, unknown value"
    );
}

#[test]
fn keyed_buckets_and_ip_keys_are_rewritten() {
    let mut a = shipped();
    let mut hints = FieldHints::new();
    hints.insert("by_user", "user.name");
    let mut resp = json!({"aggregations": {
        "by_user": {"buckets": {"jdoe": {"doc_count": 1}, "SYSTEM": {"doc_count": 2}}},
        "by_ip": {"buckets": {"10.0.0.5": {"doc_count": 4}, "8.8.8.8": {"doc_count": 1}}}
    }});
    a.anonymize_json_with_hints(&mut resp, &hints);
    let users = resp["aggregations"]["by_user"]["buckets"]
        .as_object()
        .unwrap();
    assert!(
        users.contains_key("USER_1") && users.contains_key("SYSTEM") && !users.contains_key("jdoe")
    );
    let ips = resp["aggregations"]["by_ip"]["buckets"]
        .as_object()
        .unwrap();
    assert!(ips.contains_key("IP_INT_1") && ips.contains_key("8.8.8.8"));
    // ordinary field-name keys are never swept
    let mut b = shipped();
    b.anonymize_field("data_srcuser", "status");
    let mut doc = json!({"status": "ok"});
    b.anonymize_json(&mut doc);
    assert!(doc.get("status").is_some());
}

#[test]
fn colliding_renamed_keys_are_disambiguated() {
    let mut a = shipped();
    let mut doc = json!({"10.0.0.5": 1, "010.0.0.5": 2});
    a.anonymize_json(&mut doc);
    let keys: Vec<_> = doc.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| k.starts_with("IP_INT_")));
}

#[test]
fn deanonymize_json_handles_nested_json_strings() {
    let mut a = shipped();
    let user = a.anonymize_field("data_win_eventdata_user", r"CORP\jsmith");
    assert_eq!(user, r"DOMAIN_INT_1\USER_1");
    let mut args = json!({
        "index": "wazuh-*",
        "query": "agent.name:HOST_9 AND user:USER_1",
        "body": format!("{{\"query\":{{\"match\":{{\"user\":\"{}\"}}}}}}", user.replace('\\', "\\\\")),
        "n": 5
    });
    assert!(a.deanonymize_json(&mut args));
    assert_eq!(args["query"], "agent.name:HOST_9 AND user:jsmith");
    let body: Value = serde_json::from_str(args["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["query"]["match"]["user"], r"CORP\jsmith");
    let mut untouched = json!({"q": "nothing here"});
    assert!(!a.deanonymize_json(&mut untouched));
}

#[test]
fn debug_output_has_no_pii() {
    let mut a = shipped();
    a.anonymize_field("agent_name", "SECRET-HOST");
    assert!(!format!("{a:?}").contains("SECRET-HOST"));
}

// ---------------------------------------------------------------------------
// Leaks carried over from the Python proxy, and Rust-only ones
// ---------------------------------------------------------------------------

#[test]
fn numbers_in_pii_fields_are_tokenized() {
    let mut a = shipped();
    let mut doc = json!({"data_srcuser": 1001, "data_dstuser": 1001, "rule_level": 12});
    assert!(a.anonymize_json(&mut doc));
    assert_eq!(
        doc,
        json!({"data_srcuser": "USER_1", "data_dstuser": "USER_1", "rule_level": 12})
    );
}

#[test]
fn numeric_bucket_key_of_a_hinted_aggregation_is_tokenized() {
    let mut a = shipped();
    let hints = FieldHints::from_arguments(&json!({
        "body": {"aggs": {"users": {"terms": {"field": "data_srcuser"}}}}
    }));
    let mut doc = json!({"aggregations": {"users": {"buckets": [{"key": 1001, "doc_count": 3}]}}});
    assert!(a.anonymize_json_with_hints(&mut doc, &hints));
    assert_eq!(doc["aggregations"]["users"]["buckets"][0]["key"], "USER_1");
    assert_eq!(doc["aggregations"]["users"]["buckets"][0]["doc_count"], 3);
}

#[test]
fn value_not_matching_the_only_category_pattern_is_still_tokenized() {
    // data_office365_UserId is listed only under `email`; a value that is no
    // address used to fall through to the free-text detectors and leak.
    let mut a = shipped();
    assert_eq!(
        a.anonymize_field("data_office365_UserId", "jdoe"),
        "EMAIL_1"
    );
    assert_eq!(
        a.anonymize_field("data_office365_UserId", "jane@corp.example"),
        "EMAIL_2"
    );
    // A field listed under user and email still picks user for a bare name.
    assert_eq!(
        a.anonymize_field("data_win_eventdata_targetUserName", "bob"),
        "USER_1"
    );
}

#[test]
fn repeated_json_keys_never_pass_through_as_written() {
    let mut a = shipped();
    let t = r#"Result: {"msg":"login from 10.0.0.5","msg":"ok"}"#;
    let out = a.anonymize_text_content(t, &FieldHints::new());
    assert!(!out.contains("10.0.0.5"), "{out}");
    // Also inside a JSON document encoded in a string field.
    let mut doc = json!({"full_log": r#"{"src":"10.0.0.6","src":"x"}"#});
    a.anonymize_json(&mut doc);
    assert!(!doc.to_string().contains("10.0.0.6"), "{doc}");
    // A document without repeated keys that needs no change stays as written.
    let unchanged = r#"Result: {"a":  1, "b": "public 8.8.8.8"}"#;
    assert_eq!(
        a.anonymize_text_content(unchanged, &FieldHints::new()),
        unchanged
    );
}

#[test]
fn process_paths_and_logon_ids_are_not_user_names() {
    // callerProcessName / targetLogonId were listed as user fields: the path
    // became USER_n and the sweep then rewrote it inside commandLine.
    let mut a = shipped();
    let mut doc = json!({
        "data_win_eventdata_callerProcessName": r"C:\Windows\System32\net1.exe",
        "data_win_eventdata_targetLogonId": "0x3e7",
        "data_win_eventdata_commandLine": r"C:\Windows\System32\net1.exe localgroup administrators"
    });
    a.anonymize_json(&mut doc);
    assert_eq!(
        doc["data_win_eventdata_callerProcessName"],
        r"C:\Windows\System32\net1.exe"
    );
    assert_eq!(doc["data_win_eventdata_targetLogonId"], "0x3e7");
    assert_eq!(
        doc["data_win_eventdata_commandLine"],
        r"C:\Windows\System32\net1.exe localgroup administrators"
    );
}

#[test]
fn internal_ips_glued_to_names_are_tokenized() {
    let mut a = shipped();
    let out = text(
        &mut a,
        "conn_from_10.0.0.5 backup_192.168.1.20_2024.tar ip10.1.2.3 v1.2.3.4",
    );
    assert!(!out.contains("10.0.0.5"), "{out}");
    assert!(!out.contains("192.168.1.20"), "{out}");
    assert!(!out.contains("10.1.2.3"), "{out}");
    // Public addresses stay (needed for threat intel).
    assert!(out.contains("1.2.3.4"), "{out}");
}
