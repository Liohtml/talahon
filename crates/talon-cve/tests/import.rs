//! Import of the three sources into a database file and the queries on it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use serde_json::json;
use talon_cve::import::{ImportError, import_epss, import_kev, import_nvd_feed};
use talon_cve::store::{Reader, Search, Sort, StoreError, Table, Writer};

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn import_then_lookup_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cve.sqlite");
    build_db(&path, "2026-11-17T03:00:00Z");
    let reader = Reader::new(&path);

    let status = reader.status().unwrap();
    assert_eq!(
        (status.cve_count, status.epss_count, status.kev_count),
        (3, 3, 2)
    );
    assert_eq!(
        status.epss_score_date.as_deref(),
        Some("2026-11-17T12:03:07Z")
    );
    assert_eq!(status.epss_model_version.as_deref(), Some("v2026.06.15"));
    assert_eq!(status.kev_catalog_version.as_deref(), Some("2026.11.13"));

    let found = reader
        .lookup(
            &ids(&["CVE-2021-44228", "CVE-2026-0002", "CVE-2030-9999"]),
            true,
        )
        .unwrap();
    let log4j = &found[0];
    assert_eq!(log4j["found"], true);
    assert!(
        log4j["description"]
            .as_str()
            .unwrap()
            .starts_with("Apache Log4j2")
    );
    // The primary CVSS 3.1 is the headline; CVSS 2 stays in all_metrics.
    assert_eq!(log4j["cvss"]["base_score"], 10.0);
    assert_eq!(log4j["cvss"]["version"], "3.1");
    assert_eq!(log4j["all_metrics"].as_array().unwrap().len(), 2);
    assert_eq!(log4j["all_metrics"][1]["severity"], "HIGH");
    assert_eq!(log4j["cwe"], json!(["CWE-502"]));
    assert_eq!(
        log4j["products"],
        json!([{"vendor": "apache", "product": "log4j"}])
    );
    assert_eq!(log4j["cpe_matches"][0]["version_end_excluding"], "2.15.0");
    assert_eq!(log4j["cpe_matches_total"], 1);
    // The same link from two sources is one reference with both tags.
    let refs = log4j["references"].as_array().unwrap();
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0]["tags"], json!(["Vendor Advisory", "Patch"]));
    assert_eq!(log4j["epss"]["score"], 0.94358);
    assert_eq!(log4j["kev"]["known_ransomware_use"], "Known");
    // Known to EPSS only.
    assert_eq!(found[1]["found"], true);
    assert_eq!(found[1]["epss"]["percentile"], 0.12345);
    assert_eq!(found[1]["kev"], json!(null));
    // Known to nobody.
    assert_eq!(found[2]["found"], false);

    let without_refs = reader.lookup(&ids(&["CVE-2021-44228"]), false).unwrap();
    assert_eq!(without_refs[0]["references"], json!(null));
    assert_eq!(without_refs[0]["references_total"], 2);
}

#[test]
fn search_by_words_product_and_filters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cve.sqlite");
    build_db(&path, "2026-11-17T03:00:00Z");
    let reader = Reader::new(&path);
    let search = |s: Search| -> Vec<String> {
        reader
            .search(&s)
            .unwrap()
            .0
            .into_iter()
            .map(|h| h.id)
            .collect()
    };
    let base = || Search {
        limit: 10,
        ..Search::default()
    };

    // Words: description, product name, id.
    assert_eq!(
        search(Search {
            query: Some("heartbeat openssl".into()),
            ..base()
        }),
        ["CVE-2014-0160"]
    );
    assert_eq!(
        search(Search {
            query: Some("log4j".into()),
            ..base()
        }),
        ["CVE-2021-44228"]
    );
    assert_eq!(
        search(Search {
            query: Some("CVE-2014-0160".into()),
            ..base()
        }),
        ["CVE-2014-0160"]
    );
    assert!(
        search(Search {
            query: Some("heartbeat log4j".into()),
            ..base()
        })
        .is_empty()
    );
    // FTS syntax in the input is text, not an operator.
    assert!(
        search(Search {
            query: Some("heartbeat OR log4j".into()),
            ..base()
        })
        .is_empty()
    );
    // CPE names; the CNA's product of a CVE NVD has not analysed yet.
    assert_eq!(
        search(Search {
            vendor: Some("apache".into()),
            product: Some("log4j".into()),
            ..base()
        }),
        ["CVE-2021-44228"]
    );
    assert_eq!(
        search(Search {
            product: Some("examplewiki".into()),
            ..base()
        }),
        ["CVE-2026-0001"]
    );
    assert!(
        search(Search {
            vendor: Some("openssl".into()),
            product: Some("log4j".into()),
            ..base()
        })
        .is_empty()
    );
    // SQL in an argument is a value.
    assert!(
        search(Search {
            product: Some("x' OR '1'='1".into()),
            ..base()
        })
        .is_empty()
    );
    // Filters and order.
    assert_eq!(
        search(Search {
            min_cvss: Some(9.0),
            ..base()
        }),
        ["CVE-2021-44228"]
    );
    assert_eq!(
        search(Search {
            kev_only: true,
            sort: Sort::Epss,
            ..base()
        }),
        ["CVE-2014-0160", "CVE-2021-44228"]
    );
    assert_eq!(
        search(Search {
            published_after: Some("2026-01-01".into()),
            ..base()
        }),
        ["CVE-2026-0001"]
    );
    assert_eq!(
        search(Search {
            min_epss: Some(0.944),
            ..base()
        }),
        ["CVE-2014-0160"]
    );
    // The limit is hard and says when it cut.
    let (hits, more) = reader
        .search(&Search {
            kev_only: true,
            limit: 1,
            ..Search::default()
        })
        .unwrap();
    assert_eq!((hits.len(), more), (1, true));
}

#[test]
fn kev_and_epss_queries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cve.sqlite");
    build_db(&path, "2026-11-17T03:00:00Z");
    let reader = Reader::new(&path);

    let kev = reader
        .kev(&ids(&["CVE-2014-0160", "CVE-2026-0001"]))
        .unwrap();
    assert_eq!(kev[0]["in_kev"], true);
    assert_eq!(kev[0]["kev"]["date_added"], "2022-05-04");
    assert_eq!(kev[1]["in_kev"], false);

    let list = |after: Option<&str>, text: Option<&str>, ransomware: bool| -> Vec<String> {
        reader
            .kev_list(after, text, ransomware, 10)
            .unwrap()
            .iter()
            .map(|e| e["cve_id"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(list(None, None, false), ["CVE-2014-0160", "CVE-2021-44228"]);
    assert_eq!(list(Some("2022-01-01"), None, false), ["CVE-2014-0160"]);
    assert_eq!(list(None, Some("log4j"), false), ["CVE-2021-44228"]);
    assert_eq!(list(None, None, true), ["CVE-2021-44228"]);
    // `%` is text, not a wildcard.
    assert!(list(None, Some("%"), false).is_empty());

    let epss = reader
        .epss(&ids(&["CVE-2021-44228", "CVE-2030-0001"]))
        .unwrap();
    assert_eq!(epss[0]["epss"]["score"], 0.94358);
    assert_eq!(epss[1]["epss"], json!(null));
}

#[test]
fn newer_record_wins_and_older_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cve.sqlite");
    build_db(&path, "2026-11-17T03:00:00Z");
    let mut w = Writer::open(&path).unwrap();

    // The "modified" feed: one newer record, one older than what is stored.
    let update = nvd_feed(&[
        nvd_entry(
            "CVE-2021-44228",
            "2026-11-17T00:00:00.000",
            "Rewritten text about gadgets.",
            9.0,
            &["cpe:2.3:a:apache:log4j_core:*:*:*:*:*:*:*:*"],
        ),
        nvd_entry(
            "CVE-2014-0160",
            "2020-01-01T00:00:00.000",
            "Stale text.",
            1.0,
            &[],
        ),
    ]);
    let done = import_nvd_feed(&mut w, gz(&update).as_slice(), None, LIMIT).unwrap();
    assert_eq!((done.seen, done.written), (2, 1));
    assert_eq!(done.sha256, sha256_hex(&update));
    assert_eq!(w.count(Table::Cve).unwrap(), 3);
    w.finish().unwrap();

    let reader = Reader::new(&path);
    let found = reader
        .lookup(&ids(&["CVE-2021-44228", "CVE-2014-0160"]), true)
        .unwrap();
    assert_eq!(found[0]["description"], "Rewritten text about gadgets.");
    assert_eq!(found[0]["cvss"]["base_score"], 9.0);
    assert_eq!(
        found[0]["products"],
        json!([{"vendor": "apache", "product": "log4j_core"}])
    );
    assert!(
        found[1]["description"]
            .as_str()
            .unwrap()
            .contains("heartbeat")
    );
    // The search index follows: the old words and product are gone.
    let hits = |q: &str| {
        reader
            .search(&Search {
                query: Some(q.into()),
                limit: 10,
                ..Search::default()
            })
            .unwrap()
            .0
            .len()
    };
    assert_eq!(hits("gadgets"), 1);
    assert_eq!(hits("JNDI"), 0);
    let by_product = |p: &str| {
        reader
            .search(&Search {
                product: Some(p.into()),
                limit: 10,
                ..Search::default()
            })
            .unwrap()
            .0
            .len()
    };
    assert_eq!((by_product("log4j_core"), by_product("log4j")), (1, 0));
}

#[test]
fn wrong_checksum_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut w = Writer::open(&dir.path().join("w.sqlite")).unwrap();
    let nvd = sample_nvd();
    let wrong = "0".repeat(64);
    let err = import_nvd_feed(&mut w, gz(&nvd).as_slice(), Some(&wrong), LIMIT).unwrap_err();
    assert!(matches!(err, ImportError::Checksum { .. }), "{err}");
    // Nothing of the refused feed is kept.
    assert_eq!(w.count(Table::Cve).unwrap(), 0);
    // An upper-case digest (as NVD prints it) matches.
    let upper = sha256_hex(&nvd).to_uppercase();
    import_nvd_feed(&mut w, gz(&nvd).as_slice(), Some(&upper), LIMIT).unwrap();
    assert_eq!(w.count(Table::Cve).unwrap(), 3);
}

#[test]
fn broken_and_oversized_input_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut w = Writer::open(&dir.path().join("w.sqlite")).unwrap();
    let nvd = sample_nvd();

    // Not gzip at all (an HTML error page).
    let err = import_nvd_feed(&mut w, b"<html>blocked</html>".as_slice(), None, LIMIT).unwrap_err();
    assert!(matches!(err, ImportError::Read { .. }), "{err}");
    // Truncated gzip.
    let cut = gz(&nvd);
    let err = import_nvd_feed(&mut w, &cut[..cut.len() / 2], None, LIMIT).unwrap_err();
    assert!(
        matches!(
            err,
            ImportError::Read { .. } | ImportError::Malformed { .. }
        ),
        "{err}"
    );
    // JSON of another shape.
    let err = import_nvd_feed(
        &mut w,
        gz(b"{\"message\": \"rate limited\"}").as_slice(),
        None,
        LIMIT,
    )
    .unwrap_err();
    assert!(matches!(err, ImportError::Malformed { .. }), "{err}");
    // An entry whose id is not a CVE id.
    let bad = nvd_feed(&[nvd_entry(
        "CVE-2021-1'; DROP TABLE cve;--",
        "x",
        "x",
        1.0,
        &[],
    )]);
    let err = import_nvd_feed(&mut w, gz(&bad).as_slice(), None, LIMIT).unwrap_err();
    assert!(matches!(err, ImportError::Malformed { .. }), "{err}");
    // More uncompressed data than allowed (a gzip bomb).
    let err = import_nvd_feed(&mut w, gz(&nvd).as_slice(), None, 100).unwrap_err();
    assert!(
        matches!(err, ImportError::TooLarge { limit: 100, .. }),
        "{err}"
    );
    assert_eq!(w.count(Table::Cve).unwrap(), 0);

    // EPSS: wrong header, bad row, empty, too large.
    for bad in [
        "cve,score\nCVE-2021-44228,0.5\n",
        "cve,epss,percentile\nCVE-2021-44228,7,0.5\n",
        "cve,epss,percentile\n",
        "",
    ] {
        let err = import_epss(&mut w, gz(bad.as_bytes()).as_slice(), LIMIT).unwrap_err();
        assert!(
            matches!(err, ImportError::Malformed { .. }),
            "{bad:?}: {err}"
        );
    }
    let err = import_epss(&mut w, gz(SAMPLE_EPSS.as_bytes()).as_slice(), 50).unwrap_err();
    assert!(matches!(err, ImportError::TooLarge { .. }), "{err}");

    // KEV: count mismatch (a truncated catalogue), empty, bad id, too large.
    let mut kev: serde_json::Value = serde_json::from_slice(&sample_kev()).unwrap();
    kev["count"] = json!(3);
    let err = import_kev(&mut w, serde_json::to_vec(&kev).unwrap().as_slice(), LIMIT).unwrap_err();
    assert!(matches!(err, ImportError::Malformed { .. }), "{err}");
    let err = import_kev(
        &mut w,
        b"{\"count\":0,\"vulnerabilities\":[]}".as_slice(),
        LIMIT,
    )
    .unwrap_err();
    assert!(matches!(err, ImportError::Malformed { .. }), "{err}");
    kev["count"] = json!(2);
    kev["vulnerabilities"][0]["cveID"] = json!("not-a-cve");
    let err = import_kev(&mut w, serde_json::to_vec(&kev).unwrap().as_slice(), LIMIT).unwrap_err();
    assert!(matches!(err, ImportError::Malformed { .. }), "{err}");
    let err = import_kev(&mut w, sample_kev().as_slice(), 10).unwrap_err();
    assert!(matches!(err, ImportError::TooLarge { .. }), "{err}");
}

#[test]
fn epss_and_kev_are_replaced_not_merged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cve.sqlite");
    build_db(&path, "2026-11-17T03:00:00Z");
    let mut w = Writer::open(&path).unwrap();
    let next = "#model_version:v2,score_date:2026-11-18T12:00:00Z\ncve,epss,percentile\nCVE-2021-44228,0.5,0.9\n";
    let done = import_epss(&mut w, gz(next.as_bytes()).as_slice(), LIMIT).unwrap();
    assert_eq!(done.rows, 1);
    assert_eq!(w.count(Table::Epss).unwrap(), 1);
    w.finish().unwrap();
    assert_eq!(
        Reader::new(&path)
            .status()
            .unwrap()
            .epss_score_date
            .as_deref(),
        Some("2026-11-18T12:00:00Z")
    );
}

#[test]
fn reader_reports_missing_and_foreign_files() {
    let dir = tempfile::tempdir().unwrap();
    let err = Reader::new(dir.path().join("nope.sqlite"))
        .status()
        .unwrap_err();
    assert!(matches!(err, StoreError::Missing(_)), "{err}");

    // A SQLite file that is not ours, and a file that is not SQLite.
    let foreign = dir.path().join("foreign.sqlite");
    rusqlite::Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE t (x)")
        .unwrap();
    assert!(matches!(
        Reader::new(&foreign).status().unwrap_err(),
        StoreError::Schema { .. }
    ));
    let garbage = dir.path().join("garbage.sqlite");
    std::fs::write(&garbage, b"this is not a database").unwrap();
    assert!(Reader::new(&garbage).status().is_err());
}

#[test]
fn reader_works_on_a_read_only_file_in_a_read_only_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("data");
    std::fs::create_dir(&sub).unwrap();
    let path = sub.join("cve.sqlite");
    build_db(&path, "2026-11-17T03:00:00Z");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)).unwrap();
    let before: Vec<_> = std::fs::read_dir(&sub)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();

    let reader = Reader::new(&path);
    assert_eq!(reader.status().unwrap().cve_count, 3);
    assert_eq!(
        reader.lookup(&ids(&["CVE-2014-0160"]), true).unwrap()[0]["found"],
        true
    );

    // No journal, WAL or lock file appeared beside the database.
    let after: Vec<_> = std::fs::read_dir(&sub)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
}
