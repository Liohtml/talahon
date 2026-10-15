//! Alert correlation: cluster alerts that share a host, a user or a
//! pivotable indicator within a time window.
//!
//! Linking is single-linkage per entity: alerts carrying the same entity are
//! sorted by time and consecutive ones are joined when their gap is within
//! the window (so a chain of alerts each 30 min apart forms one cluster with
//! a 60 min window). Entities that appear in too many alerts
//! (`max_entity_fanout`, e.g. a shared DNS server or the hash of a common
//! system binary) are suppressed and reported instead of gluing everything
//! together. Alerts without a timestamp link to every alert sharing an
//! entity.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::alert::AlertFields;
use crate::ioc::{ExtractOptions, IocExtractor, IocType, Scope};
use crate::mitre::{self, Tactic};

/// Correlation options.
#[derive(Debug, Clone)]
pub struct CorrelationOptions {
    /// Maximum gap between linked alerts.
    pub window: Duration,
    /// Entities seen in more alerts than this are not used for linking.
    pub max_entity_fanout: usize,
    /// Include single-alert clusters in [`CorrelationResult::clusters`].
    pub include_singletons: bool,
    /// Link on host.
    pub link_host: bool,
    /// Link on user.
    pub link_user: bool,
    /// Link on indicators.
    pub link_ioc: bool,
}

impl Default for CorrelationOptions {
    fn default() -> Self {
        Self {
            window: Duration::minutes(60),
            max_entity_fanout: 50,
            include_singletons: false,
            link_host: true,
            link_user: true,
            link_ioc: true,
        }
    }
}

/// The correlation-relevant view of one alert.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AlertNode {
    /// Alert id (`alert-<n>` when the document has none).
    pub id: String,
    /// Event time.
    #[serde(default)]
    pub timestamp: Option<DateTime<Utc>>,
    /// Host (lowercase).
    #[serde(default)]
    pub host: Option<String>,
    /// Normalised user (built-in principals excluded).
    #[serde(default)]
    pub user: Option<String>,
    /// Rule id.
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Rule level.
    #[serde(default)]
    pub rule_level: Option<u8>,
    /// Rule description.
    #[serde(default)]
    pub rule_description: Option<String>,
    /// Pivotable indicator keys (`ipv4:1.2.3.4`, `sha256:...`).
    #[serde(default)]
    pub iocs: Vec<String>,
    /// Tactics from rule tags.
    #[serde(default)]
    pub tactics: Vec<Tactic>,
}

impl AlertNode {
    /// Build from a raw alert; `index` names alerts without an id.
    pub fn from_alert_json(alert: &Value, index: usize) -> Self {
        let f = AlertFields::from_json(alert);
        let mut x = IocExtractor::new(ExtractOptions {
            max_iocs: 200,
            ..Default::default()
        });
        x.add_json(alert);
        let iocs: BTreeSet<String> = x
            .finish()
            .iocs
            .into_iter()
            .filter(|i| match i.ioc_type {
                IocType::Ipv4 | IocType::Ipv6 => matches!(
                    i.scope,
                    Some(Scope::Public | Scope::Private | Scope::SharedAddressSpace)
                ),
                IocType::Domain | IocType::Url | IocType::Email => true,
                t => t.is_hash(),
            })
            .map(|i| i.key())
            .collect();
        let mut tactics: Vec<Tactic> = f
            .mitre_ids
            .iter()
            .flat_map(|id| mitre::tactics_for(id))
            .chain(f.mitre_tactics.iter().filter_map(|t| Tactic::parse(t)))
            .collect();
        tactics.sort();
        tactics.dedup();
        AlertNode {
            id: f.id.clone().unwrap_or_else(|| format!("alert-{index}")),
            timestamp: f.timestamp,
            host: f.host(),
            user: f.principal_user(),
            rule_id: f.rule_id.clone(),
            rule_level: f.rule_level,
            rule_description: f.rule_description.clone(),
            iocs: iocs.into_iter().collect(),
            tactics,
        }
    }

    fn entities(&self, o: &CorrelationOptions) -> Vec<String> {
        let mut e = Vec::new();
        if o.link_host {
            if let Some(h) = &self.host {
                e.push(format!("host:{h}"));
            }
        }
        if o.link_user {
            if let Some(u) = &self.user {
                e.push(format!("user:{u}"));
            }
        }
        if o.link_ioc {
            e.extend(self.iocs.iter().map(|i| format!("ioc:{i}")));
        }
        e
    }
}

/// An entity shared inside a cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedEntity {
    /// `host`, `user` or `ioc`.
    pub kind: String,
    /// Value (`ipv4:1.2.3.4` for indicators).
    pub value: String,
    /// Alerts in the cluster carrying it.
    pub alert_count: usize,
}

/// A group of related alerts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cluster {
    /// `C1`, `C2`, ... (largest first).
    pub id: String,
    /// Member alert ids, in time order.
    pub alert_ids: Vec<String>,
    /// Earliest timestamp.
    pub first_seen: Option<DateTime<Utc>>,
    /// Latest timestamp.
    pub last_seen: Option<DateTime<Utc>>,
    /// `last_seen - first_seen` in seconds.
    pub span_seconds: Option<i64>,
    /// Distinct hosts.
    pub hosts: Vec<String>,
    /// Distinct users.
    pub users: Vec<String>,
    /// Entities shared by ≥ 2 members.
    pub shared_entities: Vec<SharedEntity>,
    /// Highest rule level.
    pub max_rule_level: Option<u8>,
    /// Union of tactics, kill-chain order.
    pub tactics: Vec<Tactic>,
    /// Deterministic observations about the cluster.
    pub assessment: Vec<String>,
}

/// An entity excluded from linking because it is too common.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressedEntity {
    /// Entity key.
    pub entity: String,
    /// Number of alerts carrying it.
    pub alert_count: usize,
}

/// Result of [`correlate`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// Number of alerts analysed.
    pub alerts_analyzed: usize,
    /// Clusters (size ≥ 2 unless `include_singletons`), largest first.
    pub clusters: Vec<Cluster>,
    /// Ids of alerts that did not join any cluster.
    pub singletons: Vec<String>,
    /// Entities skipped for being too common.
    pub suppressed_entities: Vec<SuppressedEntity>,
}

struct Dsu(Vec<usize>);

impl Dsu {
    fn find(&mut self, x: usize) -> usize {
        let mut r = x;
        while self.0[r] != r {
            r = self.0[r];
        }
        let mut c = x;
        while self.0[c] != r {
            let n = self.0[c];
            self.0[c] = r;
            c = n;
        }
        r
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.0[ra.max(rb)] = ra.min(rb);
        }
    }
}

/// Correlate raw alert documents.
pub fn correlate_alerts(alerts: &[Value], opts: &CorrelationOptions) -> CorrelationResult {
    let nodes: Vec<AlertNode> = alerts
        .iter()
        .enumerate()
        .map(|(i, a)| AlertNode::from_alert_json(a, i + 1))
        .collect();
    correlate(&nodes, opts)
}

/// Correlate prepared nodes.
pub fn correlate(nodes: &[AlertNode], opts: &CorrelationOptions) -> CorrelationResult {
    let n = nodes.len();
    let mut dsu = Dsu((0..n).collect());
    let entities: Vec<Vec<String>> = nodes.iter().map(|a| a.entities(opts)).collect();
    let mut by_entity: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, es) in entities.iter().enumerate() {
        for e in es {
            by_entity.entry(e.as_str()).or_default().push(i);
        }
    }

    let mut suppressed = Vec::new();
    for (entity, members) in &by_entity {
        if members.len() < 2 {
            continue;
        }
        if members.len() > opts.max_entity_fanout {
            suppressed.push(SuppressedEntity {
                entity: entity.to_string(),
                alert_count: members.len(),
            });
            continue;
        }
        let mut timed: Vec<usize> = members
            .iter()
            .copied()
            .filter(|&i| nodes[i].timestamp.is_some())
            .collect();
        timed.sort_by_key(|&i| nodes[i].timestamp);
        for w in timed.windows(2) {
            if let (Some(a), Some(b)) = (nodes[w[0]].timestamp, nodes[w[1]].timestamp) {
                if b - a <= opts.window {
                    dsu.union(w[0], w[1]);
                }
            }
        }
        let untimed: Vec<usize> = members
            .iter()
            .copied()
            .filter(|&i| nodes[i].timestamp.is_none())
            .collect();
        for &u in &untimed {
            for &m in members {
                dsu.union(u, m);
            }
        }
    }

    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let r = dsu.find(i);
        groups.entry(r).or_default().push(i);
    }
    let mut groups: Vec<Vec<usize>> = groups.into_values().collect();
    for g in &mut groups {
        g.sort_by_key(|&i| (nodes[i].timestamp, i));
    }
    groups.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a[0].cmp(&b[0])));

    let mut clusters = Vec::new();
    let mut singletons = Vec::new();
    for g in groups {
        if g.len() == 1 && !opts.include_singletons {
            singletons.push(nodes[g[0]].id.clone());
            continue;
        }
        clusters.push(build_cluster(
            nodes,
            &entities,
            &g,
            clusters.len() + 1,
            &suppressed,
        ));
    }
    suppressed.sort_by_key(|s| std::cmp::Reverse(s.alert_count));
    CorrelationResult {
        alerts_analyzed: n,
        clusters,
        singletons,
        suppressed_entities: suppressed,
    }
}

fn build_cluster(
    nodes: &[AlertNode],
    entities: &[Vec<String>],
    members: &[usize],
    number: usize,
    suppressed: &[SuppressedEntity],
) -> Cluster {
    let first_seen = members.iter().filter_map(|&i| nodes[i].timestamp).min();
    let last_seen = members.iter().filter_map(|&i| nodes[i].timestamp).max();
    let hosts: BTreeSet<String> = members
        .iter()
        .filter_map(|&i| nodes[i].host.clone())
        .collect();
    let users: BTreeSet<String> = members
        .iter()
        .filter_map(|&i| nodes[i].user.clone())
        .collect();
    let mut tactics: Vec<Tactic> = members
        .iter()
        .flat_map(|&i| nodes[i].tactics.iter().copied())
        .collect();
    tactics.sort();
    tactics.dedup();

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for &i in members {
        for e in &entities[i] {
            *counts.entry(e.as_str()).or_insert(0) += 1;
        }
    }
    let mut shared: Vec<SharedEntity> = counts
        .into_iter()
        .filter(|(e, c)| *c >= 2 && !suppressed.iter().any(|s| s.entity == *e))
        .filter_map(|(e, c)| {
            let (kind, value) = e.split_once(':')?;
            Some(SharedEntity {
                kind: kind.to_string(),
                value: value.to_string(),
                alert_count: c,
            })
        })
        .collect();
    shared.sort_by(|a, b| {
        b.alert_count
            .cmp(&a.alert_count)
            .then_with(|| a.value.cmp(&b.value))
    });

    let mut assessment = Vec::new();
    let ioc_hosts = |key: &str| -> BTreeSet<String> {
        members
            .iter()
            .filter(|&&i| nodes[i].iocs.iter().any(|k| k == key))
            .filter_map(|&i| nodes[i].host.clone())
            .collect()
    };
    for s in shared.iter().filter(|s| s.kind == "ioc") {
        let hs = ioc_hosts(&s.value);
        if hs.len() >= 2 {
            assessment.push(format!(
                "Indicator {} seen on {} hosts ({}): possible campaign or lateral spread.",
                s.value,
                hs.len(),
                hs.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    for s in shared.iter().filter(|s| s.kind == "user") {
        let hs: BTreeSet<String> = members
            .iter()
            .filter(|&&i| nodes[i].user.as_deref() == Some(s.value.as_str()))
            .filter_map(|&i| nodes[i].host.clone())
            .collect();
        if hs.len() >= 2 {
            assessment.push(format!(
                "Account {} active on {} hosts within the window: check for credential misuse or lateral movement.",
                s.value,
                hs.len()
            ));
        }
    }
    if tactics.len() >= 3 {
        assessment.push(format!(
            "Multi-stage activity across {} tactics ({}).",
            tactics.len(),
            tactics
                .iter()
                .map(|t| t.name())
                .collect::<Vec<_>>()
                .join(" -> ")
        ));
    }
    if hosts.len() == 1 && members.len() >= 5 {
        assessment.push(format!(
            "Burst of {} alerts on a single host.",
            members.len()
        ));
    }
    let rules: BTreeSet<&str> = members
        .iter()
        .filter_map(|&i| nodes[i].rule_id.as_deref())
        .collect();
    if rules.len() == 1 && members.len() >= 3 && hosts.len() >= 3 {
        assessment.push(format!(
            "The same rule fired on {} hosts: check for a shared cause (campaign, deployment or noisy rule).",
            hosts.len()
        ));
    }

    Cluster {
        id: format!("C{number}"),
        alert_ids: members.iter().map(|&i| nodes[i].id.clone()).collect(),
        first_seen,
        last_seen,
        span_seconds: first_seen
            .zip(last_seen)
            .map(|(a, b)| (b - a).num_seconds()),
        hosts: hosts.into_iter().collect(),
        users: users.into_iter().collect(),
        shared_entities: shared,
        max_rule_level: members.iter().filter_map(|&i| nodes[i].rule_level).max(),
        tactics,
        assessment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alert(id: &str, ts: &str, host: &str, user: &str, extra: Value) -> Value {
        let mut a = json!({
            "_id": id,
            "_source": {
                "timestamp": ts,
                "agent": {"name": host},
                "rule": {"id": "100", "level": 10, "mitre": {"id": []}},
                "data": {"win": {"eventdata": {"user": user}}}
            }
        });
        if let (Some(src), Some(extra)) = (a["_source"].as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                src.insert(k.clone(), v.clone());
            }
        }
        a
    }

    #[test]
    fn host_window_chain_and_split() {
        let alerts = vec![
            alert("a1", "2024-05-01T10:00:00Z", "WS1", "SYSTEM", json!({})),
            alert("a2", "2024-05-01T10:40:00Z", "WS1", "SYSTEM", json!({})),
            alert("a3", "2024-05-01T11:30:00Z", "WS1", "SYSTEM", json!({})),
            alert("a4", "2024-05-01T15:00:00Z", "WS1", "SYSTEM", json!({})),
            alert("b1", "2024-05-01T10:05:00Z", "WS2", "SYSTEM", json!({})),
        ];
        let r = correlate_alerts(&alerts, &CorrelationOptions::default());
        assert_eq!(r.alerts_analyzed, 5);
        assert_eq!(r.clusters.len(), 1);
        assert_eq!(r.clusters[0].alert_ids, vec!["a1", "a2", "a3"]);
        assert_eq!(r.clusters[0].span_seconds, Some(5400));
        assert_eq!(r.clusters[0].hosts, vec!["ws1"]);
        assert!(
            r.clusters[0].users.is_empty(),
            "SYSTEM is not a correlatable user"
        );
        let mut s = r.singletons.clone();
        s.sort();
        assert_eq!(s, vec!["a4", "b1"]);
    }

    #[test]
    fn shared_ioc_across_hosts_and_user_spread() {
        let c2 = json!({"data": {"win": {"eventdata": {"destinationIp": "185.220.101.4", "user": "CORP\\alice"}}}});
        let alerts = vec![
            alert(
                "x1",
                "2024-05-01T10:00:00Z",
                "WS1",
                "CORP\\alice",
                c2.clone(),
            ),
            alert(
                "x2",
                "2024-05-01T10:10:00Z",
                "WS2",
                "CORP\\alice",
                c2.clone(),
            ),
            alert(
                "x3",
                "2024-05-01T10:20:00Z",
                "WS3",
                "CORP\\bob",
                json!({"data": {"win": {"eventdata": {"destinationIp": "185.220.101.4", "user": "CORP\\bob"}}}}),
            ),
        ];
        let r = correlate_alerts(&alerts, &CorrelationOptions::default());
        assert_eq!(r.clusters.len(), 1);
        let c = &r.clusters[0];
        assert_eq!(c.alert_ids.len(), 3);
        assert!(
            c.shared_entities
                .iter()
                .any(|e| e.kind == "ioc" && e.value == "ipv4:185.220.101.4" && e.alert_count == 3)
        );
        assert!(
            c.assessment.iter().any(|a| a.contains("seen on 3 hosts")),
            "{:?}",
            c.assessment
        );
        assert!(
            c.assessment
                .iter()
                .any(|a| a.contains("Account alice active on 2 hosts")),
            "{:?}",
            c.assessment
        );
    }

    #[test]
    fn fanout_suppression() {
        let alerts: Vec<Value> = (0..6)
            .map(|i| {
                alert(
                    &format!("d{i}"),
                    "2024-05-01T10:00:00Z",
                    &format!("WS{i}"),
                    "SYSTEM",
                    json!({"data": {"win": {"eventdata": {"queryName": "time.windows.com"}}}}),
                )
            })
            .collect();
        let opts = CorrelationOptions {
            max_entity_fanout: 5,
            ..Default::default()
        };
        let r = correlate_alerts(&alerts, &opts);
        assert!(r.clusters.is_empty());
        assert_eq!(r.singletons.len(), 6);
        assert_eq!(
            r.suppressed_entities[0].entity,
            "ioc:domain:time.windows.com"
        );
        assert_eq!(r.suppressed_entities[0].alert_count, 6);
    }

    #[test]
    fn untimed_and_singletons_option() {
        let nodes = vec![
            AlertNode {
                id: "n1".into(),
                host: Some("h".into()),
                ..Default::default()
            },
            AlertNode {
                id: "n2".into(),
                host: Some("h".into()),
                timestamp: crate::alert::parse_timestamp_str("2024-01-01T00:00:00Z"),
                ..Default::default()
            },
            AlertNode {
                id: "n3".into(),
                host: Some("other".into()),
                ..Default::default()
            },
        ];
        let r = correlate(
            &nodes,
            &CorrelationOptions {
                include_singletons: true,
                ..Default::default()
            },
        );
        assert_eq!(r.clusters.len(), 2);
        assert_eq!(r.clusters[0].alert_ids.len(), 2);
        assert_eq!(r.clusters[1].alert_ids, vec!["n3"]);
        assert!(r.singletons.is_empty());
        let r = correlate(
            &nodes,
            &CorrelationOptions {
                link_host: false,
                ..Default::default()
            },
        );
        assert!(r.clusters.is_empty());
    }

    #[test]
    fn multi_stage_assessment_and_missing_ids() {
        let a = json!({"timestamp": "2024-05-01T10:00:00Z", "agent": {"name": "WS9"}, "rule": {"id": "1", "level": 12, "mitre": {"id": ["T1059.001"]}}});
        let b = json!({"timestamp": "2024-05-01T10:05:00Z", "agent": {"name": "WS9"}, "rule": {"id": "2", "level": 13, "mitre": {"id": ["T1547.001"]}}});
        let c = json!({"timestamp": "2024-05-01T10:09:00Z", "agent": {"name": "WS9"}, "rule": {"id": "3", "level": 14, "mitre": {"id": ["T1071.001"]}}});
        let r = correlate_alerts(&[a, b, c], &CorrelationOptions::default());
        let cl = &r.clusters[0];
        assert_eq!(cl.alert_ids, vec!["alert-1", "alert-2", "alert-3"]);
        assert_eq!(cl.max_rule_level, Some(14));
        assert!(cl.tactics.contains(&Tactic::CommandAndControl));
        assert!(
            cl.assessment.iter().any(|x| x.starts_with("Multi-stage")),
            "{:?}",
            cl.assessment
        );
    }
}
