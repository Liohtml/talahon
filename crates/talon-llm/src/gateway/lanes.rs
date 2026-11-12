//! Concurrency admission: the global in-flight cap and the per-lane share
//! of it.
//!
//! A *lane* is a token label (the host uses the lane's IPC key). Every
//! admitted request is counted against its lane — across all of that lane's
//! tokens — and against the gateway as a whole, in one critical section, so
//! neither bound can be overshot by concurrent requests.
//!
//! # Rule
//!
//! With `G` = the global cap and `C` = the lane limit
//! (`max(1, floor(G x share / 100))`, only when that is below `G`), a
//! request from a lane holding `x` slots while `T` slots are held overall is
//!
//! 1. refused with [`Refusal::LaneShare`] if the gateway is shared and
//!    `x >= C`;
//! 2. refused with [`Refusal::Overloaded`] if `T >= G`;
//! 3. admitted otherwise.
//!
//! The gateway is *shared* once it has issued tokens for a second label; a
//! single-lane deployment is never limited below `G`.
//!
//! # Guarantee
//!
//! Requests admitted while the gateway is shared never raise a lane above
//! `C`. So once it is shared, `k` other lanes hold at most `k x C` slots
//! together, and a lane is refused for capacity only at its own limit or
//! when it already holds `G - k x C` slots or more: one lane alone can never
//! take the last `G - C` slots from the others. Nothing is queued — a
//! refusal is immediate — and memory is one map entry per lane with a
//! request in flight.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

/// The most slots one lane may hold, or `None` when lanes are not limited
/// below the global cap: no global cap (`0`), a share of `0` or `>= 100`
/// percent, or a cap too small to reserve anything (`1`).
pub(crate) fn lane_limit(global_cap: u32, share_percent: u32) -> Option<u32> {
    if global_cap == 0 || share_percent == 0 || share_percent >= 100 {
        return None;
    }
    let scaled = u64::from(global_cap) * u64::from(share_percent) / 100;
    let limit = u32::try_from(scaled).unwrap_or(u32::MAX).max(1);
    (limit < global_cap).then_some(limit)
}

/// Why a request got no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The lane already holds its share of the global cap.
    LaneShare {
        /// Slots the lane holds.
        in_flight: u32,
        /// The lane limit.
        limit: u32,
    },
    /// Every slot of the global cap is taken.
    Overloaded,
}

#[derive(Debug, Default)]
struct State {
    /// Slots held overall.
    total: u32,
    /// Slots held per lane; lanes with none are removed.
    lanes: HashMap<String, u32>,
    /// The first label a token was issued for.
    first_label: Option<String>,
    /// A second label has been seen: lane limits apply.
    shared: bool,
}

impl State {
    fn observe(&mut self, label: &str) {
        if self.shared {
            return;
        }
        match &self.first_label {
            None => self.first_label = Some(label.to_string()),
            Some(first) if first != label => self.shared = true,
            Some(_) => {}
        }
    }
}

/// Admission control for the global cap and the per-lane share of it.
#[derive(Debug)]
pub(crate) struct LaneLimiter {
    /// Global cap (`None` = disabled).
    global_cap: Option<u32>,
    /// Lane limit (`None` = lanes are bounded by the global cap only).
    lane_limit: Option<u32>,
    state: Mutex<State>,
}

impl LaneLimiter {
    /// `global_cap == 0` disables the global cap (and with it the lane
    /// limit); see [`lane_limit`] for `share_percent`.
    pub(crate) fn new(global_cap: u32, share_percent: u32) -> Self {
        Self {
            global_cap: (global_cap > 0).then_some(global_cap),
            lane_limit: lane_limit(global_cap, share_percent),
            state: Mutex::new(State::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // The critical sections only touch plain counters; after a panic
        // elsewhere the data is still consistent enough to keep serving.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Note that a token was issued for `label`. The second distinct label
    /// makes the gateway shared (for good).
    pub(crate) fn observe(&self, label: &str) {
        self.lock().observe(label);
    }

    /// Take a slot for `label`. The slot is released when the returned
    /// guard is dropped.
    pub(crate) fn admit(self: &Arc<Self>, label: &str) -> Result<LaneGuard, Refusal> {
        let mut state = self.lock();
        state.observe(label);
        let in_flight = state.lanes.get(label).copied().unwrap_or(0);
        if state.shared
            && let Some(limit) = self.lane_limit
            && in_flight >= limit
        {
            return Err(Refusal::LaneShare { in_flight, limit });
        }
        if self.global_cap.is_some_and(|cap| state.total >= cap) {
            return Err(Refusal::Overloaded);
        }
        state.total = state.total.saturating_add(1);
        match state.lanes.get_mut(label) {
            Some(n) => *n = n.saturating_add(1),
            None => {
                state.lanes.insert(label.to_string(), 1);
            }
        }
        Ok(LaneGuard {
            limiter: Arc::clone(self),
            label: label.to_string(),
        })
    }

    /// Slots held overall and per lane (only lanes with a request in
    /// flight).
    pub(crate) fn in_flight(&self) -> (u32, BTreeMap<String, u32>) {
        let state = self.lock();
        let lanes = state.lanes.iter().map(|(k, v)| (k.clone(), *v)).collect();
        (state.total, lanes)
    }

    fn release(&self, label: &str) {
        let mut state = self.lock();
        state.total = state.total.saturating_sub(1);
        if let Some(n) = state.lanes.get_mut(label) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                state.lanes.remove(label);
            }
        }
    }
}

/// One slot of the global cap, counted against a lane; released on drop
/// (also when the holder is cancelled or unwinds).
#[derive(Debug)]
pub(crate) struct LaneGuard {
    limiter: Arc<LaneLimiter>,
    label: String,
}

impl Drop for LaneGuard {
    fn drop(&mut self) {
        self.limiter.release(&self.label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn shared(global: u32, share: u32, labels: &[&str]) -> Arc<LaneLimiter> {
        let l = Arc::new(LaneLimiter::new(global, share));
        for label in labels {
            l.observe(label);
        }
        l
    }

    #[test]
    fn lane_limit_is_derived_from_the_global_cap() {
        assert_eq!(lane_limit(32, 75), Some(24));
        assert_eq!(lane_limit(32, 25), Some(8));
        assert_eq!(lane_limit(7, 75), Some(5));
        assert_eq!(lane_limit(2, 75), Some(1));
        assert_eq!(lane_limit(32, 1), Some(1), "never below one slot");
        // Nothing to reserve / disabled.
        assert_eq!(lane_limit(1, 75), None);
        assert_eq!(lane_limit(0, 75), None);
        assert_eq!(lane_limit(32, 0), None);
        assert_eq!(lane_limit(32, 100), None);
        assert_eq!(lane_limit(32, 400), None);
        assert_eq!(lane_limit(u32::MAX, 99), Some(4_252_017_622));
    }

    #[test]
    fn a_lone_lane_gets_the_whole_cap() {
        let l = Arc::new(LaneLimiter::new(4, 75));
        l.observe("a");
        l.observe("a");
        let held: Vec<_> = (0..4).map(|_| l.admit("a").unwrap()).collect();
        assert_eq!(l.admit("a").unwrap_err(), Refusal::Overloaded);
        drop(held);
        assert_eq!(l.in_flight(), (0, BTreeMap::new()));
    }

    #[test]
    fn a_saturating_lane_leaves_the_reserve_to_others() {
        let l = shared(8, 75, &["a", "b"]);
        let mut a = Vec::new();
        for _ in 0..6 {
            a.push(l.admit("a").unwrap());
        }
        assert_eq!(
            l.admit("a").unwrap_err(),
            Refusal::LaneShare {
                in_flight: 6,
                limit: 6
            }
        );
        // The other lane gets the two reserved slots; then the gateway is
        // full, and each lane is told its own reason.
        let b1 = l.admit("b").unwrap();
        let b2 = l.admit("b").unwrap();
        assert_eq!(l.admit("b").unwrap_err(), Refusal::Overloaded);
        assert!(matches!(
            l.admit("a").unwrap_err(),
            Refusal::LaneShare { .. }
        ));
        let (total, lanes) = l.in_flight();
        assert_eq!(total, 8);
        assert_eq!(lanes["a"], 6);
        assert_eq!(lanes["b"], 2);
        // A released slot is reusable by its lane, not beyond the limit.
        a.pop();
        a.push(l.admit("a").unwrap());
        assert!(l.admit("a").is_err());
        drop((b1, b2, a));
        assert_eq!(l.in_flight(), (0, BTreeMap::new()));
    }

    #[test]
    fn slots_admitted_before_a_second_lane_appears_drain() {
        let l = Arc::new(LaneLimiter::new(4, 50));
        l.observe("a");
        let mut a: Vec<_> = (0..4).map(|_| l.admit("a").unwrap()).collect();
        // The second lane appears: `a` keeps what it has but gets no more
        // until it is below its limit of 2.
        l.observe("b");
        assert_eq!(l.admit("b").unwrap_err(), Refusal::Overloaded);
        a.pop();
        assert!(matches!(
            l.admit("a").unwrap_err(),
            Refusal::LaneShare {
                in_flight: 3,
                limit: 2
            }
        ));
        let _b = l.admit("b").unwrap();
        a.pop();
        a.pop();
        assert!(l.admit("a").is_ok());
    }

    #[test]
    fn an_unseen_label_at_admission_also_makes_the_gateway_shared() {
        let l = Arc::new(LaneLimiter::new(4, 50));
        let _a1 = l.admit("a").unwrap();
        let _a2 = l.admit("a").unwrap();
        let _a3 = l.admit("a").unwrap();
        let _b = l.admit("b").unwrap();
        assert!(matches!(
            l.admit("a").unwrap_err(),
            Refusal::LaneShare { .. }
        ));
    }

    #[test]
    fn without_a_global_cap_nothing_is_limited_but_lanes_are_counted() {
        let l = shared(0, 75, &["a", "b"]);
        let held: Vec<_> = (0..100).map(|_| l.admit("a").unwrap()).collect();
        assert_eq!(l.in_flight().1["a"], 100);
        drop(held);
        assert_eq!(l.in_flight().0, 0);
    }

    #[test]
    fn a_share_of_100_restores_the_plain_global_cap() {
        let l = shared(4, 100, &["a", "b"]);
        let _held: Vec<_> = (0..4).map(|_| l.admit("a").unwrap()).collect();
        assert_eq!(l.admit("a").unwrap_err(), Refusal::Overloaded);
        assert_eq!(l.admit("b").unwrap_err(), Refusal::Overloaded);
    }

    #[test]
    fn slots_are_released_when_the_holder_panics() {
        let l = shared(2, 50, &["a", "b"]);
        let l2 = Arc::clone(&l);
        let result = std::thread::spawn(move || {
            let _slot = l2.admit("a").unwrap();
            panic!("holder died");
        })
        .join();
        assert!(result.is_err());
        assert_eq!(l.in_flight(), (0, BTreeMap::new()));
        assert!(l.admit("a").is_ok());
    }

    #[test]
    fn concurrent_admissions_never_overshoot() {
        use std::sync::atomic::{AtomicU32, Ordering};
        const GLOBAL: u32 = 8;
        const LIMIT: u32 = 6;
        let l = shared(GLOBAL, 75, &["l0", "l1", "l2", "l3"]);
        let per_lane: Arc<Vec<AtomicU32>> = Arc::new((0..4).map(|_| AtomicU32::new(0)).collect());
        let total = Arc::new(AtomicU32::new(0));
        let threads: Vec<_> = (0..16usize)
            .map(|t| {
                let l = Arc::clone(&l);
                let per_lane = Arc::clone(&per_lane);
                let total = Arc::clone(&total);
                std::thread::spawn(move || {
                    let lane = t % 4;
                    let label = format!("l{lane}");
                    let mut admitted = 0u32;
                    for _ in 0..2000 {
                        if let Ok(guard) = l.admit(&label) {
                            admitted += 1;
                            let mine = per_lane[lane].fetch_add(1, Ordering::SeqCst) + 1;
                            let all = total.fetch_add(1, Ordering::SeqCst) + 1;
                            assert!(mine <= LIMIT, "lane over its limit: {mine}");
                            assert!(all <= GLOBAL, "global cap exceeded: {all}");
                            std::thread::yield_now();
                            total.fetch_sub(1, Ordering::SeqCst);
                            per_lane[lane].fetch_sub(1, Ordering::SeqCst);
                            drop(guard);
                        }
                    }
                    admitted
                })
            })
            .collect();
        let admitted: u32 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert!(admitted > 0);
        assert_eq!(l.in_flight(), (0, BTreeMap::new()));
    }

    #[derive(Debug, Clone)]
    enum Op {
        Admit(usize),
        Release(usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => (0usize..5).prop_map(Op::Admit),
            2 => any::<usize>().prop_map(Op::Release),
        ]
    }

    proptest! {
        /// Random admissions and releases over five lanes, checked against
        /// a model: the counts are exact, neither bound is overshot, every
        /// refusal has the stated cause, and a lane below `G - k x C`
        /// (`k` = other lanes holding slots) is never refused.
        #[test]
        fn admission_matches_the_model(
            global in 1u32..12,
            share in 0u32..120,
            ops in proptest::collection::vec(op(), 0..200),
        ) {
            let labels = ["l0", "l1", "l2", "l3", "l4"];
            let l = shared(global, share, &labels);
            let limit = lane_limit(global, share);
            let mut held: Vec<(usize, LaneGuard)> = Vec::new();
            for op in ops {
                match op {
                    Op::Release(i) => {
                        if !held.is_empty() {
                            let at = i % held.len();
                            drop(held.swap_remove(at));
                        }
                    }
                    Op::Admit(lane) => {
                        let mine = held.iter().filter(|(l, _)| *l == lane).count() as u32;
                        let total = held.len() as u32;
                        let others = (0..labels.len())
                            .filter(|o| *o != lane && held.iter().any(|(l, _)| l == o))
                            .count() as u32;
                        match l.admit(labels[lane]) {
                            Ok(guard) => {
                                prop_assert!(total < global);
                                prop_assert!(limit.is_none_or(|c| mine < c));
                                held.push((lane, guard));
                            }
                            Err(Refusal::LaneShare { in_flight, limit: c }) => {
                                prop_assert_eq!(Some(c), limit);
                                prop_assert_eq!(in_flight, mine);
                                prop_assert!(mine >= c);
                            }
                            Err(Refusal::Overloaded) => {
                                prop_assert_eq!(total, global);
                                if let Some(c) = limit {
                                    // The guarantee: others hold at most
                                    // `k x C`, so this lane holds the rest.
                                    prop_assert!(mine >= global.saturating_sub(others * c));
                                    prop_assert!(others >= 1);
                                }
                            }
                        }
                    }
                }
                let (total, lanes) = l.in_flight();
                prop_assert_eq!(total as usize, held.len());
                prop_assert!(total <= global);
                for (i, label) in labels.iter().enumerate() {
                    let expected = held.iter().filter(|(l, _)| *l == i).count() as u32;
                    prop_assert_eq!(lanes.get(*label).copied().unwrap_or(0), expected);
                    prop_assert!(limit.is_none_or(|c| expected <= c));
                }
            }
            drop(held);
            prop_assert_eq!(l.in_flight(), (0, BTreeMap::new()));
        }
    }
}
