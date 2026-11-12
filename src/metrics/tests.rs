//! The counters, and the exposition text they render to.

use super::*;
use crate::config::Source;
use crate::policy::{ListKind, ListsBuilder, Sources};
use crate::rules;

#[test]
fn every_outcome_has_its_own_counter() {
    let queries = Queries::default();
    for (n, outcome) in Outcome::ALL.into_iter().enumerate() {
        for _ in 0..=n {
            queries.record(outcome);
        }
    }
    let counts: Vec<u64> = queries.counts().map(|(_, count)| count).collect();
    assert_eq!(counts, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(queries.total(), 45);
}

#[test]
fn answer_times_go_in_the_first_bucket_they_fit_and_the_sum() {
    let histogram = Histogram::default();
    for millis in [1, 5, 6, 700, 60_000] {
        histogram.record(Duration::from_millis(millis));
    }
    let snapshot = histogram.snapshot();
    assert_eq!(snapshot.counts, [2, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1]);
    assert_eq!(snapshot.count(), 5);
    assert_eq!(snapshot.sum, Duration::from_millis(60_712));
}

fn sample_lists() -> Arc<Lists> {
    let sources = Sources {
        blocklists: vec![
            Source::try_from("https://user:pw@lists.example/ads.txt?key=1".to_owned()).unwrap(),
            Source::try_from("/etc/zinkhole/gone.txt".to_owned()).unwrap(),
        ],
        allowlists: vec![],
    };
    let mut builder = ListsBuilder::new(sources);
    for rule in rules::parse_line("ads.example").rules {
        builder.add(ListKind::Block, &rule);
    }
    builder.source_done(true);
    builder.source_done(false);
    Arc::new(builder.finish())
}

fn render_sample(state: &State) -> String {
    let queries = Queries::default();
    queries.record(Outcome::Blocked);
    queries.record(Outcome::Blocked);
    let histogram = Histogram::default();
    histogram.record(Duration::from_millis(20));
    histogram.record(Duration::from_secs(9));
    render(&Snapshot {
        queries: &queries,
        upstream: vec![
            ServerMetrics {
                name: "https://dns.quad9.net (9.9.9.9)".to_owned(),
                preferred: true,
                failures: 3,
                answer_times: histogram.snapshot(),
            },
            ServerMetrics {
                name: "a \"quoted\" \\ name".to_owned(),
                preferred: false,
                failures: 0,
                answer_times: Histogram::default().snapshot(),
            },
        ],
        counts: Counts {
            local_records: 2,
            blocked_domains: 1,
            allowed_domains: 0,
        },
        cache_entries: 7,
        lists: sample_lists(),
        state,
    })
}

#[test]
fn the_exposition_holds_every_metric() {
    let state = State::default();
    state.complete_load(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
    let text = render_sample(&state);
    let quad9 = r#"server="https://dns.quad9.net (9.9.9.9)""#;
    for line in [
        "zinkhole_build_info{version=\"3.0.0\"} 1".to_owned(),
        "zinkhole_queries_total{outcome=\"blocked\"} 2".to_owned(),
        "zinkhole_queries_total{outcome=\"local\"} 0".to_owned(),
        format!("zinkhole_upstream_answer_duration_seconds_bucket{{{quad9},le=\"0.01\"}} 0"),
        format!("zinkhole_upstream_answer_duration_seconds_bucket{{{quad9},le=\"0.025\"}} 1"),
        format!("zinkhole_upstream_answer_duration_seconds_bucket{{{quad9},le=\"5\"}} 1"),
        format!("zinkhole_upstream_answer_duration_seconds_bucket{{{quad9},le=\"+Inf\"}} 2"),
        format!("zinkhole_upstream_answer_duration_seconds_sum{{{quad9}}} 9.02"),
        format!("zinkhole_upstream_answer_duration_seconds_count{{{quad9}}} 2"),
        format!("zinkhole_upstream_failures_total{{{quad9}}} 3"),
        format!("zinkhole_upstream_preferred{{{quad9}}} 1"),
        r#"zinkhole_upstream_preferred{server="a \"quoted\" \\ name"} 0"#.to_owned(),
        "zinkhole_blocked_domains 1".to_owned(),
        "zinkhole_local_records 2".to_owned(),
        "zinkhole_cache_entries 7".to_owned(),
        r#"zinkhole_list_loaded{kind="block",index="0",source="https://lists.example/ads.txt"} 1"#
            .to_owned(),
        r#"zinkhole_list_loaded{kind="block",index="1",source="/etc/zinkhole/gone.txt"} 0"#
            .to_owned(),
        "zinkhole_lists_last_complete_load_timestamp_seconds 1700000000".to_owned(),
        "# TYPE zinkhole_upstream_answer_duration_seconds histogram".to_owned(),
    ] {
        assert!(
            text.lines().any(|l| l == line),
            "missing {line:?} in\n{text}"
        );
    }
    // Not scheduled: no sample at all.
    assert!(
        !text
            .lines()
            .any(|l| l.starts_with("zinkhole_lists_next_load")),
        "{text}"
    );
    assert!(!text.contains("pw@") && !text.contains("key=1"));
}

#[test]
fn no_two_samples_share_a_series() {
    // Two list URLs that differ only in their (hidden) query.
    let sources = Sources {
        blocklists: [
            "https://pgl.example/list?a=1",
            "https://pgl.example/list?b=2",
        ]
        .map(|url| Source::try_from(url.to_owned()).unwrap())
        .to_vec(),
        allowlists: vec![Source::try_from("https://pgl.example/list?a=1".to_owned()).unwrap()],
    };
    let mut builder = ListsBuilder::new(sources);
    (0..3).for_each(|_| builder.source_done(true));
    let queries = Queries::default();
    let text = render(&Snapshot {
        queries: &queries,
        upstream: Vec::new(),
        counts: Counts::default(),
        cache_entries: 0,
        lists: Arc::new(builder.finish()),
        state: &State::default(),
    });
    let series: Vec<&str> = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.rsplit_once(' ').unwrap().0)
        .collect();
    let mut unique = series.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), series.len(), "{text}");
}

#[test]
fn every_sample_belongs_to_a_declared_family_once() {
    let text = render_sample(&State::default());
    let mut families = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let name = rest.split(' ').next().unwrap();
            assert!(!families.contains(&name), "{name} declared twice");
            families.push(name);
        } else if !line.starts_with("# HELP ") {
            let name = line.split(['{', ' ']).next().unwrap();
            let family = ["_bucket", "_sum", "_count"]
                .iter()
                .find_map(|suffix| name.strip_suffix(suffix))
                .filter(|base| families.contains(base))
                .unwrap_or(name);
            assert_eq!(families.last(), Some(&family), "{line} outside its family");
            assert!(
                line.rsplit(' ').next().unwrap().parse::<f64>().is_ok(),
                "{line}"
            );
        }
    }
}

#[test]
fn every_outcome_has_a_counter_of_its_own() {
    let queries = Queries::default();
    for (times, outcome) in (1u64..).zip(Outcome::ALL) {
        for _ in 0..times {
            queries.record(outcome);
        }
    }
    let counts: Vec<u64> = queries.counts().map(|(_, count)| count).collect();
    let expected: Vec<u64> = (1u64..).take(Outcome::ALL.len()).collect();
    assert_eq!(counts, expected);
}
