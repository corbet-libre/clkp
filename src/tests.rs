use super::*;
use cshm::{ChangePreset, ChoiceOption, Field};
use serde_json::json;

fn field(id: &str, kind: FieldType) -> Field {
    Field {
        id: id.into(),
        label: id.into(),
        kind,
        required: false,
        filterable: true,
        change_preset: ChangePreset::Free,
        no_contact_details: false,
    }
}
fn schema() -> Schema {
    Schema {
        community: "community".into(),
        version: 1,
        private: vec![],
        public: vec![
            field(
                "number",
                FieldType::Decimal {
                    min: None,
                    max: None,
                },
            ),
            field(
                "choice",
                FieldType::Choice {
                    options: ["a", "b"]
                        .into_iter()
                        .map(|v| ChoiceOption {
                            id: v.into(),
                            label: v.into(),
                        })
                        .collect(),
                },
            ),
            field("boolean", FieldType::YesNo),
            field("location", FieldType::Location),
            field(
                "text",
                FieldType::ShortText {
                    min_length: 0,
                    max_length: 100,
                },
            ),
            field(
                "integer",
                FieldType::Integer {
                    min: None,
                    max: None,
                },
            ),
        ],
    }
}
fn profile(value: Value) -> PublicProfile {
    PublicProfile {
        community: "community".into(),
        schema_version: 1,
        public: serde_json::from_value(value).unwrap(),
    }
}
fn prepare(id: &str, profile: &PublicProfile, rules: &[Rule]) -> Projection {
    Projection::prepare(id, profile, &schema(), rules, &|_| {
        cshm::ContactCheck::Unavailable
    })
    .unwrap()
}

#[test]
fn indexed_candidates_equal_an_independent_exhaustive_guard_oracle() {
    let mut inputs = Vec::new();
    for i in 0..24 {
        let value =
            profile(json!({"number":i%6,"choice":if i%2==0 {"a"}else{"b"},"boolean":i%3==0}));
        let rules = match i % 6 {
            0 => vec![Rule::NumberRange {
                field: "number".into(),
                min: "1".into(),
                max: "4".into(),
            }],
            1 => vec![Rule::Equal {
                field: "boolean".into(),
                value: json!(true),
            }],
            2 => vec![Rule::OneOf {
                field: "choice".into(),
                values: vec!["a".into()],
            }],
            3 => vec![
                Rule::Equal {
                    field: "number".into(),
                    value: json!(2.0),
                },
                Rule::Block {
                    member: "member2".into(),
                },
            ],
            4 => vec![Rule::OneOf {
                field: "choice".into(),
                values: vec!["a".into(), "b".into()],
            }],
            _ => vec![],
        };
        inputs.push((format!("member{i}"), value, rules));
    }
    let compiled: Vec<_> = inputs.iter().map(|(id, p, r)| prepare(id, p, r)).collect();
    for (a, (id, p, r)) in inputs.iter().enumerate() {
        let independent = Participant::new(id, p, &schema(), r).unwrap();
        let exhaustive: Vec<_> = inputs
            .iter()
            .enumerate()
            .filter_map(|(b, (id, p, r))| {
                let peer = Participant::new(id, p, &schema(), r).unwrap();
                cgrd::matches(&independent, &peer).is_match().then_some(b)
            })
            .collect();
        let indexed: Vec<_> = compiled
            .iter()
            .enumerate()
            .filter_map(|(b, peer)| compiled[a].reciprocal_match(peer).then_some(b))
            .collect();
        assert_eq!(indexed, exhaustive);
    }
}

#[test]
fn exact_numbers_locations_and_optional_fields_have_sound_indexes() {
    let a = profile(
        json!({"number":34,"integer":4,"location":{"latitude":1,"longitude":2},"text":"hello"}),
    );
    let b = profile(
        json!({"number":34.0,"integer":4.0,"location":{"latitude":1.0,"longitude":2.0},"text":"hello"}),
    );
    let rules = vec![
        Rule::Equal {
            field: "number".into(),
            value: json!(34.0),
        },
        Rule::Equal {
            field: "location".into(),
            value: json!({"latitude":1,"longitude":2}),
        },
        Rule::Equal {
            field: "text".into(),
            value: json!("hello"),
        },
    ];
    let pa = prepare("alice", &a, &rules);
    let pb = prepare("bob", &b, &[]);
    assert!(pa.indexes() == pb.indexes());
    assert!(pa.reciprocal_match(&pb));
    assert_eq!(pa.plan().clauses().len(), 3);
    for key in pa.indexes() {
        assert_eq!(key.as_str().len(), 69);
    }
    assert!(!pa.reciprocal_match(&prepare("empty", &profile(json!({})), &[])));
}

#[test]
fn invalid_types_private_filters_and_missing_contact_detector_fail_closed() {
    let p = profile(json!({"number":"34"}));
    assert!(
        Projection::prepare("alice", &p, &schema(), &[], &|_| {
            cshm::ContactCheck::Unavailable
        })
        .is_err()
    );
    let p = profile(json!({"number":34}));
    let rule = Rule::Equal {
        field: "private".into(),
        value: json!("secret"),
    };
    assert!(
        Projection::prepare("alice", &p, &schema(), &[rule], &|_| {
            cshm::ContactCheck::Unavailable
        })
        .is_err()
    );
    let mut s = schema();
    s.public[4].no_contact_details = true;
    let p = profile(json!({"text":"anything"}));
    assert!(
        Projection::prepare("alice", &p, &s, &[], &|_| cshm::ContactCheck::Unavailable).is_err()
    );
    assert!(decimal(&json!("not a number")).is_err());
}

#[test]
fn community_and_schema_scope_cannot_cross_index_keys() {
    let p = profile(json!({"number":34}));
    let a = prepare("alice", &p, &[]);
    let mut p2 = p.clone();
    let mut s = schema();
    s.community = "foreign".into();
    p2.community = s.community.clone();
    let b = Projection::prepare("bob", &p2, &s, &[], &|_| cshm::ContactCheck::Unavailable).unwrap();
    assert!(a.indexes().is_disjoint(b.indexes()));
    assert!(!a.reciprocal_match(&b));
    s.community = "community".into();
    s.version = 2;
    p2.community = s.community.clone();
    p2.schema_version = 2;
    let b = Projection::prepare("bob", &p2, &s, &[], &|_| cshm::ContactCheck::Unavailable).unwrap();
    assert!(a.indexes().is_disjoint(b.indexes()));
    assert!(!a.reciprocal_match(&b));
}

#[test]
fn index_encoding_remains_byte_identical_across_digest_versions() {
    // Independently computed with Python hashlib over the exact JSON array.
    assert_eq!(
        index_key(&schema(), "boolean", json!(true)).as_str(),
        "clkp_27d03d2765068a75e47ba3623e74378b3c99d6f09b73ad33b570bcb08f10cf45"
    );
}

#[test]
fn distance_candidates_equal_exhaustive_guard_and_fixed_equatorial_oracle() {
    // WGS84 equatorial fixture separations are 0, about1113.2m and2226.4m.
    // Explicit expected bands avoid implementing another distance calculation.
    let bands = [
        (0, 1200, [true, true, false]),
        (1, 1200, [false, true, false]),
        (1500, 2500, [false, false, true]),
        (0, 2500, [true, true, true]),
    ];
    let categories = [[0, 1, 2], [1, 0, 1], [2, 1, 0]];
    let mut fixtures = Vec::new();
    for (point, longitude) in [0.0, 0.01, 0.02].into_iter().enumerate() {
        for (lower, upper, allowed) in bands {
            let id = format!("point{point}-{lower}-{upper}");
            let value = profile(json!({"location":{"latitude":0,"longitude":longitude}}));
            let rules = vec![Rule::DistanceRange {
                field: "location".into(),
                min_meters: lower.to_string(),
                max_meters: upper.to_string(),
            }];
            fixtures.push((point, allowed, id, value, rules));
        }
    }
    let projections: Vec<_> = fixtures
        .iter()
        .map(|(_, _, id, value, rules)| prepare(id, value, rules))
        .collect();
    for (a, (point_a, allow_a, id_a, value_a, rules_a)) in fixtures.iter().enumerate() {
        let owner = Participant::new(id_a, value_a, &schema(), rules_a).unwrap();
        let mut expected = Vec::new();
        let mut exhaustive = Vec::new();
        let mut indexed = Vec::new();
        for (b, (point_b, allow_b, id_b, value_b, rules_b)) in fixtures.iter().enumerate() {
            let category = categories[*point_a][*point_b];
            if a != b && allow_a[category] && allow_b[category] {
                expected.push(b);
            }
            let peer = Participant::new(id_b, value_b, &schema(), rules_b).unwrap();
            if cgrd::matches(&owner, &peer).is_match() {
                exhaustive.push(b);
            }
            if projections[a].reciprocal_match(&projections[b]) {
                indexed.push(b);
            }
        }
        assert_eq!(exhaustive, expected);
        assert_eq!(indexed, expected);
        assert!(!projections[a].reciprocal_match(&prepare("absent", &profile(json!({})), &[])));
    }
}
