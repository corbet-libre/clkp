//! Typed index planning. These projections narrow candidates, never authorize
//! admission or disclosure. Current Switchboard authority must precede use.
#![forbid(unsafe_code)]

mod cursor;
pub use cursor::*;

use cgrd::{Participant, Rule, RuleError};
use cshm::{FieldType, PublicProfile, Schema};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Storage-compatible opaque index key over approved public attributes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexKey(String);
impl IndexKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded query plan: each clause is a union of exact indexes; clauses are
/// intersected. Numeric intervals have no exact-index prefilter and are always
/// checked by Guard. Empty clauses mean the scoped live-entry index.
pub struct Plan {
    clauses: Vec<BTreeSet<IndexKey>>,
}
impl Plan {
    pub fn clauses(&self) -> &[BTreeSet<IndexKey>] {
        &self.clauses
    }

    /// A necessary candidate condition, deliberately not an admission verdict.
    pub fn includes(&self, indexes: &BTreeSet<IndexKey>) -> bool {
        self.clauses
            .iter()
            .all(|clause| !clause.is_disjoint(indexes))
    }
}

/// Ephemeral prepared view, owned by the caller for one operation. There is no
/// retained roster or independent profile store in this library.
pub struct Projection {
    participant: Participant,
    indexes: BTreeSet<IndexKey>,
    plan: Plan,
}
impl Projection {
    /// Guard validates the exact schema, public types and rules. A deterministic
    /// contact detector must be supplied by its owner when the schema needs it.
    pub fn prepare(
        member: &str,
        profile: &PublicProfile,
        schema: &Schema,
        rules: &[Rule],
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Self, RuleError> {
        let participant = Participant::with_contact(member, profile, schema, rules, contact)?;
        let mut indexes = BTreeSet::new();
        for field in schema.public.iter().filter(|field| field.filterable) {
            if let Some(value) = profile.public.get(&field.id) {
                indexes.insert(key(schema, &field.id, &field.kind, value)?);
            }
        }
        let mut clauses = Vec::new();
        for rule in rules {
            match rule {
                Rule::Equal { field, value } => {
                    let kind = &schema
                        .public
                        .iter()
                        .find(|f| f.id == *field)
                        .ok_or(RuleError::NotFilterable)?
                        .kind;
                    clauses.push([key(schema, field, kind, value)?].into());
                }
                Rule::OneOf { field, values } => {
                    let clause = values
                        .iter()
                        .map(|value| index_key(schema, field, Value::String(value.clone())))
                        .collect();
                    clauses.push(clause);
                }
                Rule::NumberRange { .. } | Rule::Block { .. } => {}
            }
        }
        Ok(Self {
            participant,
            indexes,
            plan: Plan { clauses },
        })
    }
    pub fn indexes(&self) -> &BTreeSet<IndexKey> {
        &self.indexes
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Exact two-way evaluation stays in Guard. The index optimization can only
    /// discard a pair that cannot satisfy its public equality/choice predicates.
    pub fn reciprocal_match(&self, other: &Self) -> bool {
        self.plan.includes(&other.indexes)
            && other.plan.includes(&self.indexes)
            && cgrd::matches(&self.participant, &other.participant).is_match()
    }
}

fn decimal(value: &Value) -> Result<String, RuleError> {
    Ok(cshm::parse_number(&value.to_string())
        .map_err(|_| RuleError::Type)?
        .normalized()
        .to_string())
}

fn key(
    schema: &Schema,
    field: &str,
    kind: &FieldType,
    value: &Value,
) -> Result<IndexKey, RuleError> {
    // Reuse Guard's exact decimal domain. JSON spelling must not separate 34
    // and 34.0; location coordinates obey the same equality rule.
    let normalized = match kind {
        FieldType::Integer { .. } | FieldType::Decimal { .. } => Value::String(decimal(value)?),
        FieldType::Location => {
            serde_json::json!([decimal(&value["latitude"])?, decimal(&value["longitude"])?])
        }
        _ => value.clone(),
    };
    Ok(index_key(schema, field, normalized))
}

fn index_key(schema: &Schema, field: &str, normalized: Value) -> IndexKey {
    let bytes = serde_json::json!([
        "clkp.index.v1",
        schema.community,
        schema.version,
        field,
        normalized
    ])
    .to_string();
    let digest = Sha256::digest(bytes.as_bytes());
    IndexKey(format!("clkp_{digest:x}"))
}

#[cfg(test)]
mod tests;
