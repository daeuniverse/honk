//! Generation-bound rule identities and per-rule evaluation evidence.

use serde::Serialize;

use crate::routing::{
    Router,
    native::{self, EvaluatedRule, MatchResult},
};

/// `None` identifies an evaluated fallback, never unknown kernel provenance.
pub(crate) fn rule_id(instance: &str, generation: u64, compiled_id: Option<u32>) -> String {
    match compiled_id {
        Some(id) => format!("{instance}:{generation}:rule:{id}"),
        None => format!("{instance}:{generation}:fallback"),
    }
}

/// The fallback's display text when its source text is not retained, as DNS renders its own.
pub(crate) fn fallback_expression(router: &Router) -> String {
    format!("fallback: {}", router.fallback().outbound)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RuleCondition {
    pub(crate) id: String,
    pub(crate) expression: String,
    pub(crate) result: &'static str,
    pub(crate) missing_inputs: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RuleEvaluation {
    pub(crate) rule_id: String,
    pub(crate) expression: String,
    pub(crate) result: &'static str,
    pub(crate) missing_inputs: Vec<&'static str>,
    pub(crate) conditions: Vec<RuleCondition>,
}

impl RuleEvaluation {
    pub(crate) fn heap_bytes(&self) -> usize {
        self.rule_id.capacity()
            + self.expression.capacity()
            + self.missing_inputs.capacity() * size_of::<&str>()
            + self.conditions.capacity() * size_of::<RuleCondition>()
            + self
                .conditions
                .iter()
                .map(|condition| {
                    condition.id.capacity()
                        + condition.expression.capacity()
                        + condition.missing_inputs.capacity() * size_of::<&str>()
                })
                .sum::<usize>()
    }
}

pub(crate) fn observed_rule_evaluations(
    instance: &str,
    generation: u64,
    router: &Router,
    evaluated: &[EvaluatedRule],
) -> Vec<RuleEvaluation> {
    evaluated
        .iter()
        .enumerate()
        .map(|(index, evaluated)| rule_evaluation(instance, generation, router, index, evaluated))
        .collect()
}

pub(crate) fn rule_evaluation(
    instance: &str,
    generation: u64,
    router: &Router,
    index: usize,
    evaluated: &EvaluatedRule,
) -> RuleEvaluation {
    let compiled = router.compiled_routes().get(index);
    let rule_id = rule_id(instance, generation, compiled.map(|rule| rule.id));
    let mut missing = Vec::new();
    let conditions = compiled
        .map(|rule| {
            rule.conditions
                .iter()
                .zip(&evaluated.conditions)
                .enumerate()
                .map(|(index, (condition, &result))| {
                    let condition_missing = if result == MatchResult::Indeterminate {
                        let name = native::missing_input(&condition.predicate);
                        if !missing.contains(&name) {
                            missing.push(name);
                        }
                        vec![name]
                    } else {
                        Vec::new()
                    };
                    RuleCondition {
                        id: format!("{rule_id}/condition:{index}"),
                        expression: rule.condition_expressions[index].clone(),
                        result: result_name(result),
                        missing_inputs: condition_missing,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    if evaluated.result != MatchResult::Indeterminate {
        missing.clear();
    }
    RuleEvaluation {
        rule_id,
        expression: compiled
            .map(|rule| rule.expression.clone())
            .unwrap_or_else(|| fallback_expression(router)),
        result: result_name(evaluated.result),
        missing_inputs: missing,
        conditions,
    }
}

fn result_name(result: MatchResult) -> &'static str {
    match result {
        MatchResult::Matched => "matched",
        MatchResult::NotMatched => "not_matched",
        MatchResult::Indeterminate => "indeterminate",
        MatchResult::Skipped => "skipped",
    }
}
