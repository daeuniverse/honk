use super::*;

/// A route through a group exit keeps Score on its leaf: the retry after a
/// failed route excludes that leaf and routes the other one the same way.
#[test]
fn a_score_retry_excludes_the_leaf_of_the_failed_route() {
    let nodes = [node("a"), node("b"), node("land")];
    let manager = GroupManager::new(
        &[Group {
            exit: Some("land".into()),
            ..group("g", &nodes[..2])
        }],
        &nodes,
    );
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let primary = manager.selection_plan_for_target("g", &context);
    let entry = &primary.entries[0];
    let failed = entry.route.as_deref().unwrap();
    assert_eq!((failed.leaf(), failed.exit()), (entry.node.id, nodes[2].id));
    let business = entry.feedback.as_ref().unwrap().begin().unwrap();
    let retry = manager.score_retry_plan_for_target(
        "g",
        &context,
        entry.node.id,
        &entry.final_owners,
        &business.continuation(),
    );
    assert_eq!(retry.entries.len(), 1);
    let other = retry.entries[0].route.as_deref().unwrap();
    assert_eq!(other.exit(), nodes[2].id);
    assert_ne!(other.leaf(), failed.leaf());
    assert_eq!(other.leaf(), retry.entries[0].node.id);
}
