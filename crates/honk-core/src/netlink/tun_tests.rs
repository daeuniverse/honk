use super::*;

#[test]
fn mutation_ack_distinguishes_refusal_from_lost_confirmation() {
    let ack = |error: i32| encode_request(17, NLMSG_ERROR, 0, &error.to_ne_bytes(), &[]);
    assert_eq!(mutation_ack(&ack(0), 17).unwrap(), Some(()));
    assert_eq!(mutation_ack(&ack(0), 18).unwrap(), None);
    assert!(matches!(mutation_ack(&ack(-libc::EEXIST), 17),
        Err(MutationError::Refused(error)) if error.raw_os_error() == Some(libc::EEXIST)));
    assert!(matches!(
        mutation_ack(&ack(1), 17),
        Err(MutationError::Unconfirmed(_))
    ));
    assert!(matches!(
        mutation_ack(&ack(0)[..19], 17),
        Err(MutationError::Unconfirmed(_))
    ));
    let mut invalid = ack(0);
    invalid[..4].copy_from_slice(&15u32.to_ne_bytes());
    assert!(matches!(
        mutation_ack(&invalid, 17),
        Err(MutationError::Unconfirmed(_))
    ));
}
