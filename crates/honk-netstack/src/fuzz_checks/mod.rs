//! Replayable properties for the `fuzz/` targets and `tests/fuzz_replay.rs`.
//!
//! Both drive only the public `Stack` API against a scripted remote, so a finding reproduces from
//! its input alone and a panic is the failure signal. They assert no panic, bounded output per
//! drain, well-formed and in-MTU output, the whole-stack recount in `Stack::check`, and that
//! closing everything returns every pool charge.

mod packet;
mod schedule;
mod transparent;
mod world;

pub use packet::check as packet;
pub use schedule::check as schedule;
pub use transparent::check as transparent;

/// Seed inputs for each target, as `(target, bytes)`; the corpus generator writes them out.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let packets = packet::seeds().into_iter().map(|s| ("netstack_packet", s));
    let schedules = schedule::seeds()
        .into_iter()
        .map(|s| ("netstack_schedule", s));
    let transparent = transparent::seeds()
        .into_iter()
        .map(|s| ("netstack_transparent", s));
    packets.chain(schedules).chain(transparent).collect()
}
