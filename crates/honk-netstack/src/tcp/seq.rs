//! Modular 32-bit sequence-number comparisons (RFC 9293 §3.4).

pub fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

pub fn gt(a: u32, b: u32) -> bool {
    lt(b, a)
}

pub fn ge(a: u32, b: u32) -> bool {
    le(b, a)
}

pub fn max(a: u32, b: u32) -> u32 {
    if gt(a, b) { a } else { b }
}

pub fn min(a: u32, b: u32) -> u32 {
    if lt(a, b) { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraparound_ordering() {
        assert!(lt(u32::MAX - 1, 3));
        assert!(gt(3, u32::MAX - 1));
        assert!(le(7, 7) && ge(7, 7) && !lt(7, 7));
        assert_eq!(max(u32::MAX, 2), 2);
        assert_eq!(min(u32::MAX, 2), u32::MAX);
    }
}
