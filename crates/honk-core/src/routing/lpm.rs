use super::*;

/// Binary LPM trie. Insert CIDRs and check IP matches in O(key_bits) time.
/// Handles IPv4 and IPv6 CIDRs in the same matcher.
#[derive(Debug, Clone)]
pub(crate) struct BinaryLpmTrie {
    v4_nodes: Vec<TrieNode>,
    v6_nodes: Vec<TrieNode>,
}

#[derive(Debug, Clone, Copy, Default)]
struct TrieNode {
    zero: u32,
    one: u32,
    matched: bool,
}

impl BinaryLpmTrie {
    pub(crate) fn from_nets(nets: &[ipnet::IpNet]) -> Self {
        let mut trie = Self {
            v4_nodes: vec![TrieNode::default()],
            v6_nodes: vec![TrieNode::default()],
        };

        for net in nets {
            let prefix = net.prefix_len() as u32;
            match net.addr() {
                IpAddr::V4(ip) => Self::insert(&mut trie.v4_nodes, &ip.octets(), prefix),
                IpAddr::V6(ip) => Self::insert(&mut trie.v6_nodes, &ip.octets(), prefix),
            }
        }
        trie.v4_nodes.shrink_to_fit();
        trie.v6_nodes.shrink_to_fit();
        trie
    }

    fn insert(nodes: &mut Vec<TrieNode>, bytes: &[u8], prefix: u32) {
        let mut node_idx = 0u32;
        for bit_idx in 0..prefix {
            let byte = bytes[(bit_idx / 8) as usize];
            let bit = (byte >> (7 - (bit_idx % 8))) & 1;

            let child_val = if bit == 0 {
                nodes[node_idx as usize].zero
            } else {
                nodes[node_idx as usize].one
            };

            let next_idx = if child_val == 0 {
                let new_idx = nodes.len() as u32;
                nodes.push(TrieNode::default());
                let parent = &mut nodes[node_idx as usize];
                if bit == 0 {
                    parent.zero = new_idx;
                } else {
                    parent.one = new_idx;
                }
                new_idx
            } else {
                child_val
            };
            node_idx = next_idx;
        }
        nodes[node_idx as usize].matched = true;
    }

    fn matches_nodes(nodes: &[TrieNode], bytes: &[u8], key_bits: u32) -> bool {
        if nodes.is_empty() {
            return false;
        }

        let mut node_idx = 0u32;
        for bit_idx in 0..key_bits {
            if nodes[node_idx as usize].matched {
                return true;
            }
            let byte = bytes[(bit_idx / 8) as usize];
            let bit = (byte >> (7 - (bit_idx % 8))) & 1;

            let child = if bit == 0 {
                nodes[node_idx as usize].zero
            } else {
                nodes[node_idx as usize].one
            };

            if child == 0 {
                return nodes[node_idx as usize].matched;
            }
            node_idx = child;
        }
        nodes[node_idx as usize].matched
    }

    pub(crate) fn matches(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => Self::matches_nodes(&self.v4_nodes, &ip.octets(), 32),
            IpAddr::V6(ip) => Self::matches_nodes(&self.v6_nodes, &ip.octets(), 128),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn built_trie_keeps_no_spare_node_capacity() {
        let nets = [
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/33".parse().unwrap(),
        ];
        let trie = super::BinaryLpmTrie::from_nets(&nets);
        for nodes in [&trie.v4_nodes, &trie.v6_nodes] {
            assert_eq!(nodes.capacity(), nodes.len());
        }
    }
}
