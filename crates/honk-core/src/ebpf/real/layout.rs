//! The one owner of eBPF ABI layout checks. BTF validation of the object and map-info validation of
//! the loaded maps are complementary: BTF proves the locked wrapper and payload shapes the kernel
//! will use, map info proves the instantiated maps actually carry them.

use super::*;
use honk_ebpf_common::event::DaeEvent;

pub(super) fn validate_object(obj: &[u8]) -> anyhow::Result<()> {
    let object = aya_obj::Object::parse(obj)?;
    for (name, map) in &object.maps {
        anyhow::ensure!(
            map.pinning() == aya_obj::maps::PinningType::None,
            "eBPF object map {name} declares implicit pinning; rebuild without pinning so the loader owns every pin"
        );
    }
    let data = object
        .btf
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("required flow lifetime object BTF not found"))?
        .to_bytes();
    validate_flow_lifetime_btf(&data)?;
    let btf = btf::Btf::parse(&data).ok_or_else(|| anyhow::anyhow!("invalid flow map BTF"))?;
    for (map, payload, size) in [
        (
            "CONN_STATE_MAP",
            "ConnState",
            core::mem::size_of::<FlowMapValue<ConnState>>(),
        ),
        (
            "REDIRECT_TRACK",
            "RedirectEntry",
            core::mem::size_of::<FlowMapValue<RedirectEntry>>(),
        ),
        (
            "ROUTING_HANDOFF_MAP",
            "RoutingHandoffEntry",
            core::mem::size_of::<FlowMapValue<RoutingHandoffEntry>>(),
        ),
    ] {
        let value = object_map_value_type(&object, &btf, map)?;
        anyhow::ensure!(
            flow_value_btf_matches(&btf, value, payload, size),
            "incompatible locked value BTF for {map}; rebuild the eBPF object"
        );
    }
    let value = object_map_value_type(&object, &btf, "TCP_SOCKET_BINDING")?;
    anyhow::ensure!(
        tcp_proof_btf_matches(&btf, value),
        "incompatible native proof BTF for TCP_SOCKET_BINDING; rebuild the eBPF object"
    );
    Ok(())
}

fn object_map_value_type(
    object: &aya_obj::Object,
    btf: &btf::Btf<'_>,
    name: &str,
) -> anyhow::Result<usize> {
    let Some(aya_obj::maps::Map::Btf(map)) = object.maps.get(name) else {
        anyhow::bail!("required BTF map {name} missing");
    };
    btf.resolve_composite(map.def.btf_value_type_id)
        .ok_or_else(|| anyhow::anyhow!("required BTF value type for {name} missing"))
}

fn flow_value_btf_matches(btf: &btf::Btf<'_>, value: usize, payload: &str, size: usize) -> bool {
    (|| {
        let (lock, lock_offset) = btf.direct_member(value, "lock")?;
        let lock = btf.resolve_modifiers(lock)?;
        let (padding, padding_offset) = btf.direct_member(value, "padding")?;
        let (inner, payload_offset) = btf.direct_member(value, "value")?;
        Some(
            btf.u32_at(value + 8)? == size as u32
                && lock_offset == 0
                && btf.kind(lock)? == 4
                && btf.string(btf.u32_at(lock)?)? == "bpf_spin_lock"
                && btf.u32_at(lock + 8)? == 4
                && btf.sized_member_offset("bpf_spin_lock", "val", 4) == Some(0)
                && padding_offset == 4
                && btf.unsigned_integer_width(padding, 4)
                && payload_offset == 8
                && Some(btf.resolve_modifiers(inner)?) == btf.find_type(4, payload),
        )
    })()
    .unwrap_or(false)
}

fn tcp_proof_btf_matches(btf: &btf::Btf<'_>, value: usize) -> bool {
    Some(value) == btf.find_type(4, "TcpSocketBinding")
        && btf.u32_at(value + 8) == Some(120)
        && btf.sized_member_offset("TcpSocketBinding", "tuples", 40) == Some(0)
        && btf.sized_member_offset("TcpSocketBinding", "handoff", 72) == Some(40)
        && btf.sized_member_offset("TcpSocketBinding", "kind", 4) == Some(112)
        && btf.sized_member_offset("TcpSocketBinding", "syn_isn", 4) == Some(116)
}

fn validate_flow_lifetime_btf(data: &[u8]) -> anyhow::Result<()> {
    use core::mem::{offset_of, size_of};

    let btf =
        btf::Btf::parse(data).ok_or_else(|| anyhow::anyhow!("invalid flow lifetime object BTF"))?;
    for (name, size, fields) in [
        (
            "TuplesKey",
            size_of::<TuplesKey>(),
            &[("padding", 3, offset_of!(TuplesKey, padding))][..],
        ),
        (
            "ConnState",
            size_of::<ConnState>(),
            &[
                (
                    "is_wan_ingress_direction",
                    1,
                    offset_of!(ConnState, is_wan_ingress_direction),
                ),
                ("state", 1, offset_of!(ConnState, state)),
                ("tcp_syn_flags", 2, offset_of!(ConnState, tcp_syn_flags)),
                ("decision_token", 4, offset_of!(ConnState, decision_token)),
                ("last_seen_ns", 8, offset_of!(ConnState, last_seen_ns)),
                ("meta", 8, offset_of!(ConnState, meta)),
                ("mac", 6, offset_of!(ConnState, mac)),
                ("padding", 2, offset_of!(ConnState, padding)),
                ("pname", 16, offset_of!(ConnState, pname)),
                ("pid", 4, offset_of!(ConnState, pid)),
                ("trace_id", 4, offset_of!(ConnState, trace_id)),
                ("incarnation", 8, offset_of!(ConnState, incarnation)),
                ("tcp_syn_isn", 4, offset_of!(ConnState, tcp_syn_isn)),
                ("reserved", 4, offset_of!(ConnState, reserved)),
            ][..],
        ),
        (
            "RoutingHandoffEntry",
            size_of::<RoutingHandoffEntry>(),
            &[
                (
                    "last_seen_ns",
                    8,
                    offset_of!(RoutingHandoffEntry, last_seen_ns),
                ),
                ("result", 40, offset_of!(RoutingHandoffEntry, result)),
                (
                    "routing_generation",
                    8,
                    offset_of!(RoutingHandoffEntry, routing_generation),
                ),
                ("trace_id", 4, offset_of!(RoutingHandoffEntry, trace_id)),
                (
                    "trace_padding",
                    4,
                    offset_of!(RoutingHandoffEntry, trace_padding),
                ),
                (
                    "incarnation",
                    8,
                    offset_of!(RoutingHandoffEntry, incarnation),
                ),
            ][..],
        ),
        (
            "RoutingResult",
            size_of::<RoutingResult>(),
            &[
                ("mark", 4, offset_of!(RoutingResult, mark)),
                ("must", 1, offset_of!(RoutingResult, must)),
                ("mac", 6, offset_of!(RoutingResult, mac)),
                ("outbound", 1, offset_of!(RoutingResult, outbound)),
                ("pname", 16, offset_of!(RoutingResult, pname)),
                ("pid", 4, offset_of!(RoutingResult, pid)),
                ("dscp", 1, offset_of!(RoutingResult, dscp)),
                ("padding", 3, offset_of!(RoutingResult, padding)),
                (
                    "decision_token",
                    4,
                    offset_of!(RoutingResult, decision_token),
                ),
            ][..],
        ),
        (
            "RedirectEntry",
            size_of::<RedirectEntry>(),
            &[
                ("last_seen_ns", 8, offset_of!(RedirectEntry, last_seen_ns)),
                ("dmac", 6, offset_of!(RedirectEntry, dmac)),
                ("smac", 6, offset_of!(RedirectEntry, smac)),
                ("from_wan", 1, offset_of!(RedirectEntry, from_wan)),
                ("outbound", 1, offset_of!(RedirectEntry, outbound)),
                ("padding", 2, offset_of!(RedirectEntry, padding)),
                ("ifindex", 4, offset_of!(RedirectEntry, ifindex)),
                (
                    "decision_token",
                    4,
                    offset_of!(RedirectEntry, decision_token),
                ),
                ("incarnation", 8, offset_of!(RedirectEntry, incarnation)),
            ][..],
        ),
        (
            "DaeEvent",
            size_of::<DaeEvent>(),
            &[("incarnation", 8, offset_of!(DaeEvent, incarnation))][..],
        ),
    ] {
        anyhow::ensure!(
            btf.find_type(4, name)
                .and_then(|record| btf.u32_at(record + 8))
                == Some(size as u32)
                && fields.iter().all(|(member, width, offset)| btf
                    .sized_member_offset(name, member, *width)
                    == Some(*offset as u32)),
            "incompatible {name} ABI; rebuild the eBPF object"
        );
    }
    Ok(())
}

pub(super) fn validate_loaded_maps(bpf: &Ebpf) -> anyhow::Result<()> {
    use aya_obj::generated::bpf_map_type::*;
    for (name, type_, key, value, count, flags) in [
        (
            "CONN_STATE_MAP",
            BPF_MAP_TYPE_HASH,
            40,
            80,
            honk_ebpf_common::conn::MAX_CONN_STATE_NUM,
            1,
        ),
        ("REDIRECT_TRACK", BPF_MAP_TYPE_HASH, 40, 48, 65536, 1),
        ("ROUTING_HANDOFF_MAP", BPF_MAP_TYPE_HASH, 40, 80, 65536, 1),
        ("RETIRE_ACTIVE", BPF_MAP_TYPE_ARRAY, 4, 4, 1, 0),
        ("RETIRE_FENCE", BPF_MAP_TYPE_HASH, 40, 16, 65536, 1),
        ("TCP_LIVE_PINS", BPF_MAP_TYPE_HASH, 8, 1, 65536, 1),
        ("FLOW_INCARNATION_SEQUENCE", BPF_MAP_TYPE_ARRAY, 4, 16, 1, 0),
        ("RETIRE_GRACE_ROOT", BPF_MAP_TYPE_ARRAY_OF_MAPS, 4, 4, 1, 0),
        ("TCP_PUBLISHING", BPF_MAP_TYPE_HASH, 40, 8, 65536, 1),
        ("TCP_SOCKET_BINDING", BPF_MAP_TYPE_SK_STORAGE, 4, 120, 0, 1),
        ("AUX_OCCUPANCY", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 2, 0),
        ("ADMISSION_PRESSURE", BPF_MAP_TYPE_ARRAY, 4, 4, 1, 0),
    ] {
        syscall::validate_map_layout(bpf, name, type_, key, value, count, flags)?;
    }
    Ok(())
}

pub(super) fn validate_socket_identity(bpf: &Ebpf) -> anyhow::Result<()> {
    syscall::validate_map_layout(
        bpf,
        "SOCKET_IDENTITY",
        aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_SK_STORAGE,
        core::mem::size_of::<i32>() as u32,
        core::mem::size_of::<SocketIdentity>() as u32,
        0,
        aya_obj::generated::BPF_F_NO_PREALLOC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aya_obj::maps::{Map, PinningType};

    fn unique_offset(data: &[u8], needle: &[u8]) -> usize {
        let mut offsets = data
            .windows(needle.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset));
        let offset = offsets.next().expect("object metadata must be present");
        assert!(offsets.next().is_none(), "object metadata must be unique");
        offset
    }

    fn assert_implicit_pinning_rejected(data: &[u8], pinned_name: &str) {
        validate_object(crate::DEFAULT_BPF_OBJECT).expect("canonical object must be accepted");
        let original = aya_obj::Object::parse(crate::DEFAULT_BPF_OBJECT).unwrap();
        let pinned = aya_obj::Object::parse(data).unwrap();
        let abi = |map: &Map| {
            (
                map.map_type(),
                map.key_size(),
                map.value_size(),
                map.max_entries(),
                map.map_flags(),
                map.map_extra(),
            )
        };
        assert_eq!(original.maps.len(), pinned.maps.len());
        for (name, map) in &original.maps {
            assert_eq!(map.pinning(), PinningType::None);
            let changed = &pinned.maps[name];
            assert_eq!(abi(map), abi(changed), "map ABI changed for {name}");
            assert_eq!(
                changed.pinning(),
                if name == pinned_name {
                    PinningType::ByName
                } else {
                    PinningType::None
                },
                "unexpected pinning for {name}"
            );
        }
        let error = validate_object(data)
            .expect_err("object-declared implicit pinning must be rejected before loading");
        assert!(error.to_string().contains(pinned_name), "{error:#}");
    }

    #[test]
    fn object_layout_rejects_legacy_implicit_pinning() {
        let object = aya_obj::Object::parse(crate::DEFAULT_BPF_OBJECT).unwrap();
        let Map::Legacy(map) = &object.maps["RECEIVE_TRACE"] else {
            panic!("RECEIVE_TRACE must use legacy map metadata");
        };
        let def = map.def;
        let metadata: Vec<_> = [
            def.map_type,
            def.key_size,
            def.value_size,
            def.max_entries,
            def.map_flags,
            def.id,
            def.pinning as u32,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
        let mut data = crate::DEFAULT_BPF_OBJECT.to_vec();
        let offset = unique_offset(&data, &metadata)
            + core::mem::offset_of!(aya_obj::maps::bpf_map_def, pinning);
        data[offset..offset + 4].copy_from_slice(&(PinningType::ByName as u32).to_le_bytes());
        assert_implicit_pinning_rejected(&data, "RECEIVE_TRACE");
    }

    #[test]
    fn object_layout_rejects_btf_implicit_pinning() {
        let object = aya_obj::Object::parse(crate::DEFAULT_BPF_OBJECT).unwrap();
        assert!(matches!(
            object.maps["FLOW_INCARNATION_SEQUENCE"],
            Map::Btf(_)
        ));
        let raw = object.btf.as_ref().unwrap().to_bytes();
        let btf = btf::Btf::parse(&raw).unwrap();
        let var = btf.find_type(14, "FLOW_INCARNATION_SEQUENCE").unwrap();
        let def = btf.resolve_composite(btf.u32_at(var + 8).unwrap()).unwrap();
        let flags = (0..btf.u32_at(def + 4).unwrap() & 0xffff)
            .map(|index| def + 12 + index as usize * 12)
            .find(|member| btf.string(btf.u32_at(*member).unwrap()) == Some("map_flags"))
            .unwrap();
        let entries = btf.direct_member(def, "max_entries").unwrap().0;
        let strings =
            btf::BTF_HEADER_LEN + u32::from_le_bytes(raw[16..20].try_into().unwrap()) as usize;
        let pinning = unique_offset(&raw[strings..], b"pinning\0") as u32;
        let mut data = crate::DEFAULT_BPF_OBJECT.to_vec();
        let offset = unique_offset(&data, &raw) + flags;
        // Omitting the zero-valued map_flags field preserves the map ABI.
        data[offset..offset + 4].copy_from_slice(&pinning.to_le_bytes());
        data[offset + 4..offset + 8].copy_from_slice(&entries.to_le_bytes());
        assert_implicit_pinning_rejected(&data, "FLOW_INCARNATION_SEQUENCE");
    }

    #[test]
    fn lifetime_layout_rejects_implicit_padding_and_stale_incarnation() {
        let mut strings = vec![0];
        let mut add_name = |name: &str| {
            let offset = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            offset
        };
        let mut types = vec![
            0u32,
            1 << 24,
            1,
            8,
            0,
            1 << 24,
            8,
            64,
            0,
            3 << 24,
            0,
            1,
            1,
            3,
        ];
        let mut records = [0; 5];
        for (index, (name, size, members)) in [
            ("TuplesKey", 40, &[("padding", 3, 37)][..]),
            (
                "ConnState",
                72,
                &[
                    ("is_wan_ingress_direction", 1, 0),
                    ("state", 1, 1),
                    ("tcp_syn_flags", 19, 2),
                    ("decision_token", 9, 4),
                    ("last_seen_ns", 2, 8),
                    ("meta", 2, 16),
                    ("mac", 15, 24),
                    ("padding", 18, 30),
                    ("pname", 16, 32),
                    ("pid", 9, 48),
                    ("trace_id", 9, 52),
                    ("incarnation", 2, 56),
                    ("tcp_syn_isn", 9, 64),
                    ("reserved", 9, 68),
                ][..],
            ),
            (
                "RoutingHandoffEntry",
                72,
                &[
                    ("last_seen_ns", 2, 0),
                    ("result", 17, 8),
                    ("routing_generation", 2, 48),
                    ("trace_id", 9, 56),
                    ("trace_padding", 9, 60),
                    ("incarnation", 2, 64),
                ][..],
            ),
            (
                "RedirectEntry",
                40,
                &[
                    ("last_seen_ns", 2, 0),
                    ("dmac", 15, 8),
                    ("smac", 15, 14),
                    ("from_wan", 1, 20),
                    ("outbound", 1, 21),
                    ("padding", 18, 22),
                    ("ifindex", 9, 24),
                    ("decision_token", 9, 28),
                    ("incarnation", 2, 32),
                ][..],
            ),
            ("DaeEvent", 80, &[("incarnation", 2, 72)][..]),
        ]
        .into_iter()
        .enumerate()
        {
            records[index] = btf::BTF_HEADER_LEN + types.len() * 4;
            types.extend_from_slice(&[add_name(name), (4 << 24) | members.len() as u32, size]);
            for (member, type_id, offset) in members {
                types.extend_from_slice(&[add_name(member), *type_id, offset * 8]);
            }
        }
        // IDs 9/10: native u32 and the actual lock type, not a same-size integer.
        types.extend_from_slice(&[add_name("u32"), 1 << 24, 4, 32]);
        types.extend_from_slice(&[
            add_name("bpf_spin_lock"),
            (4 << 24) | 1,
            4,
            add_name("val"),
            9,
            0,
        ]);
        let mut wrappers = [0; 3];
        for (index, (name, payload, size)) in [
            ("ConnValue", 5, 80),
            ("RedirectValue", 7, 48),
            ("HandoffValue", 6, 80),
        ]
        .into_iter()
        .enumerate()
        {
            wrappers[index] = btf::BTF_HEADER_LEN + types.len() * 4;
            types.extend_from_slice(&[
                add_name(name),
                (4 << 24) | 3,
                size,
                add_name("lock"),
                10,
                0,
                add_name("padding"),
                9,
                32,
                add_name("value"),
                payload,
                64,
            ]);
        }
        let proof = btf::BTF_HEADER_LEN + types.len() * 4;
        types.extend_from_slice(&[
            add_name("TcpSocketBinding"),
            (4 << 24) | 4,
            120,
            add_name("tuples"),
            4,
            0,
            add_name("handoff"),
            6,
            320,
            add_name("kind"),
            9,
            896,
            add_name("syn_isn"),
            9,
            928,
        ]);
        // IDs 15/16: byte arrays used by the unchanged payloads.
        for length in [6, 16] {
            types.extend_from_slice(&[0, 3 << 24, 0, 1, 1, length]);
        }
        // ID 17: the unwrapped routing result nested in handoff/proof payloads.
        let routing_result = btf::BTF_HEADER_LEN + types.len() * 4;
        types.extend_from_slice(&[add_name("RoutingResult"), (4 << 24) | 9, 40]);
        for (name, type_id, offset) in [
            ("mark", 9, 0),
            ("must", 1, 4),
            ("mac", 15, 5),
            ("outbound", 1, 11),
            ("pname", 16, 12),
            ("pid", 9, 28),
            ("dscp", 1, 32),
            ("padding", 3, 33),
            ("decision_token", 9, 36),
        ] {
            types.extend_from_slice(&[add_name(name), type_id, offset * 8]);
        }
        types.extend_from_slice(&[0, 3 << 24, 0, 1, 1, 2]);
        types.extend_from_slice(&[add_name("u16"), 1 << 24, 2, 16]);
        let type_len = (types.len() * 4) as u32;
        let mut data = vec![0x9f, 0xeb, 1, 0];
        for word in [
            btf::BTF_HEADER_LEN as u32,
            0,
            type_len,
            type_len,
            strings.len() as u32,
        ] {
            data.extend_from_slice(&word.to_le_bytes());
        }
        for word in types {
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(&strings);
        let validate = |data: &[u8]| -> anyhow::Result<()> {
            validate_flow_lifetime_btf(data)?;
            let btf = btf::Btf::parse(data).unwrap();
            for ((record, payload), size) in wrappers
                .iter()
                .zip(["ConnState", "RedirectEntry", "RoutingHandoffEntry"])
                .zip([80, 48, 80])
            {
                anyhow::ensure!(
                    flow_value_btf_matches(&btf, *record, payload, size),
                    "wrapper rejected"
                );
            }
            anyhow::ensure!(tcp_proof_btf_matches(&btf, proof), "proof rejected");
            Ok(())
        };
        assert!(validate(&data).is_ok());
        let syn_name = proof + 48;
        let name: [u8; 4] = data[syn_name..syn_name + 4].try_into().unwrap();
        data[syn_name..syn_name + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate(&data).is_err());
        data[syn_name..syn_name + 4].copy_from_slice(&name);

        let padding_name = records[0] + 12;
        let name: [u8; 4] = data[padding_name..padding_name + 4].try_into().unwrap();
        data[padding_name..padding_name + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate(&data).is_err());
        data[padding_name..padding_name + 4].copy_from_slice(&name);

        let result_padding = routing_result + 12 + 7 * 12;
        for (offset, invalid) in [
            (result_padding, 0u32),
            (result_padding + 4, 18),
            (result_padding + 8, 32 * 8),
        ] {
            let original: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
            data[offset..offset + 4].copy_from_slice(&invalid.to_le_bytes());
            assert!(validate(&data).is_err());
            data[offset..offset + 4].copy_from_slice(&original);
            assert!(validate(&data).is_ok());
        }

        let size_offset = records[4] + 8;
        data[size_offset..size_offset + 4].copy_from_slice(&72u32.to_le_bytes());
        assert!(validate(&data).is_err());
        data[size_offset..size_offset + 4].copy_from_slice(&80u32.to_le_bytes());
        let incarnation_offset = records[4] + 20;
        data[incarnation_offset..incarnation_offset + 4]
            .copy_from_slice(&(64u32 * 8).to_le_bytes());
        assert!(validate(&data).is_err());
        data[incarnation_offset..incarnation_offset + 4]
            .copy_from_slice(&(72u32 * 8).to_le_bytes());
        assert!(validate(&data).is_ok());
        for wrapper in wrappers {
            for (offset, invalid) in [
                (wrapper + 16, 9u32),
                (wrapper + 20, 32),
                (wrapper + 32, 0),
                (wrapper + 44, 0),
            ] {
                let original: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
                data[offset..offset + 4].copy_from_slice(&invalid.to_le_bytes());
                assert!(validate(&data).is_err());
                data[offset..offset + 4].copy_from_slice(&original);
                assert!(validate(&data).is_ok());
            }
        }
        let handoff_offset = proof + 32;
        data[handoff_offset..handoff_offset + 4].copy_from_slice(&328u32.to_le_bytes());
        assert!(validate(&data).is_err());
    }
}
