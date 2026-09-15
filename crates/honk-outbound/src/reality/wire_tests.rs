use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn hello_offers_hybrid_then_preset_classic_and_authenticates_full_transcript() {
    let server_private = [0x51_u8; 32];
    let mut server_public = [0_u8; 32];
    unsafe {
        boring_sys::X25519_public_from_private(server_public.as_mut_ptr(), server_private.as_ptr())
    };
    let config = RealityConfig {
        public_key: server_public,
        short_id: [0x19; 8],
        server_name: "localhost".to_owned(),
    };
    let (client, mut peer) = tokio::io::duplex(16 * 1024);
    let connect = tokio::spawn(async move { reality_connect(client, &config, false).await });
    let mut record_header = [0_u8; 5];
    peer.read_exact(&mut record_header).await.unwrap();
    assert_eq!(record_header[0], 22);
    let mut hello = vec![0; u16::from_be_bytes([record_header[3], record_header[4]]) as usize];
    peer.read_exact(&mut hello).await.unwrap();
    assert_eq!(hello[0], 1);
    assert_eq!(hello[38], 32);
    let mut cursor = 71;
    let ciphers = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
    cursor += 2 + ciphers;
    cursor += 1 + hello[cursor] as usize;
    let extensions_len = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
    cursor += 2;
    let end = cursor + extensions_len;
    let mut shares = Vec::new();
    let mut classic_public = None;
    while cursor < end {
        let kind = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
        let len = u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]) as usize;
        cursor += 4;
        if kind == 51 {
            let mut share = cursor + 2;
            while share < cursor + len {
                let group = u16::from_be_bytes([hello[share], hello[share + 1]]);
                let size = u16::from_be_bytes([hello[share + 2], hello[share + 3]]) as usize;
                share += 4;
                shares.push((group, size));
                if group == 29 {
                    classic_public = Some(hello[share..share + size].try_into().unwrap());
                }
                share += size;
            }
        }
        cursor += len;
    }
    assert_eq!(shares, vec![(0x11ec, 1184 + 32), (29, 32)]);
    let classic_public: [u8; 32] = classic_public.unwrap();
    let mut shared = [0_u8; 32];
    assert_eq!(
        unsafe {
            boring_sys::X25519(
                shared.as_mut_ptr(),
                server_private.as_ptr(),
                classic_public.as_ptr(),
            )
        },
        1
    );
    let mut auth_key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&hello[6..26]), &shared)
        .expand(b"REALITY", &mut auth_key)
        .unwrap();
    let mut sealed = hello[39..71].to_vec();
    let nonce = hello[26..38].to_vec();
    hello[39..71].fill(0);
    let aead =
        boring::aead::AeadCtx::new_default_tag(&boring::aead::Algorithm::aes_256_gcm(), &auth_key)
            .unwrap();
    let (plaintext, tag) = sealed.split_at_mut(16);
    aead.open_in_place(&nonce, plaintext, tag, &hello).unwrap();
    assert_eq!(&plaintext[8..], &[0x19; 8]);
    peer.write_all(&[21, 3, 3, 0, 2, 2, 80]).await.unwrap();
    assert!(connect.await.unwrap().is_err());
}

#[test]
fn repeated_client_hello_is_rejected_without_resealing() {
    let connector = crate::tls::build_reality_connector(false).unwrap();
    let ssl = connector.configure().unwrap();
    setup_reality_ssl(
        &ssl,
        &RealityConfig {
            public_key: [7; 32],
            short_id: [0; 8],
            server_name: "localhost".into(),
        },
    )
    .unwrap();
    let mut hello = vec![1, 0, 0, 0x4d, 3, 3];
    hello.extend_from_slice(&[0x33; 32]);
    hello.push(32);
    hello.extend_from_slice(&[0; 32]);
    hello.extend(0xa0..0xb0);
    assert_eq!(
        reality_fixup_cb(ssl.as_ptr(), hello.as_mut_ptr(), hello.len()),
        1
    );
    let sealed = hello.clone();
    assert_eq!(
        reality_fixup_cb(ssl.as_ptr(), hello.as_mut_ptr(), hello.len()),
        0
    );
    assert_eq!(hello, sealed);
}
