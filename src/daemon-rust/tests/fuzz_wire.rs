use gungnird::{
    ipc::{self, Frame},
    md::{self, Request, Value},
};

#[test]
fn fuzz_frame_header_parsing_does_not_panic() {
    let mut rng: u64 = 0xdead_beef_cafe_babe;
    let mut next_u32 = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng as u32
    };

    for _ in 0..10_000 {
        let mut buf = [0u8; 16];
        for chunk in buf.chunks_mut(4) {
            chunk.copy_from_slice(&next_u32().to_le_bytes());
        }

        // Must never panic on arbitrary byte sequences
        let frame = Frame::decode(&buf);
        let _ = frame.encode();
    }
}

#[test]
fn fuzz_md_wire_parsing_does_not_panic() {
    let mut rng: u64 = 0x1234_5678_9abc_def0;
    let mut next_bytes = |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            *b = (rng & 0xff) as u8;
        }
    };

    let kinds = [
        md::MSG_MD_IDENTIFY,
        md::MSG_MD_GET,
        md::MSG_MD_SET,
        md::MSG_MD_UNSET,
        md::MSG_MD_LIST,
        md::MSG_MD_REMOVED,
        md::MSG_MD_MOVED,
        ipc::MSG_PING,
        ipc::MSG_PONG,
        999, // Unknown kind
    ];

    let mut scratch = [0u8; 512];
    for len in [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
        for _ in 0..100 {
            next_bytes(&mut scratch[..len]);
            for &k in &kinds {
                // Parsing malformed requests must safely return Result, never panic
                let _ = Request::parse(k, &scratch[..len]);
            }
            let _ = Value::decode(&scratch[..len]);
            let _ = md::reply_result(&scratch[..len]);
        }
    }
}
