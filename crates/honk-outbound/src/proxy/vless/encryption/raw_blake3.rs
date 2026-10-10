const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const DERIVE_KEY_CONTEXT: u32 = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;
const CHUNK_LEN: usize = 1024;
const BLOCK_LEN: usize = 64;
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

#[derive(Clone, Copy)]
struct Output {
    input_cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(self) -> [u32; 8] {
        compress(
            self.input_cv,
            self.block,
            self.counter,
            self.block_len,
            self.flags,
        )[..8]
            .try_into()
            .expect("BLAKE3 chaining value length")
    }

    fn root_hash(self) -> [u8; 32] {
        let words = compress(
            self.input_cv,
            self.block,
            0,
            self.block_len,
            self.flags | ROOT,
        );
        let mut output = [0u8; 32];
        for (chunk, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        output
    }
}

pub(super) fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
    let context_key = hash(context, IV, DERIVE_KEY_CONTEXT);
    let mut key_words = [0u32; 8];
    for (word, bytes) in key_words
        .iter_mut()
        .zip(context_key.as_chunks::<4>().0.iter())
    {
        *word = u32::from_le_bytes(*bytes);
    }
    hash(material, key_words, DERIVE_KEY_MATERIAL)
}

fn hash(mut input: &[u8], key: [u32; 8], flags: u32) -> [u8; 32] {
    let mut stack = Vec::<[u32; 8]>::new();
    let mut chunk_counter = 0u64;
    while input.len() > CHUNK_LEN {
        let mut cv = chunk_output(&input[..CHUNK_LEN], key, chunk_counter, flags).chaining_value();
        let mut total_chunks = chunk_counter + 1;
        while total_chunks & 1 == 0 {
            cv = parent_output(stack.pop().expect("left BLAKE3 subtree"), cv, key, flags)
                .chaining_value();
            total_chunks >>= 1;
        }
        stack.push(cv);
        input = &input[CHUNK_LEN..];
        chunk_counter += 1;
    }
    let mut output = chunk_output(input, key, chunk_counter, flags);
    while let Some(left) = stack.pop() {
        output = parent_output(left, output.chaining_value(), key, flags);
    }
    output.root_hash()
}

fn chunk_output(input: &[u8], key: [u32; 8], counter: u64, flags: u32) -> Output {
    let mut cv = key;
    let mut offset = 0;
    while input.len().saturating_sub(offset) > BLOCK_LEN {
        let block = words(&input[offset..offset + BLOCK_LEN]);
        let block_flags = flags | if offset == 0 { CHUNK_START } else { 0 };
        cv = compress(cv, block, counter, BLOCK_LEN as u32, block_flags)[..8]
            .try_into()
            .expect("BLAKE3 chaining value length");
        offset += BLOCK_LEN;
    }
    let remaining = &input[offset..];
    Output {
        input_cv: cv,
        block: words(remaining),
        counter,
        block_len: remaining.len() as u32,
        flags: flags | CHUNK_END | if offset == 0 { CHUNK_START } else { 0 },
    }
}

fn parent_output(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&left);
    block[8..].copy_from_slice(&right);
    Output {
        input_cv: key,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flags | PARENT,
    }
}

fn words(bytes: &[u8]) -> [u32; 16] {
    let mut block = [0u8; BLOCK_LEN];
    block[..bytes.len()].copy_from_slice(bytes);
    let mut words = [0u32; 16];
    for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0.iter()) {
        *word = u32::from_le_bytes(*bytes);
    }
    words
}

fn compress(cv: [u32; 8], block: [u32; 16], counter: u64, block_len: u32, flags: u32) -> [u32; 16] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    for schedule in MSG_SCHEDULE {
        round(&mut state, &block, &schedule);
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

fn round(state: &mut [u32; 16], message: &[u32; 16], schedule: &[usize; 16]) {
    g(
        state,
        0,
        4,
        8,
        12,
        message[schedule[0]],
        message[schedule[1]],
    );
    g(
        state,
        1,
        5,
        9,
        13,
        message[schedule[2]],
        message[schedule[3]],
    );
    g(
        state,
        2,
        6,
        10,
        14,
        message[schedule[4]],
        message[schedule[5]],
    );
    g(
        state,
        3,
        7,
        11,
        15,
        message[schedule[6]],
        message[schedule[7]],
    );
    g(
        state,
        0,
        5,
        10,
        15,
        message[schedule[8]],
        message[schedule[9]],
    );
    g(
        state,
        1,
        6,
        11,
        12,
        message[schedule[10]],
        message[schedule[11]],
    );
    g(
        state,
        2,
        7,
        8,
        13,
        message[schedule[12]],
        message[schedule[13]],
    );
    g(
        state,
        3,
        4,
        9,
        14,
        message[schedule[14]],
        message[schedule[15]],
    );
}

fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}
