//! Review test (not part of the branch): what a forged snapshot costs the
//! joining node in memory before it is refused.
use sha2::{Digest, Sha256};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::*;
use timecurrency_v5::{
    app::App,
    proof::key_hash,
    statesync::{Manifest, NodeOptions, SYNC_CHUNK_BYTES, SYNC_FORMAT, metadata_hash},
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[test]
fn review_a_forged_snapshot_is_refused_within_the_memory_the_documentation_names() {
    // What any peer can advertise for a height the light client knows: a
    // file in the snapshot format, with the public application hash of that
    // height in its header, a correct checksum, and rows of its own choice.
    // Here: the smallest rows the format allows, sorted by key hash.
    const ROWS: u32 = 1_000_000;
    let (height, trusted) = (1000u64, [7u8; 32]);
    let mut keys: Vec<([u8; 32], [u8; 4])> = (0..ROWS)
        .map(|index| (key_hash(&index.to_be_bytes()), index.to_be_bytes()))
        .collect();
    keys.sort_unstable();
    let mut file = Vec::new();
    file.extend_from_slice(b"TIMEV5SNAPSHOT\0\x01");
    file.extend_from_slice(&height.to_be_bytes());
    file.extend_from_slice(&trusted);
    file.extend_from_slice(&[0u8; 32]);
    file.extend_from_slice(&u64::from(ROWS).to_be_bytes());
    file.extend_from_slice(&0u32.to_be_bytes());
    for (_, key) in &keys {
        file.extend_from_slice(&4u16.to_be_bytes());
        file.extend_from_slice(key);
        file.extend_from_slice(&0u32.to_be_bytes());
    }
    let digest: [u8; 32] = Sha256::digest(&file).into();
    file.extend_from_slice(&digest);
    drop(keys);
    let chunks: Vec<&[u8]> = file.chunks(SYNC_CHUNK_BYTES as usize).collect();
    let metadata = Manifest {
        total_bytes: file.len() as u64,
        chunk_bytes: SYNC_CHUNK_BYTES,
        chunk_hashes: chunks.iter().map(|chunk| Sha256::digest(chunk).into()).collect(),
    }
    .encode();

    let dir = tempfile::tempdir().unwrap();
    let app = App::open_with_options(dir.path().join("joiner.db"), NodeOptions::default()).unwrap();
    let offer = app.offer_snapshot(RequestOfferSnapshot {
        snapshot: Some(Snapshot {
            height,
            format: SYNC_FORMAT,
            chunks: chunks.len() as u32,
            hash: metadata_hash(&metadata).to_vec().into(),
            metadata: metadata.into(),
        }),
        app_hash: trusted.to_vec().into(),
    });
    assert_eq!(offer.result, response_offer_snapshot::Result::Accept as i32);
    let last = chunks.len() - 1;
    for (index, chunk) in chunks[..last].iter().enumerate() {
        let request = RequestApplySnapshotChunk { index: index as u32, chunk: chunk.to_vec().into(), sender: "attacker".into() };
        assert_eq!(app.apply_snapshot_chunk(request).result, response_apply_snapshot_chunk::Result::Accept as i32);
    }
    let request = RequestApplySnapshotChunk { index: last as u32, chunk: chunks[last].to_vec().into(), sender: "attacker".into() };
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let answer = app.apply_snapshot_chunk(request);
    let used = PEAK.load(Ordering::Relaxed) - before;
    // It is refused, as it must be.
    assert_eq!(answer.result, response_apply_snapshot_chunk::Result::RejectSnapshot as i32);
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);
    let ratio = used as f64 / file.len() as f64;
    eprintln!(
        "forged snapshot: {} bytes on disk, {} rows; memory allocated on top while it was checked: {} bytes ({ratio:.1} times the file).",
        file.len(),
        ROWS,
        used
    );
    // The documentation: "one chunk and the manifest" while chunks arrive,
    // and for the rebuild "the whole state in memory, as the running node
    // does". A forged file is not the state; a node sized for the real
    // state should refuse it without holding a multiple of its length.
    assert!(used <= 2 * file.len(), "{used} bytes for a {} byte file", file.len());
}
