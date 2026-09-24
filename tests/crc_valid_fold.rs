//! CRC-valid PGSS fixtures (checksum over type+payload is recomputed).
//!
//! Documents B26: a CRC-ok put whose version length is shortened (CRC
//! rewritten) leaves the old big-endian version bytes as `00 00 …` at the
//! next record boundary. `parse_record` treats `crc=0 && type=0` as a torn
//! tail (B4 fix) and `load` rewrites the CRC-valid suffix away.

use slipstream::snapshot::{SnapshotError, load};
use std::path::Path;
use tempfile::TempDir;

const MAGIC: &[u8; 4] = b"PGSS";
const REC_PUT: u8 = 0x01;
const REC_CURSOR: u8 = 0x03;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let c = crc32(payload);
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&c.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn put_rec(key: &str, value: &[u8], ver: &[u8]) -> Vec<u8> {
    let mut p = vec![REC_PUT];
    p.extend_from_slice(&(key.len() as u16).to_le_bytes());
    p.extend_from_slice(key.as_bytes());
    p.extend_from_slice(&(value.len() as u32).to_le_bytes());
    p.extend_from_slice(value);
    p.push(ver.len() as u8);
    p.extend_from_slice(ver);
    frame(&p)
}

fn cur_rec(cur: &[u8]) -> Vec<u8> {
    let mut p = vec![REC_CURSOR, cur.len() as u8];
    p.extend_from_slice(cur);
    frame(&p)
}

fn describe(path: &Path) -> String {
    match load(path) {
        Ok(None) => "Ok(None)".into(),
        Ok(Some(s)) => {
            let mut keys: Vec<_> = s.entries.keys().cloned().collect();
            keys.sort();
            format!("Ok(Some) keys={keys:?} cur={:?}", s.cursor.as_u64())
        }
        Err(SnapshotError::Corrupted) => "Err(Corrupted)".into(),
        Err(e) => format!("Err({e})"),
    }
}

/// `ver_len` shrunk 8→0, CRC recomputed over the short payload, leftover
/// NATS `u64` BE version (`00 00 00 00 00 00 00 01`) sits in front of a
/// still-CRC-valid PUT+CURSOR.
#[test]
fn ver_len_shrink_crc_ok_drops_suffix() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s.snap");

    let mut short = vec![REC_PUT];
    short.extend_from_slice(&1u16.to_le_bytes());
    short.extend_from_slice(b"a");
    short.extend_from_slice(&1u32.to_le_bytes());
    short.extend_from_slice(b"x");
    short.push(0); // ver_len = 0, CRC covers this
    let mut data = MAGIC.to_vec();
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&frame(&short));
    data.extend_from_slice(&1u64.to_be_bytes()); // leftover version
    data.extend_from_slice(&put_rec("b", b"y", &2u64.to_be_bytes()));
    data.extend_from_slice(&cur_rec(&2u64.to_be_bytes()));
    let before = data.len();
    std::fs::write(&path, &data).unwrap();

    let snap = load(&path).unwrap().expect("prefix still loads");
    let after = std::fs::read(&path).unwrap();
    eprintln!(
        "CONFIRMED B26 ver_len-shrink: {} before={before} after={} keys={:?} cur={:?}",
        describe(&path),
        after.len(),
        snap.entries.keys().collect::<Vec<_>>(),
        snap.cursor.as_u64()
    );
    assert!(
        !snap.entries.contains_key("b") && snap.cursor.as_u64() != Some(2),
        "B26: suffix must be gone on current main"
    );
    assert!(
        after.len() < before,
        "load rewrote the CRC-valid suffix away"
    );
}

/// Writer-framed PUTs (CRC intact) with 5 NULs punched between them.
#[test]
fn mid_file_five_nuls_drops_crc_valid_suffix() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s.snap");

    let mut data = MAGIC.to_vec();
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&put_rec("a", b"x", &1u64.to_be_bytes()));
    data.extend_from_slice(&[0u8; 5]);
    data.extend_from_slice(&put_rec("b", b"y", &2u64.to_be_bytes()));
    data.extend_from_slice(&cur_rec(&2u64.to_be_bytes()));
    let before = data.len();
    std::fs::write(&path, &data).unwrap();

    let snap = load(&path).unwrap().expect("prefix still loads");
    let after = std::fs::read(&path).unwrap();
    eprintln!(
        "CONFIRMED B26 mid-NUL5: keys={:?} cur={:?} before={before} after={}",
        snap.entries.keys().collect::<Vec<_>>(),
        snap.cursor.as_u64(),
        after.len()
    );
    assert_eq!(snap.entries.len(), 1);
    assert!(snap.entries.contains_key("a"));
    assert!(!snap.entries.contains_key("b"));
    assert_eq!(snap.cursor.as_u64(), None);
    assert!(after.len() < before);
}
