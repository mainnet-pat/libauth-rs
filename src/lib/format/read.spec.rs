//! Port of `format/read.spec.ts`.

use libauth::message::read_components::read_bytes;
use libauth::{read_item_count, read_multiple, ReadPosition, ReadResult};

#[test]
fn read_multiple_() {
    let bin = [0, 1, 2, 3, 4];
    assert_eq!(
        read_multiple(
            ReadPosition { bin: &bin, index: 0 },
            (read_bytes(0), read_bytes(1), read_bytes(3))
        ),
        Ok(ReadResult {
            position: ReadPosition { bin: &[0, 1, 2, 3, 4], index: 4 },
            result: (vec![], vec![0], vec![1, 2, 3]),
        })
    );
    assert_eq!(
        read_multiple(
            ReadPosition { bin: &bin, index: 0 },
            (read_bytes(0), read_bytes(1), read_bytes(3), read_bytes(2))
        ),
        Err("Error reading bytes: insufficient length. Bytes requested: 2; remaining bytes: 1".to_string())
    );
}

#[test]
fn read_item_count_() {
    assert_eq!(
        read_item_count(ReadPosition { bin: &[0, 1, 2, 3, 4], index: 0 }, read_bytes(2)),
        Ok(ReadResult {
            position: ReadPosition { bin: &[0, 1, 2, 3, 4], index: 1 },
            result: vec![],
        })
    );
    assert_eq!(
        read_item_count(ReadPosition { bin: &[1, 1, 2, 3, 4], index: 0 }, read_bytes(2)),
        Ok(ReadResult {
            position: ReadPosition { bin: &[1, 1, 2, 3, 4], index: 3 },
            result: vec![vec![1, 2]],
        })
    );
    assert_eq!(
        read_item_count(ReadPosition { bin: &[2, 1, 2, 3, 4], index: 0 }, read_bytes(2)),
        Ok(ReadResult {
            position: ReadPosition { bin: &[2, 1, 2, 3, 4], index: 5 },
            result: vec![vec![1, 2], vec![3, 4]],
        })
    );
    assert_eq!(
        read_item_count(ReadPosition { bin: &[0xfd, 1], index: 0 }, read_bytes(2)),
        Err("Error reading item count. Error reading CompactUint: insufficient bytes. CompactUint prefix 253 requires at least 3 bytes. Remaining bytes: 2".to_string())
    );
    assert_eq!(
        read_item_count(ReadPosition { bin: &[1, 1], index: 0 }, read_bytes(2)),
        Err("Error reading item. Error reading bytes: insufficient length. Bytes requested: 2; remaining bytes: 1".to_string())
    );
}
