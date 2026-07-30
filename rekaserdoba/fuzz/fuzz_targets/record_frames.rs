#![no_main]

use libfuzzer_sys::fuzz_target;
use rekaserdoba_server::record::{RecordKind, parse_frames};

fuzz_target!(|data: &[u8]| {
    let _ = parse_frames(data, RecordKind::Data);
    let _ = parse_frames(data, RecordKind::Control);
});
