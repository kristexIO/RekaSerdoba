use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rekaserdoba_server::record::{
    EpochKeys, RecordKind, RecordReceiver, RecordSender, parse_frames,
};

fn protocol(c: &mut Criterion) {
    let body = vec![0x5a; 1280];
    let mut encoded = Vec::with_capacity(body.len() + 4);
    encoded.push(1);
    encoded.push(0);
    encoded.extend_from_slice(&(body.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&body);

    let mut parsing = c.benchmark_group("record_frames");
    parsing.throughput(Throughput::Bytes(encoded.len() as u64));
    parsing.bench_function("parse", |b| {
        b.iter(|| parse_frames(&encoded, RecordKind::Data).unwrap())
    });
    parsing.finish();

    let session_id = [7u8; 16];
    let sender_keys = EpochKeys::derive([9u8; 32], session_id, 0).unwrap();
    let receiver_keys = EpochKeys::derive([9u8; 32], session_id, 0).unwrap();
    let sender = RecordSender::new(RecordKind::Data, session_id, 0, sender_keys.c2s_data);
    let mut receiver = RecordReceiver::new(
        RecordKind::Data,
        session_id,
        0,
        receiver_keys.c2s_data,
        4096,
    )
    .unwrap();
    let mut number = 0u64;

    let mut crypto = c.benchmark_group("record_crypto");
    crypto.throughput(Throughput::Bytes(encoded.len() as u64));
    crypto.bench_function("seal_open", |b| {
        b.iter(|| {
            let sealed = sender.seal(&encoded, false).unwrap();
            let opened = receiver.open(&sealed).unwrap();
            number = number.wrapping_add(opened.len() as u64);
        })
    });
    crypto.finish();
    std::hint::black_box(number);
}

criterion_group!(benches, protocol);
criterion_main!(benches);
