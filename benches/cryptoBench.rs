use crate::aes::{aes_128_gcm, aes_128_gcm_siv, aes_256_gcm, aes_256_gcm_siv};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::RngCore;
use std::sync::Once;
use std::time::Duration;

pub mod aes;

static INIT_KEY_AND_DATA: Once = Once::new();
static mut KEY_128BIT: [u8; 16] = [0; 16];
static mut KEY_256BIT: [u8; 32] = [0; 32];
static mut NONCE_96BIT: [u8; 12] = [0; 12];
static mut PAYLOAD_1KB: [u8; 1024] = [0; 1024];
static mut PAYLOAD_1MB_HEAP: Vec<u8> = Vec::new();

fn init() {
    let mut rng = rand::thread_rng();
    unsafe {
        println!("init");
        // Init test data
        rng.fill_bytes(&mut KEY_128BIT);
        rng.fill_bytes(&mut KEY_256BIT);
        rng.fill_bytes(&mut NONCE_96BIT);
        rng.fill_bytes(&mut PAYLOAD_1KB);

        // Init heap test data
        PAYLOAD_1MB_HEAP = vec![0; 1024 * 1024];
        rng.fill_bytes(&mut PAYLOAD_1MB_HEAP);
        println!("init done");
    }
}

fn get_key_128() -> [u8; 16] {
    unsafe { KEY_128BIT }
}
fn get_key_256() -> [u8; 32] {
    unsafe { KEY_256BIT }
}

fn get_nonce_96() -> [u8; 12] {
    unsafe { NONCE_96BIT }
}

fn get_payload_1kb() -> [u8; 1024] {
    unsafe { PAYLOAD_1KB }
}

fn get_payload_1mb_heap() -> Vec<u8> {
    unsafe { PAYLOAD_1MB_HEAP.clone() }
}

fn benchmark_aes_128_gcm(c: &mut Criterion) {
    INIT_KEY_AND_DATA.call_once(|| {
        init();
    });
    c.bench_function("aes_128_gcm-1KB", |b| {
        b.iter(|| {
            aes_128_gcm(
                black_box(&get_key_128()),
                black_box(&get_nonce_96()),
                black_box(&get_payload_1kb()),
            )
        })
    });
    c.bench_function("aes_128_gcm-1MB", |b| {
        b.iter(|| {
            aes_128_gcm(
                black_box(&get_key_128()),
                black_box(&get_nonce_96()),
                black_box(&get_payload_1mb_heap()),
            )
        })
    });
}
fn benchmark_aes_256_gcm(c: &mut Criterion) {
    INIT_KEY_AND_DATA.call_once(|| {
        init();
    });
    c.bench_function("aes_256_gcm-1KB", |b| {
        b.iter(|| {
            aes_256_gcm(
                black_box(&get_key_256()),
                black_box(&get_nonce_96()),
                black_box(&get_payload_1kb()),
            )
        })
    });
    c.bench_function("aes_256_gcm-1MB", |b| {
        b.iter(|| {
            aes_256_gcm(
                black_box(&get_key_256()),
                black_box(&get_nonce_96()),
                black_box(&get_payload_1mb_heap()),
            )
        })
    });
}

fn benchmark_aes_128_gcm_siv(c: &mut Criterion) {
    INIT_KEY_AND_DATA.call_once(|| {
        init();
    });
    c.bench_function("aes_128_gcm_siv-1KB", |b| {
        b.iter(|| {
            aes_128_gcm_siv(
                black_box(&get_key_128()),
                black_box(&get_nonce_96()),
                black_box(&get_payload_1kb()),
            )
        })
    });
    c.bench_function("aes_128_gcm_siv-1MB", |b| {
        b.iter(|| {
            aes_128_gcm_siv(
                black_box(&get_key_128()),
                black_box(&get_nonce_96()),
                black_box(&get_payload_1mb_heap()),
            )
        })
    });
}
fn benchmark_aes_256_gcm_siv(c: &mut Criterion) {
    INIT_KEY_AND_DATA.call_once(|| {
        init();
    });
    c.bench_function("aes_256_gcm_siv-1KB", |b| {
        b.iter(|| {
            aes_256_gcm_siv(
                black_box(&get_key_256()),
                black_box(&get_nonce_96()),
                black_box(&get_payload_1kb()),
            )
        })
    });
    c.bench_function("aes_256_gcm_siv-1MB", |b| {
        b.iter(|| {
            aes_256_gcm_siv(
                black_box(&get_key_256()),
                black_box(&get_nonce_96()),
                black_box(&get_payload_1mb_heap()),
            )
        })
    });
}

criterion_group! {
  name = benches;
  config = Criterion::default().measurement_time(Duration::from_secs(20));
  targets = benchmark_aes_128_gcm, benchmark_aes_256_gcm, benchmark_aes_128_gcm_siv,benchmark_aes_256_gcm_siv
}
criterion_main!(benches);
