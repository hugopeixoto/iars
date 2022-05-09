use rand::{thread_rng, Rng};
use std::fmt::Write;

pub fn generate_code() -> String {
    let mut arr = [0u8; 20];

    thread_rng().fill(&mut arr[..]);

    let mut s = String::new();

    for &b in arr.iter() {
        write!(&mut s, "{:02X}", b).unwrap();
    }

    s
}
