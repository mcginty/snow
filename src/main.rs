extern crate noiseref;

fn main() {
    let mut output = [0u8; 32];
    noiseref::HASH("abc".as_bytes(), &mut output);
    for b in &output {print!("{:x}", b);}
}
