
pub fn copy_memory(input: &[u8], out: &mut [u8]) -> usize {
    for count in 0..input.len() {out[count] = input[count];}
    input.len()
}
