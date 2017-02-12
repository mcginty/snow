//#[macro_export]
//macro_rules! named_struct {
//    (struct $name:ident { $($fname:ident : $ftype:ty),* }) => {
//        struct $name {
//            $($fname : $ftype),*
//        }
//
//        impl Named for $name {
//            fn name() -> &'static [&'static str] {
//                static NAME: &'static str = stringify!($name);
//                NAME
//            }
//        }
//    }
//}
//
//trait Named {
//    fn name() -> &'static str;
//}

pub fn copy_memory(input: &[u8], out: &mut [u8]) -> usize {
    for count in 0..input.len() {out[count] = input[count];}
    input.len()
}

pub enum Toggle<T> {
    On(T),
    Off(T)
}