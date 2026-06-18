#[macro_export]
macro_rules! dbgprintln {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        println!($($arg)*);
    }};
}
