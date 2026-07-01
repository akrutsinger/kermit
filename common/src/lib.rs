#![no_std]

pub struct StdoutWriter;

impl core::fmt::Write for StdoutWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { libc::write(1, s.as_ptr() as *const libc::c_void, s.len()) };
        Ok(())
    }
}

#[macro_export]
macro_rules! dbgprintln {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            use core::fmt::Write as _;
            let _ = core::write!($crate::StdoutWriter, $($arg)*);
            let _ = $crate::StdoutWriter.write_str("\n");
        }
        // Release: emit nothing, but still reference the args so variables that exist only to be
        // logged don't trip `unused_variables`.
        #[cfg(not(debug_assertions))]
        let _ = core::format_args!($($arg)*);
    }};
}
