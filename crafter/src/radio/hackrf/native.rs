//! Minimal receive-only ABI reviewed against libhackrf hackrf.h at cc691022.
//! No transmit symbol is declared. Library lifecycle is serialized in this crate.
use super::*;
use std::{
    ffi::{c_char, c_int, c_void, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};
static LIBRARY: Mutex<()> = Mutex::new(());
#[repr(C)]
struct Transfer {
    device: *mut c_void,
    buffer: *mut u8,
    buffer_length: c_int,
    valid_length: c_int,
    rx_ctx: *mut c_void,
    tx_ctx: *mut c_void,
}
#[repr(C)]
#[derive(Default)]
struct M0State {
    requested_mode: u16,
    request_flag: u16,
    active_mode: u32,
    m0_count: u32,
    m4_count: u32,
    num_shortfalls: u32,
    longest_shortfall: u32,
    shortfall_limit: u32,
    threshold: u32,
    next_mode: u32,
    error: u32,
}
#[link(name = "hackrf")]
extern "C" {
    fn hackrf_init() -> c_int;
    fn hackrf_exit() -> c_int;
    fn hackrf_open_by_serial(serial: *const c_char, device: *mut *mut c_void) -> c_int;
    fn hackrf_close(device: *mut c_void) -> c_int;
    fn hackrf_set_sample_rate(device: *mut c_void, rate: f64) -> c_int;
    fn hackrf_set_baseband_filter_bandwidth(device: *mut c_void, bandwidth: u32) -> c_int;
    fn hackrf_set_freq(device: *mut c_void, frequency: u64) -> c_int;
    fn hackrf_set_lna_gain(device: *mut c_void, gain: u32) -> c_int;
    fn hackrf_set_vga_gain(device: *mut c_void, gain: u32) -> c_int;
    fn hackrf_set_amp_enable(device: *mut c_void, enable: u8) -> c_int;
    fn hackrf_set_antenna_enable(device: *mut c_void, enable: u8) -> c_int;
    fn hackrf_set_rx_overrun_limit(device: *mut c_void, limit: u32) -> c_int;
    fn hackrf_start_rx(
        device: *mut c_void,
        callback: unsafe extern "C" fn(*mut Transfer) -> c_int,
        context: *mut c_void,
    ) -> c_int;
    fn hackrf_stop_rx(device: *mut c_void) -> c_int;
    fn hackrf_is_streaming(device: *mut c_void) -> c_int;
    fn hackrf_get_m0_state(device: *mut c_void, state: *mut M0State) -> c_int;
}
fn check(operation: &str, code: c_int) -> RadioResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(RadioError::Source(format!(
            "{operation}: libhackrf error {code}"
        )))
    }
}
pub(super) struct Native {
    device: *mut c_void,
    context: Option<Box<Arc<Shared>>>,
    _library: MutexGuard<'static, ()>,
}
impl Native {
    pub(super) fn open(config: HackRfConfig) -> RadioResult<Self> {
        let library = LIBRARY.try_lock().map_err(|_| {
            RadioError::Source("another crafter HackRF acquisition owns libhackrf".into())
        })?;
        let serial = CString::new(config.serial).map_err(|_| RadioError::Invalid {
            field: "serial",
            reason: "interior NUL",
        })?;
        // SAFETY: serialized init/open; serial and output pointer live across calls.
        unsafe {
            check("init", hackrf_init())?;
        }
        let mut native = Self {
            device: ptr::null_mut(),
            context: None,
            _library: library,
        };
        // SAFETY: all configuration calls receive the successfully opened handle;
        // failure drops native and closes it. Rate precedes explicit filter.
        unsafe {
            check(
                "open",
                hackrf_open_by_serial(serial.as_ptr(), &mut native.device),
            )?;
            check(
                "sample rate",
                hackrf_set_sample_rate(native.device, config.rx.sample_rate_hz as f64),
            )?;
            check(
                "baseband filter",
                hackrf_set_baseband_filter_bandwidth(native.device, config.baseband_filter_hz),
            )?;
            check(
                "frequency",
                hackrf_set_freq(native.device, config.rx.center_frequency_hz),
            )?;
            check(
                "LNA gain",
                hackrf_set_lna_gain(native.device, config.lna_gain_db),
            )?;
            check(
                "VGA gain",
                hackrf_set_vga_gain(native.device, config.vga_gain_db),
            )?;
            check(
                "RF amplifier",
                hackrf_set_amp_enable(native.device, config.amplifier_enabled.into()),
            )?;
            check(
                "antenna power",
                hackrf_set_antenna_enable(native.device, config.antenna_power_enabled.into()),
            )?;
            // Zero means unlimited; explicit polling below is the integrity gate.
            check(
                "overrun policy",
                hackrf_set_rx_overrun_limit(native.device, 0),
            )?;
        }
        Ok(native)
    }
}
impl Driver for Native {
    fn start(&mut self, shared: Arc<Shared>) -> RadioResult<()> {
        let mut context = Box::new(shared);
        let context_ptr = (&mut *context as *mut Arc<Shared>).cast();
        self.context = Some(context);
        // SAFETY: boxed context remains stable until close joins callbacks, even
        // when start reports failure after partially installing the callback.
        unsafe {
            check(
                "start RX",
                hackrf_start_rx(self.device, receive, context_ptr),
            )
        }
    }
    fn counters(&mut self) -> RadioResult<(u32, u32)> {
        let mut state = M0State::default();
        // SAFETY: live handle and correctly sized writable repr(C) result.
        unsafe {
            check("M0 state", hackrf_get_m0_state(self.device, &mut state))?;
        }
        if state.active_mode != 2 || state.error != 0 {
            return Err(RadioError::Source(format!(
                "HackRF M0 not receiving or reports error (active_mode={}, error={})",
                state.active_mode, state.error
            )));
        }
        Ok((state.num_shortfalls, state.longest_shortfall))
    }
    fn streaming(&mut self) -> bool {
        // SAFETY: called only while handle remains open on its owning thread.
        unsafe { hackrf_is_streaming(self.device) == 1 }
    }
    fn stop(&mut self) -> RadioResult<()> {
        if self.device.is_null() {
            return Ok(());
        }
        // SAFETY: stop cancels transfers; close also joins the native event
        // thread. Only afterwards may callback storage be freed.
        let (stop, close) = unsafe { (hackrf_stop_rx(self.device), hackrf_close(self.device)) };
        self.device = ptr::null_mut();
        // libhackrf cannot guarantee callback lifetime after pthread_join failure.
        // Terminate instead of permitting freed native/device memory to be used.
        if close == -1001 {
            std::process::abort();
        }
        self.context.take();
        check("close", close)?;
        check("stop RX", stop)
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        let _ = self.stop();
        // SAFETY: serialized lifecycle and no callbacks/handles remain.
        unsafe {
            hackrf_exit();
        }
    }
}
unsafe extern "C" fn receive(transfer: *mut Transfer) -> c_int {
    // SAFETY: libhackrf owns the transfer/buffer until return; start supplies the
    // boxed context and stop/close retains it until all callbacks have joined.
    // Validate native lengths before creating a slice. Every Rust panic is caught.
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(t) = (unsafe { transfer.as_ref() }) else {
            return false;
        };
        if t.rx_ctx.is_null() {
            return false;
        }
        let shared = unsafe { &*t.rx_ctx.cast::<Arc<Shared>>() };
        if t.valid_length < 0 || t.buffer_length < t.valid_length || t.buffer.is_null() {
            let mut s = shared.lock();
            s.stop = true;
            s.fault = Some(RadioError::Source("invalid HackRF transfer buffer".into()));
            Shared::gap(&mut s, GapReason::SourceLoss);
            return false;
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(t.buffer.cast::<i8>(), t.valid_length as usize) };
        shared.receive(bytes)
    }));
    match result {
        Ok(true) => 0,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_hackrf_native_abi_and_null_callback() {
        assert_eq!(std::mem::size_of::<M0State>(), 40);
        assert_eq!(
            std::mem::size_of::<Transfer>(),
            4 * std::mem::size_of::<*mut c_void>() + 8
        );
        // SAFETY: callback explicitly handles a null transfer without dereference.
        assert_eq!(unsafe { receive(ptr::null_mut()) }, 1);
        let mut transfer = Transfer {
            device: ptr::null_mut(),
            buffer: ptr::null_mut(),
            buffer_length: 0,
            valid_length: 0,
            rx_ctx: ptr::null_mut(),
            tx_ctx: ptr::null_mut(),
        };
        // SAFETY: valid transfer storage with deliberately absent context.
        assert_eq!(unsafe { receive(&mut transfer) }, 1);
    }
}
