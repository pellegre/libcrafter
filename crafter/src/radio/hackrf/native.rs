//! Minimal RX/TX ABI reviewed against libhackrf hackrf.h at cc691022.
use super::*;
use std::{
    ffi::{c_char, c_int, c_void, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::Condvar,
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
    fn hackrf_set_txvga_gain(device: *mut c_void, gain: u32) -> c_int;
    fn hackrf_set_amp_enable(device: *mut c_void, enable: u8) -> c_int;
    fn hackrf_set_antenna_enable(device: *mut c_void, enable: u8) -> c_int;
    fn hackrf_set_rx_overrun_limit(device: *mut c_void, limit: u32) -> c_int;
    fn hackrf_start_rx(
        device: *mut c_void,
        callback: unsafe extern "C" fn(*mut Transfer) -> c_int,
        context: *mut c_void,
    ) -> c_int;
    fn hackrf_stop_rx(device: *mut c_void) -> c_int;
    fn hackrf_start_tx(
        device: *mut c_void,
        callback: unsafe extern "C" fn(*mut Transfer) -> c_int,
        context: *mut c_void,
    ) -> c_int;
    fn hackrf_enable_tx_flush(
        device: *mut c_void,
        callback: unsafe extern "C" fn(*mut c_void, c_int),
        context: *mut c_void,
    ) -> c_int;
    fn hackrf_stop_tx(device: *mut c_void) -> c_int;
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

pub(in crate::radio) struct NativeTx {
    device: *mut c_void,
    context: Option<Box<TxContext>>,
    _library: MutexGuard<'static, ()>,
}

struct TxContext {
    shared: Arc<super::super::hackrf_tx::TxShared>,
    flush_result: Mutex<Option<bool>>,
    flush_ready: Condvar,
}
// SAFETY: the handle has exclusive ownership and all methods require `&mut self`;
// callbacks touch only the separately synchronized context.
unsafe impl Send for NativeTx {}

impl NativeTx {
    pub(in crate::radio) fn open(
        config: &super::super::hackrf_tx::HackRfTxConfig,
    ) -> RadioResult<Self> {
        let library = LIBRARY.try_lock().map_err(|_| {
            RadioError::Source("another crafter HackRF operation owns libhackrf".into())
        })?;
        let serial = CString::new(config.serial.clone()).map_err(|_| RadioError::Invalid {
            field: "serial",
            reason: "interior NUL",
        })?;
        // SAFETY: process-wide lock serializes library initialization and handles.
        unsafe {
            check("init", hackrf_init())?;
        }
        let mut native = Self {
            device: ptr::null_mut(),
            context: None,
            _library: library,
        };
        // SAFETY: each call receives the open device and validated scalar settings.
        unsafe {
            check(
                "open",
                hackrf_open_by_serial(serial.as_ptr(), &mut native.device),
            )?;
            check(
                "sample rate",
                hackrf_set_sample_rate(native.device, config.sample_rate_hz as f64),
            )?;
            check(
                "baseband filter",
                hackrf_set_baseband_filter_bandwidth(native.device, config.baseband_filter_hz),
            )?;
            check(
                "frequency",
                hackrf_set_freq(native.device, config.center_frequency_hz),
            )?;
            check(
                "TX VGA gain",
                hackrf_set_txvga_gain(native.device, config.tx_vga_gain_db),
            )?;
            check(
                "RF amplifier",
                hackrf_set_amp_enable(native.device, config.amplifier_enabled.into()),
            )?;
            check(
                "antenna power",
                hackrf_set_antenna_enable(native.device, config.antenna_power_enabled.into()),
            )?;
        }
        Ok(native)
    }

    pub(in crate::radio) fn transmit(
        &mut self,
        shared: Arc<super::super::hackrf_tx::TxShared>,
    ) -> RadioResult<super::super::hackrf_tx::HackRfTxStats> {
        let mut context = Box::new(TxContext {
            shared,
            flush_result: Mutex::new(None),
            flush_ready: Condvar::new(),
        });
        let context_ptr = (&mut *context as *mut TxContext).cast();
        self.context = Some(context);
        // SAFETY: boxed callback context stays pinned until flush and stop have
        // joined callbacks. The flush callback is the libhackrf completion
        // boundary that guarantees the final transfer reached the device.
        unsafe {
            check(
                "enable TX flush",
                hackrf_enable_tx_flush(self.device, flush, context_ptr),
            )?;
            check(
                "start TX",
                hackrf_start_tx(self.device, transmit, context_ptr),
            )?;
        }
        let context = self.context.as_ref().expect("TX context");
        let mut flush_result = context
            .flush_result
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while flush_result.is_none() {
            let remaining = context.shared.remaining();
            if remaining.is_zero() {
                context.shared.fail(RadioError::Source(
                    "HackRF transmission timed out before flush".into(),
                ));
                break;
            }
            let (guard, _) = context
                .flush_ready
                .wait_timeout(flush_result, remaining)
                .unwrap_or_else(|error| error.into_inner());
            flush_result = guard;
        }
        if matches!(*flush_result, Some(false)) {
            context
                .shared
                .fail(RadioError::Source("HackRF TX flush failed".into()));
        }
        drop(flush_result);
        let mut state = M0State::default();
        // SAFETY: stopping joins callbacks and lets firmware roll back a
        // shutdown-only shortfall before the terminal counters are sampled.
        let stop_code = unsafe { hackrf_stop_tx(self.device) };
        // SAFETY: the stopped device remains open and exclusively owned here.
        let counter_result = unsafe { hackrf_get_m0_state(self.device, &mut state) };
        let shared = self.context.take().expect("TX context");
        if counter_result != 0 {
            shared.shared.fail(RadioError::Source(format!(
                "M0 state: libhackrf error {counter_result}"
            )));
        } else if state.error != 0 {
            shared.shared.fail(RadioError::Source(format!(
                "HackRF M0 TX error {}",
                state.error
            )));
        }
        if stop_code != 0 {
            shared.shared.fail(RadioError::Source(format!(
                "stop TX: libhackrf error {stop_code}"
            )));
        }
        shared.shared.finish(
            (
                state.num_shortfalls,
                if state.num_shortfalls == 0 {
                    0
                } else {
                    state.longest_shortfall
                },
            ),
            stop_code == 0,
        )
    }
}

impl Drop for NativeTx {
    fn drop(&mut self) {
        if !self.device.is_null() {
            // SAFETY: this object exclusively owns the device under LIBRARY.
            unsafe {
                let _ = hackrf_stop_tx_for_drop(self.device);
                let close = hackrf_close(self.device);
                if close == -1001 {
                    std::process::abort();
                }
                self.device = ptr::null_mut();
            }
        }
        self.context.take();
        // SAFETY: initialization succeeded before this owner was returned or dropped.
        unsafe {
            let _ = hackrf_exit();
        }
    }
}

unsafe extern "C" fn transmit(transfer: *mut Transfer) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(transfer) = (unsafe { transfer.as_mut() }) else {
            return false;
        };
        if transfer.tx_ctx.is_null() || transfer.buffer.is_null() || transfer.buffer_length <= 0 {
            return false;
        }
        let context = unsafe { &*transfer.tx_ctx.cast::<TxContext>() };
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(transfer.buffer, transfer.buffer_length as usize)
        };
        let Some(valid_length) = context.shared.fill(bytes) else {
            return false;
        };
        transfer.valid_length = valid_length as c_int;
        true
    }));
    match result {
        Ok(true) => 0,
        _ => 1,
    }
}

unsafe extern "C" fn flush(context: *mut c_void, success: c_int) {
    let Some(context) = (unsafe { context.cast::<TxContext>().as_ref() }) else {
        return;
    };
    let mut result = context
        .flush_result
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *result = Some(success != 0);
    context.flush_ready.notify_all();
}

// Kept separate so Drop cannot accidentally call an RX stop symbol.
unsafe fn hackrf_stop_tx_for_drop(device: *mut c_void) -> c_int {
    unsafe { hackrf_stop_tx(device) }
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

    #[test]
    fn radio_hackrf_native_tx_sets_valid_length_and_records_flush() {
        let config = super::super::super::hackrf_tx::HackRfTxConfig {
            serial: "test".into(),
            center_frequency_hz: 2_437_000_000,
            sample_rate_hz: 20_000_000,
            baseband_filter_hz: 17_500_000,
            tx_vga_gain_db: 0,
            amplifier_enabled: false,
            antenna_power_enabled: false,
            max_duration: std::time::Duration::from_secs(1),
            max_supplied_samples: 8,
            repetitions: 1,
            inter_burst_gap_samples: 0,
        };
        let shared = Arc::new(
            super::super::super::hackrf_tx::TxShared::new(
                &[1, 2],
                &config,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .unwrap(),
        );
        let mut context = TxContext {
            shared,
            flush_result: Mutex::new(None),
            flush_ready: Condvar::new(),
        };
        let mut buffer = [0u8; 8];
        let mut transfer = Transfer {
            device: ptr::null_mut(),
            buffer: buffer.as_mut_ptr(),
            buffer_length: buffer.len() as c_int,
            valid_length: 0,
            rx_ctx: ptr::null_mut(),
            tx_ctx: (&mut context as *mut TxContext).cast(),
        };
        // SAFETY: transfer and callback context remain live for the call.
        assert_eq!(unsafe { transmit(&mut transfer) }, 0);
        assert_eq!(transfer.valid_length, transfer.buffer_length);
        assert_eq!(buffer, [1, 2, 0, 0, 0, 0, 0, 0]);
        // SAFETY: callback context remains live for the call.
        unsafe { flush((&mut context as *mut TxContext).cast(), 1) };
        assert_eq!(*context.flush_result.lock().unwrap(), Some(true));
    }
}
