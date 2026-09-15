//! Minimal RX/TX ABI reviewed against libhackrf hackrf.h at cc691022.
use super::*;
use std::{
    ffi::{c_char, c_int, c_void, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::Condvar,
};
// Initialize/exit and native open/close accounting are serialized, but no
// thread-affine MutexGuard is retained in a movable device owner.
static LIBRARY: Mutex<usize> = Mutex::new(0);
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
    fn hackrf_disable_tx_flush(device: *mut c_void) -> c_int;
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
#[derive(Clone, Copy)]
struct Lifecycle {
    stop_rx: unsafe extern "C" fn(*mut c_void) -> c_int,
    stop_tx: unsafe extern "C" fn(*mut c_void) -> c_int,
    disable_flush: unsafe extern "C" fn(*mut c_void) -> c_int,
    close: unsafe extern "C" fn(*mut c_void) -> c_int,
}
const NATIVE_LIFECYCLE: Lifecycle = Lifecycle {
    stop_rx: hackrf_stop_rx,
    stop_tx: hackrf_stop_tx,
    disable_flush: hackrf_disable_tx_flush,
    close: hackrf_close,
};
pub(in crate::radio) struct Device {
    device: *mut c_void,
    rx_context: Option<Box<Arc<Shared>>>,
    tx_context: Option<Box<TxContext>>,
    lifecycle: Lifecycle,
    registered: bool,
}
// SAFETY: the pointer has no thread affinity. Every native operation is
// serialized by SharedDevice's mutex. Callbacks use only separately owned,
// synchronized contexts, retained until transfers are quiescent.
unsafe impl Send for Device {}
pub(in crate::radio) type SharedDevice = Arc<Mutex<Device>>;
impl Device {
    pub(in crate::radio) fn open(serial: &str) -> RadioResult<SharedDevice> {
        let serial = CString::new(serial).map_err(|_| RadioError::Invalid {
            field: "serial",
            reason: "interior NUL",
        })?;
        let mut users = LIBRARY.lock().unwrap_or_else(|e| e.into_inner());
        let mut device = ptr::null_mut();
        // SAFETY: serialized process lifecycle, valid serial and output pointer.
        unsafe {
            if *users == 0 {
                check("init", hackrf_init())?;
            }
            if let Err(error) = check("open", hackrf_open_by_serial(serial.as_ptr(), &mut device)) {
                if *users == 0 {
                    let _ = hackrf_exit();
                }
                return Err(error);
            }
        }
        *users += 1;
        Ok(Arc::new(Mutex::new(Self {
            device,
            rx_context: None,
            tx_context: None,
            lifecycle: NATIVE_LIFECYCLE,
            registered: true,
        })))
    }
    fn handle(&self) -> RadioResult<*mut c_void> {
        if self.device.is_null() {
            Err(RadioError::Source(
                "HackRF device was closed after a native failure".into(),
            ))
        } else {
            Ok(self.device)
        }
    }
    fn close(&mut self) -> RadioResult<()> {
        if self.device.is_null() {
            return Ok(());
        }
        let mut users = self
            .registered
            .then(|| LIBRARY.lock().unwrap_or_else(|e| e.into_inner()));
        // SAFETY: contexts are still alive; close cancels transfers and joins
        // the event thread before any callback storage is released.
        let code = unsafe { (self.lifecycle.close)(self.device) };
        self.device = ptr::null_mut();
        if code == -1001 {
            std::process::abort();
        }
        self.rx_context.take();
        self.tx_context.take();
        if let Some(users) = &mut users {
            **users -= 1;
            if **users == 0 {
                // SAFETY: the last initialized device has closed under LIBRARY.
                unsafe {
                    let _ = hackrf_exit();
                }
            }
        }
        check("close", code)
    }
    fn stop_rx(&mut self) -> RadioResult<()> {
        if self.rx_context.is_none() {
            return Ok(());
        }
        // SAFETY: called with serialized live device ownership.
        let code = unsafe { (self.lifecycle.stop_rx)(self.handle()?) };
        if code != 0 {
            let closed = self.close();
            return Err(RadioError::Source(format!(
                "stop RX: libhackrf error {code}; close: {closed:?}"
            )));
        }
        self.rx_context.take();
        Ok(())
    }
    fn stop_tx(&mut self) -> RadioResult<()> {
        if self.tx_context.is_none() {
            return Ok(());
        }
        // SAFETY: cancellation waits for completion callbacks before returning
        // success. On failure close retains the contexts through thread join.
        let code = unsafe { (self.lifecycle.stop_tx)(self.handle()?) };
        if code != 0 {
            let closed = self.close();
            return Err(RadioError::Source(format!(
                "stop TX: libhackrf error {code}; close: {closed:?}"
            )));
        }
        // SAFETY: no transfer can still invoke the registered flush callback.
        let disabled = unsafe { (self.lifecycle.disable_flush)(self.handle()?) };
        if disabled != 0 {
            let closed = self.close();
            return Err(RadioError::Source(format!(
                "disable TX flush: libhackrf error {disabled}; close: {closed:?}"
            )));
        }
        self.tx_context.take();
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(super) struct Native {
    device: SharedDevice,
    config: HackRfConfig,
}
impl Native {
    pub(super) fn open(config: HackRfConfig) -> RadioResult<Self> {
        let device = Device::open(&config.serial)?;
        Ok(Self::shared(config, device))
    }
    pub(in crate::radio) fn shared(config: HackRfConfig, device: SharedDevice) -> Self {
        Self { device, config }
    }
}
impl Driver for Native {
    fn start(&mut self, shared: Arc<Shared>) -> RadioResult<()> {
        let mut state = self.device.lock().unwrap_or_else(|e| e.into_inner());
        if state.rx_context.is_some() || state.tx_context.is_some() {
            return Err(RadioError::Source(
                "HackRF direction has not stopped".into(),
            ));
        }
        let device = state.handle()?;
        let config = &self.config;
        // SAFETY: exclusive live handle; rate precedes explicit filter.
        unsafe {
            check(
                "sample rate",
                hackrf_set_sample_rate(device, config.rx.sample_rate_hz as f64),
            )?;
            check(
                "baseband filter",
                hackrf_set_baseband_filter_bandwidth(device, config.baseband_filter_hz),
            )?;
            check(
                "frequency",
                hackrf_set_freq(device, config.rx.center_frequency_hz),
            )?;
            check("LNA gain", hackrf_set_lna_gain(device, config.lna_gain_db))?;
            check("VGA gain", hackrf_set_vga_gain(device, config.vga_gain_db))?;
            check(
                "RF amplifier",
                hackrf_set_amp_enable(device, config.amplifier_enabled.into()),
            )?;
            check(
                "antenna power",
                hackrf_set_antenna_enable(device, config.antenna_power_enabled.into()),
            )?;
            // Zero means unlimited; explicit polling below is the integrity gate.
            check("overrun policy", hackrf_set_rx_overrun_limit(device, 0))?;
        }
        let mut context = Box::new(shared);
        let context_ptr = (&mut *context as *mut Arc<Shared>).cast();
        state.rx_context = Some(context);
        // SAFETY: boxed context remains stable until close joins callbacks, even
        // when start reports failure after partially installing the callback.
        unsafe { check("start RX", hackrf_start_rx(device, receive, context_ptr)) }
    }
    fn counters(&mut self) -> RadioResult<(u32, u32)> {
        let device = self.device.lock().unwrap_or_else(|e| e.into_inner());
        let mut state = M0State::default();
        // SAFETY: live handle and correctly sized writable repr(C) result.
        unsafe {
            check(
                "M0 state",
                hackrf_get_m0_state(device.handle()?, &mut state),
            )?;
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
        let device = self.device.lock().unwrap_or_else(|e| e.into_inner());
        device
            .handle()
            .is_ok_and(|handle| unsafe { hackrf_is_streaming(handle) == 1 })
    }
    fn stop(&mut self) -> RadioResult<()> {
        self.device
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop_rx()
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        let _ = self.stop();
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
    device: SharedDevice,
    config: super::super::hackrf_tx::HackRfTxConfig,
}

struct TxContext {
    shared: Arc<super::super::hackrf_tx::TxShared>,
    flush_result: Mutex<Option<bool>>,
    flush_ready: Condvar,
}
impl NativeTx {
    pub(in crate::radio) fn open(
        config: &super::super::hackrf_tx::HackRfTxConfig,
    ) -> RadioResult<Self> {
        Ok(Self::shared(config.clone(), Device::open(&config.serial)?))
    }
    pub(in crate::radio) fn shared(
        config: super::super::hackrf_tx::HackRfTxConfig,
        device: SharedDevice,
    ) -> Self {
        Self { device, config }
    }

    pub(in crate::radio) fn transmit(
        &mut self,
        shared: Arc<super::super::hackrf_tx::TxShared>,
    ) -> RadioResult<super::super::hackrf_tx::HackRfTxStats> {
        let mut native = self.device.lock().unwrap_or_else(|e| e.into_inner());
        if native.rx_context.is_some() || native.tx_context.is_some() {
            return Err(RadioError::Source(
                "HackRF direction has not stopped".into(),
            ));
        }
        let device = native.handle()?;
        let config = &self.config;
        // SAFETY: each call receives the exclusively held live device.
        unsafe {
            check(
                "sample rate",
                hackrf_set_sample_rate(device, config.sample_rate_hz as f64),
            )?;
            check(
                "baseband filter",
                hackrf_set_baseband_filter_bandwidth(device, config.baseband_filter_hz),
            )?;
            check(
                "frequency",
                hackrf_set_freq(device, config.center_frequency_hz),
            )?;
            check(
                "TX VGA gain",
                hackrf_set_txvga_gain(device, config.tx_vga_gain_db),
            )?;
            check(
                "RF amplifier",
                hackrf_set_amp_enable(device, config.amplifier_enabled.into()),
            )?;
            check(
                "antenna power",
                hackrf_set_antenna_enable(device, config.antenna_power_enabled.into()),
            )?;
        }
        let mut context = Box::new(TxContext {
            shared: Arc::clone(&shared),
            flush_result: Mutex::new(None),
            flush_ready: Condvar::new(),
        });
        let context_ptr = (&mut *context as *mut TxContext).cast();
        native.tx_context = Some(context);
        // SAFETY: boxed callback context stays pinned until flush and stop have
        // joined callbacks. The flush callback is the libhackrf completion
        // boundary that guarantees the final transfer reached the device.
        let started = unsafe {
            check(
                "enable TX flush",
                hackrf_enable_tx_flush(device, flush, context_ptr),
            )
            .and_then(|()| check("start TX", hackrf_start_tx(device, transmit, context_ptr)))
        };
        if let Err(error) = started {
            let stopped = native.stop_tx();
            shared.fail(RadioError::Source(format!("{error}; cleanup: {stopped:?}")));
            return shared.finish((0, 0), stopped.is_ok());
        }
        let context = native.tx_context.as_ref().expect("TX context");
        let mut flush_result = context
            .flush_result
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while flush_result.is_none() {
            if context.shared.cancel_requested() {
                context
                    .shared
                    .fail(RadioError::Source("HackRF transmission cancelled".into()));
                break;
            }
            let remaining = context.shared.remaining();
            if remaining.is_zero() {
                context.shared.fail(RadioError::Source(
                    "HackRF transmission timed out before flush".into(),
                ));
                break;
            }
            let (guard, _) = context
                .flush_ready
                .wait_timeout(flush_result, remaining.min(Duration::from_millis(20)))
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
        let stopped = native.stop_tx();
        if let Err(error) = &stopped {
            shared.fail(error.clone());
        } else {
            // SAFETY: the stopped device remains open and exclusively owned here.
            let counter_result = unsafe { hackrf_get_m0_state(device, &mut state) };
            if counter_result != 0 {
                shared.fail(RadioError::Source(format!(
                    "M0 state: libhackrf error {counter_result}"
                )));
            } else if state.error != 0 {
                shared.fail(RadioError::Source(format!(
                    "HackRF M0 TX error {}",
                    state.error
                )));
            }
        }
        shared.finish(
            (
                state.num_shortfalls,
                if state.num_shortfalls == 0 {
                    0
                } else {
                    state.longest_shortfall
                },
            ),
            stopped.is_ok(),
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Weak,
    };

    struct MockHandle {
        context: Weak<super::super::super::hackrf_tx::TxShared>,
        context_alive_on_close: Arc<AtomicBool>,
        closes: Arc<AtomicUsize>,
        stop_result: c_int,
        disable_result: c_int,
    }
    unsafe extern "C" fn mock_stop(handle: *mut c_void) -> c_int {
        // SAFETY: mock_device supplies a live MockHandle until mock_close.
        unsafe { &*handle.cast::<MockHandle>() }.stop_result
    }
    unsafe extern "C" fn mock_disable(handle: *mut c_void) -> c_int {
        // SAFETY: mock_device supplies a live MockHandle until mock_close.
        unsafe { &*handle.cast::<MockHandle>() }.disable_result
    }
    unsafe extern "C" fn mock_close(handle: *mut c_void) -> c_int {
        // SAFETY: Device closes its sole boxed MockHandle exactly once.
        let handle = unsafe { Box::from_raw(handle.cast::<MockHandle>()) };
        handle
            .context_alive_on_close
            .store(handle.context.upgrade().is_some(), Ordering::Release);
        handle.closes.fetch_add(1, Ordering::AcqRel);
        0
    }
    fn mock_device(
        stop_result: c_int,
        disable_result: c_int,
    ) -> (
        Device,
        Weak<super::super::super::hackrf_tx::TxShared>,
        Arc<AtomicBool>,
        Arc<AtomicUsize>,
    ) {
        let config = super::super::super::hackrf_tx::HackRfTxConfig {
            serial: "synthetic".into(),
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
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap(),
        );
        let weak = Arc::downgrade(&shared);
        let alive = Arc::new(AtomicBool::new(false));
        let closes = Arc::new(AtomicUsize::new(0));
        let handle = Box::new(MockHandle {
            context: weak.clone(),
            context_alive_on_close: Arc::clone(&alive),
            closes: Arc::clone(&closes),
            stop_result,
            disable_result,
        });
        (
            Device {
                device: Box::into_raw(handle).cast(),
                rx_context: None,
                tx_context: Some(Box::new(TxContext {
                    shared,
                    flush_result: Mutex::new(None),
                    flush_ready: Condvar::new(),
                })),
                lifecycle: Lifecycle {
                    stop_rx: mock_stop,
                    stop_tx: mock_stop,
                    disable_flush: mock_disable,
                    close: mock_close,
                },
                registered: false,
            },
            weak,
            alive,
            closes,
        )
    }

    #[test]
    fn stop_failure_keeps_callback_context_alive_until_close() {
        for (stop, disable) in [(-99, 0), (0, -98)] {
            let (mut device, context, alive, closes) = mock_device(stop, disable);
            assert!(device.stop_tx().is_err());
            assert!(alive.load(Ordering::Acquire));
            assert!(context.upgrade().is_none());
            assert!(device.handle().is_err());
            drop(device);
            assert_eq!(closes.load(Ordering::Acquire), 1);
        }
    }

    #[test]
    fn successful_stop_releases_context_but_retains_device() {
        let (mut device, context, alive, closes) = mock_device(0, 0);
        device.stop_tx().unwrap();
        assert!(context.upgrade().is_none());
        assert!(device.handle().is_ok());
        assert_eq!(closes.load(Ordering::Acquire), 0);
        drop(device);
        assert!(!alive.load(Ordering::Acquire));
        assert_eq!(closes.load(Ordering::Acquire), 1);
    }

    #[test]
    fn native_owner_can_move_between_threads_without_a_thread_bound_guard() {
        fn assert_send<T: Send>() {}
        assert_send::<NativeTx>();
        assert_send::<SharedDevice>();
        let (device, _, alive, closes) = mock_device(0, 0);
        std::thread::spawn(move || drop(device)).join().unwrap();
        assert!(alive.load(Ordering::Acquire));
        assert_eq!(closes.load(Ordering::Acquire), 1);
    }
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
