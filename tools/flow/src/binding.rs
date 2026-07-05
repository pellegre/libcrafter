//! Execution binding for a protocol flow.

use crafter::net::SendOptions;

/// Selects where the flow should run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindTarget {
    /// Run from inside a named network namespace.
    Netns(String),
    /// Run directly on a named host interface.
    Interface(String),
}

impl BindTarget {
    /// Name used by the send half for interface-scoped packet planning.
    pub fn send_name(&self) -> &str {
        match self {
            Self::Netns(name) | Self::Interface(name) => name,
        }
    }
}

/// Selects whether a binding only plans traffic or sends it live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindMode {
    /// Compile and plan packets without opening a real socket.
    DryRun,
    /// Open the configured live position and transmit packets.
    Live,
}

/// Selects the packet class expected by the send half.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum BindSendClass {
    /// Send network-layer packets, such as IPv4 or IPv6 datagrams.
    #[default]
    NetworkLayer,
    /// Send link-layer frames, such as Ethernet.
    LinkLayer,
}

/// Describes where and how a flow runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    target: BindTarget,
    mode: BindMode,
    send_class: BindSendClass,
}

impl Binding {
    /// Bind to a named network namespace in dry-run mode.
    pub fn netns(name: impl Into<String>) -> Self {
        Self {
            target: BindTarget::Netns(name.into()),
            mode: BindMode::DryRun,
            send_class: BindSendClass::default(),
        }
    }

    /// Bind to a named interface in dry-run mode.
    pub fn interface(name: impl Into<String>) -> Self {
        Self {
            target: BindTarget::Interface(name.into()),
            mode: BindMode::DryRun,
            send_class: BindSendClass::default(),
        }
    }

    /// Switch this binding to live traffic.
    pub const fn live(mut self) -> Self {
        self.mode = BindMode::Live;
        self
    }

    /// Select link-layer sending for this binding.
    pub const fn link_layer(mut self) -> Self {
        self.send_class = BindSendClass::LinkLayer;
        self
    }

    /// Select network-layer sending for this binding.
    pub const fn network_layer(mut self) -> Self {
        self.send_class = BindSendClass::NetworkLayer;
        self
    }

    /// Selected target.
    pub const fn target(&self) -> &BindTarget {
        &self.target
    }

    /// Selected dry-run/live mode.
    pub const fn mode(&self) -> BindMode {
        self.mode
    }

    /// Selected send class.
    pub const fn send_class(&self) -> BindSendClass {
        self.send_class
    }

    /// Returns true when this binding opts in to live traffic.
    pub const fn is_live(&self) -> bool {
        matches!(self.mode, BindMode::Live)
    }

    /// Returns true when this binding stays offline.
    pub const fn is_dry_run(&self) -> bool {
        matches!(self.mode, BindMode::DryRun)
    }

    /// Build the corresponding `crafter` send options for this binding.
    pub fn send_options(&self) -> SendOptions {
        let options = SendOptions::new().iface(self.target.send_name());
        let options = match self.send_class {
            BindSendClass::NetworkLayer => options.network_layer(),
            BindSendClass::LinkLayer => options.link_layer(),
        };

        match self.mode {
            BindMode::DryRun => options.dry_run(),
            BindMode::Live => options.live(),
        }
    }
}

impl Default for Binding {
    fn default() -> Self {
        Self::netns("flow0")
    }
}

#[cfg(test)]
mod tests {
    use super::{BindMode, BindSendClass, BindTarget, Binding};
    use crafter::net::SendMode;

    #[test]
    fn binding_default_is_netns_dry_run() {
        let binding = Binding::default();

        assert!(binding.is_dry_run());
        assert!(!binding.is_live());
        assert_eq!(binding.mode(), BindMode::DryRun);
        assert_eq!(binding.send_class(), BindSendClass::NetworkLayer);
        assert_eq!(binding.target(), &BindTarget::Netns("flow0".to_string()));
    }

    #[test]
    fn binding_live_switches_mode() {
        let binding = Binding::interface("eth0").live();

        assert!(binding.is_live());
        assert!(!binding.is_dry_run());
        assert_eq!(binding.mode(), BindMode::Live);
    }

    #[test]
    fn binding_send_options_carry_interface_class_and_dry_run() {
        let options = Binding::interface("eth0").link_layer().send_options();

        assert_eq!(options.interface_name(), Some("eth0"));
        assert_eq!(options.send_mode(), SendMode::LinkLayer);
        assert!(options.is_dry_run());
    }

    #[test]
    fn binding_live_network_layer_options_are_live() {
        let options = Binding::interface("eth1")
            .network_layer()
            .live()
            .send_options();

        assert_eq!(options.interface_name(), Some("eth1"));
        assert_eq!(options.send_mode(), SendMode::NetworkLayer);
        assert!(!options.is_dry_run());
    }
}
