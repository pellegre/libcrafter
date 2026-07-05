//! Offline helpers for manual network-namespace flow runs.

use crate::{BindSendClass, Binding, FlowError, Result};

/// Validate a Linux network namespace name used by tracked helpers.
pub fn validate_netns_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(FlowError::Binding(
            "network namespace name must not be empty".to_string(),
        ));
    }

    if name.len() > 64 {
        return Err(FlowError::Binding(
            "network namespace name must be 64 bytes or fewer".to_string(),
        ));
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(FlowError::Binding(
            "network namespace name may contain only ASCII letters, digits, '.', '_', and '-'"
                .to_string(),
        ));
    }

    Ok(())
}

/// Build a dry-run namespace binding with the requested send class.
pub fn binding(name: impl AsRef<str>, send_class: BindSendClass) -> Result<Binding> {
    let name = name.as_ref();
    validate_netns_name(name)?;

    let binding = match send_class {
        BindSendClass::Auto => Binding::netns(name),
        BindSendClass::NetworkLayer => Binding::netns(name).network_layer(),
        BindSendClass::LinkLayer => Binding::netns(name).link_layer(),
    };

    Ok(binding)
}

/// Build a dry-run namespace binding for link-layer packets.
pub fn link_layer(name: impl AsRef<str>) -> Result<Binding> {
    binding(name, BindSendClass::LinkLayer)
}

/// Build a dry-run namespace binding for network-layer packets.
pub fn network_layer(name: impl AsRef<str>) -> Result<Binding> {
    binding(name, BindSendClass::NetworkLayer)
}

#[cfg(test)]
mod tests {
    use super::{binding, link_layer, network_layer, validate_netns_name};
    use crate::{BindSendClass, BindTarget};

    #[test]
    fn netns_name_validation_accepts_safe_names() {
        validate_netns_name("flow-client_1.test").expect("safe name validates");
    }

    #[test]
    fn netns_name_validation_rejects_shell_or_path_names() {
        for name in ["", "flow client", "../flow", "flow/client", "flow$client"] {
            assert!(
                validate_netns_name(name).is_err(),
                "name should be rejected: {name}"
            );
        }
    }

    #[test]
    fn netns_binding_uses_requested_class_and_stays_dry_run() {
        let binding = link_layer("flow-client").expect("binding builds");

        assert_eq!(binding.target(), &BindTarget::Netns("flow-client".to_string()));
        assert_eq!(binding.send_class(), BindSendClass::LinkLayer);
        assert!(binding.is_dry_run());
        assert!(binding.clone().live().is_live());
    }

    #[test]
    fn netns_binding_supports_auto_and_network_layer_classes() {
        assert_eq!(
            binding("flow-auto", BindSendClass::Auto)
                .expect("auto binding builds")
                .send_class(),
            BindSendClass::Auto
        );
        assert_eq!(
            network_layer("flow-network")
                .expect("network binding builds")
                .send_class(),
            BindSendClass::NetworkLayer
        );
    }
}
