//! SNMP registry metadata scaffold.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; this step does not register
//! UDP dispatch or expose payload detection.

#![cfg_attr(not(test), allow(dead_code))]

use super::ber;

pub(super) fn application_tag_name(tag_number: u8) -> Option<&'static str> {
    match tag_number {
        ber::SNMP_APPLICATION_TAG_IP_ADDRESS => Some("ip-address"),
        ber::SNMP_APPLICATION_TAG_COUNTER32 => Some("counter32"),
        ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32 => Some("gauge32-or-unsigned32"),
        ber::SNMP_APPLICATION_TAG_TIME_TICKS => Some("time-ticks"),
        ber::SNMP_APPLICATION_TAG_OPAQUE => Some("opaque"),
        ber::SNMP_APPLICATION_TAG_COUNTER64 => Some("counter64"),
        _ => None,
    }
}

pub(super) fn application_tag_label(tag_number: u8, constructed: bool) -> String {
    if !constructed {
        if let Some(name) = application_tag_name(tag_number) {
            return name.to_string();
        }
    }

    if constructed {
        format!("constructed-application-{tag_number}")
    } else {
        format!("application-{tag_number}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_application_values_registry_labels_source_backed_tags_and_unknowns() {
        let cases = [
            (ber::SNMP_APPLICATION_TAG_IP_ADDRESS, "ip-address"),
            (ber::SNMP_APPLICATION_TAG_COUNTER32, "counter32"),
            (
                ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32,
                "gauge32-or-unsigned32",
            ),
            (ber::SNMP_APPLICATION_TAG_TIME_TICKS, "time-ticks"),
            (ber::SNMP_APPLICATION_TAG_OPAQUE, "opaque"),
            (ber::SNMP_APPLICATION_TAG_COUNTER64, "counter64"),
        ];

        for (tag, label) in cases {
            assert_eq!(application_tag_name(tag), Some(label));
            assert_eq!(application_tag_label(tag, false), label);
        }

        assert_eq!(application_tag_name(5), None);
        assert_eq!(application_tag_label(5, false), "application-5");
        assert_eq!(application_tag_label(5, true), "constructed-application-5");
        assert_eq!(
            application_tag_label(ber::SNMP_APPLICATION_TAG_IP_ADDRESS, true),
            "constructed-application-0"
        );
    }
}
