//! DNS-SD name helpers built on byte-preserving DNS names.

use crate::error::{CrafterError, Result};

use super::name::DnsName;

const DNS_SD_TCP_LABEL: &str = "tcp";
const DNS_SD_UDP_LABEL: &str = "udp";
const DNS_SD_SUB_LABEL: &[u8] = b"_sub";
const DNS_SD_SERVICE_ENUMERATION_LABELS: [&[u8]; 3] = [b"_services", b"_dns-sd", b"_udp"];

/// Build a DNS-SD service browse name such as `_http._tcp.local.`.
pub fn dns_sd_service_name(
    service: &str,
    protocol: &str,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    let service = dns_sd_prefixed_presentation_label("dns_sd.service", service)?;
    let protocol = dns_sd_prefixed_presentation_label("dns_sd.protocol", protocol)?;
    dns_sd_service_name_from_label_bytes(service, protocol, domain)
}

/// Build a DNS-SD TCP service browse name such as `_http._tcp.local.`.
pub fn dns_sd_tcp_service_name(service: &str, domain: impl Into<DnsName>) -> Result<DnsName> {
    dns_sd_service_name(service, DNS_SD_TCP_LABEL, domain)
}

/// Build a DNS-SD UDP service browse name such as `_ipp._udp.local.`.
pub fn dns_sd_udp_service_name(service: &str, domain: impl Into<DnsName>) -> Result<DnsName> {
    dns_sd_service_name(service, DNS_SD_UDP_LABEL, domain)
}

/// Build a DNS-SD service browse name from raw service and protocol label bytes.
pub fn dns_sd_service_name_from_labels(
    service: impl AsRef<[u8]>,
    protocol: impl AsRef<[u8]>,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    dns_sd_service_name_from_label_bytes(
        dns_sd_prefixed_label_bytes(service),
        dns_sd_prefixed_label_bytes(protocol),
        domain,
    )
}

/// Build a DNS-SD service instance resolve name such as
/// `Printer._http._tcp.local.`.
pub fn dns_sd_instance_name(
    instance: &str,
    service: &str,
    protocol: &str,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    let instance = single_presentation_label("dns_sd.instance", instance)?;
    let service = dns_sd_prefixed_presentation_label("dns_sd.service", service)?;
    let protocol = dns_sd_prefixed_presentation_label("dns_sd.protocol", protocol)?;
    dns_sd_instance_name_from_label_bytes(instance, service, protocol, domain)
}

/// Build a DNS-SD TCP service instance resolve name.
pub fn dns_sd_tcp_instance_name(
    instance: &str,
    service: &str,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    dns_sd_instance_name(instance, service, DNS_SD_TCP_LABEL, domain)
}

/// Build a DNS-SD UDP service instance resolve name.
pub fn dns_sd_udp_instance_name(
    instance: &str,
    service: &str,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    dns_sd_instance_name(instance, service, DNS_SD_UDP_LABEL, domain)
}

/// Build a DNS-SD service instance resolve name from raw label bytes.
pub fn dns_sd_instance_name_from_labels(
    instance: impl AsRef<[u8]>,
    service: impl AsRef<[u8]>,
    protocol: impl AsRef<[u8]>,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    dns_sd_instance_name_from_label_bytes(
        instance.as_ref().to_vec(),
        dns_sd_prefixed_label_bytes(service),
        dns_sd_prefixed_label_bytes(protocol),
        domain,
    )
}

/// Build a DNS-SD subtype browse name such as
/// `_printer._sub._http._tcp.local.`.
pub fn dns_sd_subtype_name(
    subtype: &str,
    service: &str,
    protocol: &str,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    let subtype = dns_sd_prefixed_presentation_label("dns_sd.subtype", subtype)?;
    let service = dns_sd_prefixed_presentation_label("dns_sd.service", service)?;
    let protocol = dns_sd_prefixed_presentation_label("dns_sd.protocol", protocol)?;
    dns_sd_subtype_name_from_label_bytes(subtype, service, protocol, domain)
}

/// Build a DNS-SD subtype browse name from raw label bytes.
pub fn dns_sd_subtype_name_from_labels(
    subtype: impl AsRef<[u8]>,
    service: impl AsRef<[u8]>,
    protocol: impl AsRef<[u8]>,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    dns_sd_subtype_name_from_label_bytes(
        dns_sd_prefixed_label_bytes(subtype),
        dns_sd_prefixed_label_bytes(service),
        dns_sd_prefixed_label_bytes(protocol),
        domain,
    )
}

/// Build the DNS-SD service type enumeration name for a domain.
pub fn dns_sd_service_enumeration_name(domain: impl Into<DnsName>) -> Result<DnsName> {
    compose_dns_sd_name(
        DNS_SD_SERVICE_ENUMERATION_LABELS
            .iter()
            .map(|label| label.to_vec())
            .collect(),
        domain,
    )
}

fn dns_sd_service_name_from_label_bytes(
    service: Vec<u8>,
    protocol: Vec<u8>,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    compose_dns_sd_name(vec![service, protocol], domain)
}

fn dns_sd_instance_name_from_label_bytes(
    instance: Vec<u8>,
    service: Vec<u8>,
    protocol: Vec<u8>,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    compose_dns_sd_name(vec![instance, service, protocol], domain)
}

fn dns_sd_subtype_name_from_label_bytes(
    subtype: Vec<u8>,
    service: Vec<u8>,
    protocol: Vec<u8>,
    domain: impl Into<DnsName>,
) -> Result<DnsName> {
    compose_dns_sd_name(
        vec![subtype, DNS_SD_SUB_LABEL.to_vec(), service, protocol],
        domain,
    )
}

fn compose_dns_sd_name(mut labels: Vec<Vec<u8>>, domain: impl Into<DnsName>) -> Result<DnsName> {
    let domain = domain.into();
    labels.extend(domain.labels().iter().cloned());
    DnsName::from_labels(labels)
}

fn dns_sd_prefixed_presentation_label(field: &'static str, label: &str) -> Result<Vec<u8>> {
    Ok(dns_sd_prefixed_label_bytes(single_presentation_label(
        field, label,
    )?))
}

fn single_presentation_label(field: &'static str, label: &str) -> Result<Vec<u8>> {
    let name = DnsName::parse(label)?;
    match name.labels() {
        [label] => Ok(label.clone()),
        _ => Err(CrafterError::invalid_field_value(
            field,
            "DNS-SD component must be one label",
        )),
    }
}

fn dns_sd_prefixed_label_bytes(label: impl AsRef<[u8]>) -> Vec<u8> {
    let label = label.as_ref();
    if label.starts_with(b"_") {
        return label.to_vec();
    }

    let mut prefixed = Vec::with_capacity(label.len() + 1);
    prefixed.push(b'_');
    prefixed.extend_from_slice(label);
    prefixed
}

#[cfg(test)]
mod dns_sd_name_helpers_tests {
    use super::*;
    use crate::protocols::dns::{DNS_SD_DEFAULT_DOMAIN, DNS_SD_SERVICE_ENUMERATION_NAME};

    #[test]
    fn dns_sd_name_helpers_build_service_browse_names() {
        let tcp = dns_sd_tcp_service_name("http", DNS_SD_DEFAULT_DOMAIN).unwrap();
        assert_eq!(tcp.presentation(), "_http._tcp.local.");
        assert_eq!(
            tcp.labels(),
            &[b"_http".to_vec(), b"_tcp".to_vec(), b"local".to_vec()]
        );

        let explicit =
            dns_sd_service_name("_http", "_tcp", DnsName::parse("local.").unwrap()).unwrap();
        assert_eq!(explicit, tcp);

        let udp = dns_sd_udp_service_name("ipp", DNS_SD_DEFAULT_DOMAIN).unwrap();
        assert_eq!(udp.presentation(), "_ipp._udp.local.");
    }

    #[test]
    fn dns_sd_name_helpers_build_service_enumeration_name() {
        let name = dns_sd_service_enumeration_name(DNS_SD_DEFAULT_DOMAIN).unwrap();
        assert_eq!(name.presentation(), DNS_SD_SERVICE_ENUMERATION_NAME);
        assert_eq!(
            name.labels(),
            &[
                b"_services".to_vec(),
                b"_dns-sd".to_vec(),
                b"_udp".to_vec(),
                b"local".to_vec()
            ]
        );
    }

    #[test]
    fn dns_sd_name_helpers_build_subtype_browse_names() {
        let name = dns_sd_subtype_name("printer", "http", "tcp", DNS_SD_DEFAULT_DOMAIN).unwrap();
        assert_eq!(name.presentation(), "_printer._sub._http._tcp.local.");
        assert_eq!(
            name.labels(),
            &[
                b"_printer".to_vec(),
                b"_sub".to_vec(),
                b"_http".to_vec(),
                b"_tcp".to_vec(),
                b"local".to_vec()
            ]
        );
    }

    #[test]
    fn dns_sd_name_helpers_preserve_escaped_instance_labels() {
        let name =
            dns_sd_tcp_instance_name("Kitchen\\.Display", "http", DNS_SD_DEFAULT_DOMAIN).unwrap();

        assert_eq!(name.presentation(), "Kitchen\\046Display._http._tcp.local.");
        assert_eq!(
            name.labels(),
            &[
                b"Kitchen.Display".to_vec(),
                b"_http".to_vec(),
                b"_tcp".to_vec(),
                b"local".to_vec()
            ]
        );
    }

    #[test]
    fn dns_sd_name_helpers_preserve_non_text_label_bytes() {
        let name = dns_sd_instance_name_from_labels(
            [0x00u8, 0xff],
            b"http",
            b"tcp",
            DNS_SD_DEFAULT_DOMAIN,
        )
        .unwrap();

        assert_eq!(name.presentation(), "\\000\\255._http._tcp.local.");
        assert_eq!(
            name.labels(),
            &[
                vec![0x00, 0xff],
                b"_http".to_vec(),
                b"_tcp".to_vec(),
                b"local".to_vec()
            ]
        );
        assert!(!name.is_text());
    }

    #[test]
    fn dns_sd_name_helpers_raw_label_variants_preserve_case_and_utf8_bytes() {
        let service =
            dns_sd_service_name_from_labels(b"AirPrint", b"TCP", DNS_SD_DEFAULT_DOMAIN).unwrap();
        assert_eq!(service.presentation(), "_AirPrint._TCP.local.");
        assert_eq!(
            service.labels(),
            &[b"_AirPrint".to_vec(), b"_TCP".to_vec(), b"local".to_vec()]
        );

        let instance = dns_sd_instance_name_from_labels(
            b"Caf\xc3\xa9 Printer",
            b"_ipp",
            b"_tcp",
            DNS_SD_DEFAULT_DOMAIN,
        )
        .unwrap();
        assert_eq!(
            instance.presentation(),
            "Caf\\195\\169\\032Printer._ipp._tcp.local."
        );
        assert_eq!(instance.labels()[0], b"Caf\xc3\xa9 Printer".to_vec());
        assert_eq!(instance.labels()[1], b"_ipp".to_vec());
        assert_eq!(instance.labels()[2], b"_tcp".to_vec());

        let udp_instance =
            dns_sd_udp_instance_name("Office Printer", "_scanner", DNS_SD_DEFAULT_DOMAIN).unwrap();
        assert_eq!(
            udp_instance.presentation(),
            "Office\\032Printer._scanner._udp.local."
        );

        let subtype =
            dns_sd_subtype_name_from_labels(b"Color", b"_ipp", b"_tcp", DNS_SD_DEFAULT_DOMAIN)
                .unwrap();
        assert_eq!(subtype.presentation(), "_Color._sub._ipp._tcp.local.");
        assert_eq!(
            subtype.labels(),
            &[
                b"_Color".to_vec(),
                b"_sub".to_vec(),
                b"_ipp".to_vec(),
                b"_tcp".to_vec(),
                b"local".to_vec()
            ]
        );
    }

    #[test]
    fn dns_sd_name_helpers_return_dns_name_length_errors() {
        let max_service = "a".repeat(63);
        assert!(dns_sd_tcp_service_name(&max_service, DNS_SD_DEFAULT_DOMAIN).is_err());

        let long_domain = DnsName::from_labels([
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 58],
        ])
        .unwrap();
        assert!(dns_sd_tcp_service_name("h", long_domain).is_err());
    }
}
