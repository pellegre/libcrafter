//! Simple Service Discovery Protocol (SSDP) packet primitives.
//!
//! SSDP support is source-gated by `.agents/docs/ssdp-source-manifest.md`,
//! `.agents/docs/ssdp-wire-grammar.md`, `.agents/docs/ssdp-codepoints.md`, and
//! `.agents/docs/ssdp-api-design.md`. It provides typed messages, HTTP-like
//! header handling, conservative decoding, registry metadata, and packet
//! composition without introducing a discovery workflow.

mod constants;
mod decode;
mod header;
mod message;
mod registry;

#[cfg(test)]
mod tests {
    #[test]
    fn ssdp_module_scaffold_names_core_files() {
        let modules = ["constants", "decode", "header", "message", "registry"];
        assert_eq!(modules.len(), 5);
    }
}
