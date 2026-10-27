//! VHT20 SU example matrix; device preparation belongs to the caller.
use super::{Case, CasePhy};
use crafter::prelude::*;
use serde_json::{json, Value};

pub(super) fn cases(matrix: bool) -> Vec<Case> {
    let mut cases = Vec::new();
    for coding in [VhtCoding::Bcc, VhtCoding::Ldpc] {
        for guard_interval in [VhtGuardInterval::Long, VhtGuardInterval::Short] {
            for mcs in VhtMcs::ALL {
                let coding_label = if coding == VhtCoding::Bcc {
                    "bcc"
                } else {
                    "ldpc"
                };
                let guard = if guard_interval == VhtGuardInterval::Long {
                    800
                } else {
                    400
                };
                cases.push(Case {
                    id: format!("vht20-su-{coding_label}-mcs{}-gi{guard}", mcs.index()),
                    phy: CasePhy::Vht20 {
                        mcs,
                        coding,
                        guard_interval,
                    },
                });
                if !matrix {
                    return cases;
                }
            }
        }
    }
    cases
}
pub(super) fn metadata(mcs: VhtMcs, coding: VhtCoding, guard: VhtGuardInterval) -> Value {
    json!({"phy":"vht20", "mcs":mcs.index(), "bandwidth_mhz":20, "space_time_streams":1,
        "rate_bps":mcs.rate_bps(guard), "preamble":"su",
        "coding":if coding == VhtCoding::Bcc {"bcc"} else {"ldpc"},
        "guard_interval_ns":if guard == VhtGuardInterval::Long {800} else {400}})
}
