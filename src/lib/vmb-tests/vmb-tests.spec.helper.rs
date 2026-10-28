//! The virtual machines used by the VMB test helpers.
#![allow(dead_code)]

use libauth::vm::{
    create_virtual_machine_bch_2023, create_virtual_machine_bch_2025, create_virtual_machine_bch_2026,
    create_virtual_machine_bch_spec, AuthenticationVirtualMachineBch,
};

/// The name of a VM for which VMB tests are generated (e.g.
/// `bch_2023_standard`).
pub type VmName = &'static str;

/// A virtual machine tested by the VMB tests.
pub type TestedVM = AuthenticationVirtualMachineBch;

#[allow(non_upper_case_globals)]
pub const baselineBenchmarkId: &str = "trxhzt";

fn base_vms() -> Vec<(VmName, TestedVM)> {
    vec![
        ("bch_2023_nonstandard", create_virtual_machine_bch_2023(Some(false))),
        ("bch_2023_standard", create_virtual_machine_bch_2023(Some(true))),
        ("bch_2025_nonstandard", create_virtual_machine_bch_2025(Some(false))),
        ("bch_2025_standard", create_virtual_machine_bch_2025(Some(true))),
        ("bch_2026_nonstandard", create_virtual_machine_bch_2026(Some(false))),
        ("bch_2026_standard", create_virtual_machine_bch_2026(Some(true))),
        ("bch_spec_nonstandard", create_virtual_machine_bch_spec(Some(false))),
        ("bch_spec_standard", create_virtual_machine_bch_spec(Some(true))),
    ]
}

/// The VMs by VMB test set name (libauth's `vms` object).
pub fn vms() -> Vec<(VmName, TestedVM)> {
    let base_vms = base_vms();
    let base = |name: &str| {
        base_vms
            .iter()
            .find(|(vm_name, _)| *vm_name == name)
            .map(|(_, vm)| vm.clone())
            .expect("a base VM")
    };
    let aliases = vec![
        ("bch_chip_bigint_nonstandard", base("bch_2025_nonstandard")),
        ("bch_chip_bigint_standard", base("bch_2025_standard")),
        ("bch_chip_bitwise_nonstandard", base("bch_2026_nonstandard")),
        ("bch_chip_bitwise_standard", base("bch_2026_standard")),
        ("bch_chip_eval_nonstandard", base("bch_spec_nonstandard")),
        ("bch_chip_eval_standard", base("bch_spec_standard")),
        ("bch_chip_functions_nonstandard", base("bch_2026_nonstandard")),
        ("bch_chip_functions_standard", base("bch_2026_standard")),
        ("bch_chip_limits_nonstandard", base("bch_2025_nonstandard")),
        ("bch_chip_limits_standard", base("bch_2025_standard")),
        ("bch_chip_loops_nonstandard", base("bch_2026_nonstandard")),
        ("bch_chip_loops_standard", base("bch_2026_standard")),
        ("bch_chip_p2s_nonstandard", base("bch_2026_nonstandard")),
        ("bch_chip_p2s_standard", base("bch_2026_standard")),
        ("bch_chip_pow_nonstandard", base("bch_spec_nonstandard")),
        ("bch_chip_pow_standard", base("bch_spec_standard")),
    ];
    base_vms.into_iter().chain(aliases).collect()
}

/// Test if `vm_id` is the name of a VM in {@link vms}.
pub fn is_vm(vm_id: &str) -> bool {
    vms().iter().any(|(name, _)| *name == vm_id)
}
