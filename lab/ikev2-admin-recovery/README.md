# IKEv2 lab administrative recovery harness

Offline harness for the administrative recovery of a held IKEv2 lab run. It
contains the specification, integration notes, the Python/PowerShell/C# driver
and host scripts, and their inert tests.

## Status

This is a lab snapshot, not production code. It is the first version to
complete a live administrative recovery that reached `SETTLED`: run `613ea8eb`
with candidate package `8f32030a` (`PACKAGE.json` SHA-256
`8f32030ad3f46e101ecfda33a211992bf8c9d48a7f945cd486ee6608c7581fff`).
Nothing here is built, packaged, or shipped with Bimeron Core, and nothing here
should run against a real host without the review gates described in `SPEC.md`
and `INTEGRATION.md`.

## Contents

- `SPEC.md`: specification and acceptance criteria.
- `INTEGRATION.md`: what is implemented, verification limits, and open gates.
- `check_offline.py`: inert acceptance checks. It never runs preparation or
  native admission.
- `runtime/driver/`: recovery driver code and tests.
- `runtime/host/`: one-attempt host integration code and tests (see
  `runtime/host/README.md`).

## Running offline checks

On Windows with Python 3, Windows PowerShell, and PowerShell 7 (`pwsh`)
installed:

```
python check_offline.py
```

The full mode first verifies the sealed `../source` and `../supplement-01`
snapshots from the original lab workspace and also runs
`runtime/driver/test_rpc_regression.py`, which depends on `../source`. Those
snapshots are not part of this repository, so in a Git checkout the checker
runs in partial mode: it skips both steps, runs every other inert check, and
reports `STATUS: partial` (exit code 0) instead of `passed`. A partial run is
never reported as passed. If only one of the two snapshots is present, the
checker fails.

Results are written to `validation/`, which is ignored by Git.

## Lab configuration

The published snapshot is parameterized. Lab-specific values are replaced by
placeholders, and the snapshot differs from the bytes of the lab-run package
only by these substitutions:

| Placeholder | Meaning | Files |
| --- | --- | --- |
| `<LAB_PUBLIC_IP>` | Public IPv4 address of the lab IKEv2 peer | driver and host code, tests, `runtime/host/README.md` |
| `<LAB_STEP9_ABI_ROOT>` | Host directory with the step 9 ABI run evidence | `audit-preparation.py`, `duration-native.ps1` |
| `<LAB_PRIVATE_ROOT>` | Host private lab root with evidence and admission copies | `INTEGRATION.md`, `test_dispose_held_run.py` |
| `<LAB_USER_PROFILE>` | Operator profile directory that parents `admissionRoot` | `SPEC.md` |
| `<LAB_GUEST_NAME>` | Computer name of the lab guest VM | driver and host code, tests, `runtime/host/README.md` |
| `<LAB_GUEST_SID_1001>` | SID of the guest account with RID 1001 | driver and host code, tests, `runtime/host/README.md` |
| `<LAB_GUEST_SID_1002>` | SID of the guest account with RID 1002 | `expected-schema.ps1`, `export-expected.ps1` |
| `<LAB_VM_ID>` | Hyper-V VM ID of the lab guest (lower case) | driver and host code, tests, `runtime/host/README.md` |
| `<LAB_GUEST_MAC>` | Guest network adapter MAC address (`xx:xx:xx:xx:xx:xx`) | `live_prepare.py`, `test_live_config.py`, `runtime/host/README.md` |
| `<LAB_VM_NIC_ID>` | Hyper-V ID of the guest network adapter (GUID after the VM ID, upper case) | `stock_controller.py`, `stock_receipt.py`, `stock-host-operations.ps1` |
| `<LAB_VSWITCH_ID>` | Hyper-V ID of the virtual switch the guest adapter is reconnected to (lower case) | `stock_controller.py`, `stock_receipt.py`, `stock-controller-phases.ps1`, `stock-host-operations.ps1` |

Four further placeholders are derived from the values above, in the spelling
the files use, and are not configured separately:

| Placeholder | Derived value | Files |
| --- | --- | --- |
| `<LAB_GUEST_NAME_LOWER>` | `LAB_GUEST_NAME` in lower case (a negative test case) | `test-session-loading.ps1` |
| `<LAB_VM_ID_UPPER>` | `LAB_VM_ID` in upper case | `stock_controller.py`, `stock_receipt.py`, `stock-host-operations.ps1` |
| `<LAB_VM_ID_PREFIX>` | First eight hex digits of `LAB_VM_ID` (session mutex name) | `INTEGRATION.md`, guest and preparation scripts and tests |
| `<LAB_GUEST_MAC_HEX>` | `LAB_GUEST_MAC` without separators, in upper case | `stock_controller.py`, `stock_receipt.py`, `stock-host-operations.ps1` |

Beyond these placeholders, three test fixtures change (six lines). Two
synthetic test fixtures in `runtime/driver/test_admin_recovery.py` use
neutral paths instead of the operator's profile (the `PYTHON` path with its
three `AppData` volume entries, and `LIVE_DRIVER`); the path-budget fixture keeps the
original length, so the asserted lengths are unchanged. The packet fixture
in `runtime/driver/test_offline_evidence_legacy.py` packs the peer address
with `socket.inet_aton('<LAB_PUBLIC_IP>')` instead of a packed-bytes
literal. The additions are this section, `configure_lab.py`, `test_configure_lab.py`,
`lab-config.example.json`, the `lab-config.json` entry in `.gitignore`, and
the `test_configure_lab.py` step in `check_offline.py`.

`check_offline.py` runs on the placeholder snapshot as is. Driver tests
outside `check_offline.py` that parse the peer address (for example
`test_integration.py` and `test_offline_evidence_legacy.py`) need a rendered
copy. Before any lab use, render a configured copy:

```
copy lab-config.example.json lab-config.json   (then edit the values)
python -I -B configure_lab.py --out <new directory outside this package>
```

`configure_lab.py` reads `--config`, else the `BIMERON_LAB_CONFIG`
environment variable, else `lab-config.json` beside it (ignored by Git). The
config must contain exactly `schema` (`bimeron-lab-config-v3`) and the eleven
configured keys above. `LAB_PUBLIC_IP` must be a canonical IPv4 address; the
paths must be absolute Windows paths without a trailing separator and without
quotes, `$`, or other characters that are unsafe inside the string literals
they replace. `LAB_GUEST_NAME` must be an upper-case computer name of at most
15 characters; the two SIDs must be local account SIDs
(`S-1-5-21-...-1001` and `-1002`) of one machine; `LAB_VM_ID` must be a
lower-case GUID; `LAB_GUEST_MAC` must be a lower-case, colon-separated MAC
address; `LAB_VM_NIC_ID` must be an upper-case GUID and `LAB_VSWITCH_ID` a
lower-case GUID. The tool copies the package into a new directory, substitutes the
placeholders byte for byte, refuses any unconfigured `<LAB_*>` placeholder,
and never touches the lab, the VM, or the network. The example values
(`203.0.113.10` from TEST-NET-3, an `operator` profile, and synthetic guest
identifiers) are inert.
Rendering with the original lab values reproduces the lab-run file bytes,
except for the test fixtures and the additions listed above.

## Byte exactness

`.gitattributes` marks this directory `-text` so checkouts keep the exact
bytes that the scripts parse and hash.
