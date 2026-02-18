"""Generate sample analysis data for dashboard development."""

import json
import os
from pathlib import Path


SAMPLE_ANALYSIS = {
    "_created_at": "2026-02-15T14:30:00",
    "pairing": {
        "autopiff_stage": "pairing",
        "driver_new": {
            "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "product": "ACME Network Adapter",
            "version": "10.0.26100.1",
            "arch": "x64"
        },
        "driver_old": {
            "sha256": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
            "product": "ACME Network Adapter",
            "version": "10.0.26100.0",
            "arch": "x64"
        },
        "decision": "accept",
        "confidence": 0.92,
        "noise_risk": "low",
        "rationale": [
            "Same product name and architecture",
            "Sequential version numbers",
            "Similar function count (delta < 5%)"
        ],
        "arch_mismatch": False
    },
    "symbols": {
        "autopiff_stage": "symbols",
        "symbolization": {
            "method": "ghidra_decompile",
            "coverage": 0.73
        }
    },
    "matching": {
        "autopiff_stage": "matching",
        "matching": {
            "method": "hash_lcs",
            "confidence": 0.85,
            "matched_count": 142,
            "added_count": 3,
            "removed_count": 1,
            "changed_count": 12,
            "total_new": 145,
            "total_old": 143,
            "quality": "high"
        }
    },
    "semantic_deltas": {
        "autopiff_stage": "semantic_deltas",
        "driver_new": {
            "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "version": "10.0.26100.1"
        },
        "driver_old": {
            "sha256": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
            "version": "10.0.26100.0"
        },
        "deltas": [
            {
                "function": "AcmeProcessIoctl_SetBuffer",
                "rule_id": "added_len_check_before_memcpy",
                "category": "bounds_check",
                "confidence": 0.92,
                "sinks": ["memory_copy"],
                "indicators": ["RtlCopyMemory", "inputBufferLength"],
                "diff_snippet": "--- old/AcmeProcessIoctl_SetBuffer\n+++ new/AcmeProcessIoctl_SetBuffer\n@@ -15,6 +15,9 @@\n   pBuffer = Irp->AssociatedIrp.SystemBuffer;\n   cbInput = irpSp->Parameters.DeviceIoControl.InputBufferLength;\n \n+  if (cbInput < sizeof(ACME_SET_BUFFER_INPUT)) {\n+    return STATUS_INVALID_PARAMETER;\n+  }\n   RtlCopyMemory(&DevExt->Config, pBuffer, cbInput);",
                "why_matters": "A length check was added before RtlCopyMemory, suggesting the old version allowed copying user-controlled data without validating the input buffer size. This pattern is consistent with a kernel pool buffer overflow fix.",
                "surface_area": ["ioctl"],
                "final_score": 11.42,
                "score_breakdown": {
                    "semantic": 5.80,
                    "reachability": 3.40,
                    "sinks": 1.38,
                    "penalties": 0.0,
                    "gates": []
                },
                "reachability_class": "ioctl"
            },
            {
                "function": "AcmeHandleReadRequest",
                "rule_id": "probe_for_read_or_write_added",
                "category": "user_boundary_check",
                "confidence": 0.93,
                "sinks": ["user_probe"],
                "indicators": ["ProbeForWrite", "UserBuffer"],
                "diff_snippet": "--- old/AcmeHandleReadRequest\n+++ new/AcmeHandleReadRequest\n@@ -8,6 +8,11 @@\n   pUserBuf = Irp->UserBuffer;\n   cbOut = irpSp->Parameters.Read.Length;\n \n+  __try {\n+    ProbeForWrite(pUserBuf, cbOut, sizeof(UCHAR));\n+  } __except(EXCEPTION_EXECUTE_HANDLER) {\n+    return STATUS_INVALID_USER_BUFFER;\n+  }\n   RtlCopyMemory(pUserBuf, DevExt->ReadBuf, cbOut);",
                "why_matters": "ProbeForWrite with SEH was added to validate the user-mode buffer before kernel writes to it. Without this check, a malicious user-mode caller could supply an arbitrary kernel address, leading to arbitrary kernel write.",
                "surface_area": ["ioctl"],
                "final_score": 10.85,
                "score_breakdown": {
                    "semantic": 6.14,
                    "reachability": 3.40,
                    "sinks": 1.31,
                    "penalties": 0.0,
                    "gates": []
                },
                "reachability_class": "ioctl"
            },
            {
                "function": "AcmeAllocatePacket",
                "rule_id": "alloc_size_overflow_check_added",
                "category": "int_overflow",
                "confidence": 0.90,
                "sinks": ["pool_alloc"],
                "indicators": ["RtlSizeTMult", "ExAllocatePool2"],
                "diff_snippet": "--- old/AcmeAllocatePacket\n+++ new/AcmeAllocatePacket\n@@ -5,7 +5,12 @@\n   ULONG headerSize = sizeof(ACME_PACKET_HEADER);\n   ULONG totalSize;\n \n-  totalSize = headerSize + payloadLen;\n+  NTSTATUS st = RtlSizeTMult(payloadLen, elementSize, &totalSize);\n+  if (!NT_SUCCESS(st)) {\n+    return NULL;\n+  }\n+  totalSize += headerSize;\n+\n   pPacket = ExAllocatePool2(POOL_FLAG_NON_PAGED, totalSize, 'kcaP');",
                "why_matters": "Raw integer arithmetic was replaced with RtlSizeTMult safe math. The old version could overflow totalSize when payloadLen * elementSize exceeded ULONG_MAX, causing an undersized allocation followed by heap corruption.",
                "surface_area": ["ioctl"],
                "final_score": 9.73,
                "score_breakdown": {
                    "semantic": 5.20,
                    "reachability": 3.40,
                    "sinks": 1.13,
                    "penalties": 0.0,
                    "gates": []
                },
                "reachability_class": "ioctl"
            },
            {
                "function": "AcmeCleanupDeviceContext",
                "rule_id": "null_after_free_added",
                "category": "lifetime_fix",
                "confidence": 0.88,
                "sinks": ["pool_free"],
                "indicators": ["ExFreePoolWithTag", "NULL assignment"],
                "diff_snippet": "--- old/AcmeCleanupDeviceContext\n+++ new/AcmeCleanupDeviceContext\n@@ -12,6 +12,7 @@\n   if (DevExt->pConfigBuffer != NULL) {\n     ExFreePoolWithTag(DevExt->pConfigBuffer, 'fnoC');\n+    DevExt->pConfigBuffer = NULL;\n   }",
                "why_matters": "NULL assignment added after ExFreePoolWithTag prevents double-free if AcmeCleanupDeviceContext is called more than once on the same device extension (e.g. during fast PnP removal sequences).",
                "surface_area": ["ioctl"],
                "final_score": 7.15,
                "score_breakdown": {
                    "semantic": 4.62,
                    "reachability": 2.00,
                    "sinks": 0.93,
                    "penalties": 0.40,
                    "gates": []
                },
                "reachability_class": "pnp"
            },
            {
                "function": "AcmeProcessIoctl_GetInfo",
                "rule_id": "added_struct_size_validation",
                "category": "bounds_check",
                "confidence": 0.88,
                "sinks": ["memory_copy"],
                "indicators": ["outputBufferLength", "sizeof"],
                "diff_snippet": "--- old/AcmeProcessIoctl_GetInfo\n+++ new/AcmeProcessIoctl_GetInfo\n@@ -10,6 +10,9 @@\n   cbOut = irpSp->Parameters.DeviceIoControl.OutputBufferLength;\n   pOut = Irp->AssociatedIrp.SystemBuffer;\n \n+  if (cbOut < sizeof(ACME_INFO_OUTPUT)) {\n+    return STATUS_BUFFER_TOO_SMALL;\n+  }\n   RtlCopyMemory(pOut, &DevExt->Info, sizeof(ACME_INFO_OUTPUT));",
                "why_matters": "Output buffer size validation was missing. An attacker could supply a smaller output buffer, causing RtlCopyMemory to write past the end of the system buffer and corrupt adjacent pool allocations.",
                "surface_area": ["ioctl"],
                "final_score": 6.90,
                "score_breakdown": {
                    "semantic": 4.16,
                    "reachability": 3.40,
                    "sinks": 1.34,
                    "penalties": 2.00,
                    "gates": []
                },
                "reachability_class": "ioctl"
            }
        ],
        "summary": {
            "total_deltas": 5,
            "by_category": {
                "bounds_check": 2,
                "user_boundary_check": 1,
                "int_overflow": 1,
                "lifetime_fix": 1
            },
            "by_rule": {
                "added_len_check_before_memcpy": 1,
                "probe_for_read_or_write_added": 1,
                "alloc_size_overflow_check_added": 1,
                "null_after_free_added": 1,
                "added_struct_size_validation": 1
            },
            "top_functions": [
                "AcmeProcessIoctl_SetBuffer",
                "AcmeHandleReadRequest",
                "AcmeAllocatePacket",
                "AcmeCleanupDeviceContext",
                "AcmeProcessIoctl_GetInfo"
            ],
            "top_score": 11.42,
            "match_rate": 97.9
        },
        "notes": []
    },
    "reachability": {
        "autopiff_stage": "reachability",
        "driver": {
            "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "arch": "x64"
        },
        "dispatch": {
            "driver_entry": "DriverEntry",
            "major_functions": {
                "IRP_MJ_CREATE": "AcmeCreate",
                "IRP_MJ_CLOSE": "AcmeClose",
                "IRP_MJ_DEVICE_CONTROL": "AcmeDeviceControl",
                "IRP_MJ_PNP": "AcmePnp"
            }
        },
        "ioctls": [
            {
                "ioctl": "0x222004",
                "handler": "AcmeProcessIoctl_SetBuffer",
                "confidence": 0.85,
                "evidence": ["switch_on_IoControlCode", "ioctl_case_call"]
            },
            {
                "ioctl": "0x222008",
                "handler": "AcmeProcessIoctl_GetInfo",
                "confidence": 0.85,
                "evidence": ["switch_on_IoControlCode", "ioctl_case_call"]
            }
        ],
        "tags": [
            {
                "function": "AcmeProcessIoctl_SetBuffer",
                "reachability_class": "ioctl",
                "confidence": 0.85,
                "paths": [["DriverEntry", "AcmeDeviceControl", "AcmeProcessIoctl_SetBuffer"]],
                "evidence": ["driver_entry_dispatch_setup", "switch_on_IoControlCode", "ioctl_case_call"]
            },
            {
                "function": "AcmeHandleReadRequest",
                "reachability_class": "ioctl",
                "confidence": 0.80,
                "paths": [["DriverEntry", "AcmeDeviceControl", "AcmeHandleReadRequest"]],
                "evidence": ["driver_entry_dispatch_setup", "direct_callgraph_edge"]
            },
            {
                "function": "AcmeAllocatePacket",
                "reachability_class": "ioctl",
                "confidence": 0.75,
                "paths": [["DriverEntry", "AcmeDeviceControl", "AcmeProcessIoctl_SetBuffer", "AcmeAllocatePacket"]],
                "evidence": ["driver_entry_dispatch_setup", "switch_on_IoControlCode", "direct_callgraph_edge"]
            },
            {
                "function": "AcmeCleanupDeviceContext",
                "reachability_class": "pnp",
                "confidence": 0.70,
                "paths": [["DriverEntry", "AcmePnp", "AcmeCleanupDeviceContext"]],
                "evidence": ["driver_entry_dispatch_setup", "major_function_assignment"]
            },
            {
                "function": "AcmeProcessIoctl_GetInfo",
                "reachability_class": "ioctl",
                "confidence": 0.85,
                "paths": [["DriverEntry", "AcmeDeviceControl", "AcmeProcessIoctl_GetInfo"]],
                "evidence": ["driver_entry_dispatch_setup", "switch_on_IoControlCode", "ioctl_case_call"]
            }
        ],
        "notes": []
    }
}


def generate_sample_data(output_dir: str = "/data/analyses"):
    """Write sample analysis to disk for development."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    analysis_dir = out / "acme-net-2026-02"
    analysis_dir.mkdir(exist_ok=True)
    with open(analysis_dir / "combined.json", "w") as f:
        json.dump(SAMPLE_ANALYSIS, f, indent=2)

    print(f"Sample data written to {analysis_dir}")


if __name__ == "__main__":
    generate_sample_data(os.environ.get("AUTOPIFF_ANALYSES_DIR", "/data/analyses"))
