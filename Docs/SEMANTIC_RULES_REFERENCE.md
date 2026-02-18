# AutoPiff Semantic Rules Reference

Complete technical reference for the AutoPiff semantic rule system: how rules are defined, how the engine evaluates them, and how scoring ranks findings.

---

## Architecture Overview

```
rules/semantic_rules.yaml    rules/sinks.yaml    rules/scoring.yaml
         |                         |                     |
         v                         v                     v
   +-------------------------------------------------+
   |           SemanticRuleEngine (rule_engine.py)    |
   |  1. Global exclusion check                      |
   |  2. Sink detection in diff                      |
   |  3. Guard/validation detection in added lines   |
   |  4. Per-rule signal matching + proximity check  |
   |  5. RuleHit generation with evidence            |
   +-------------------------------------------------+
                        |
                        v
   +-------------------------------------------------+
   |         Scoring (_score_findings)               |
   |  semantic_score + reachability_bonus +           |
   |  sink_bonus - penalties => final_score          |
   +-------------------------------------------------+
```

The engine takes a unified diff of a changed function and determines whether the change looks like a security fix. Every detection must be explainable.

---

## Configuration Files

### `rules/semantic_rules.yaml`

Defines the 58 semantic rules, 22 categories, and 2 global exclusions. This is the primary configuration file that controls what AutoPiff considers a security-relevant change.

### `rules/sinks.yaml`

Defines 22 groups of "dangerous" API symbols (145 total). A sink is an API whose misuse commonly leads to vulnerabilities. Rules become high-signal when patches add guards near sinks.

### `rules/scoring.yaml`

Defines the scoring model that ranks findings by exploit relevance: base weights per rule, category multipliers, reachability bonuses, sink bonuses, penalties, and gating thresholds.

---

## Categories

Each rule belongs to exactly one category. Categories group related vulnerability fix patterns.

| Category ID | Description | Rule Count |
|---|---|---|
| `bounds_check` | Added or strengthened bounds/size/index validation | 3 |
| `lifetime_fix` | Added or strengthened pointer lifetime/ownership protection | 2 |
| `user_boundary_check` | Added or strengthened validation of user-mode supplied data/pointers | 3 |
| `int_overflow` | Added or strengthened safe integer/size arithmetic checks | 2 |
| `state_hardening` | Added or strengthened state/refcount/synchronization validation | 1 |
| `race_condition` | Added synchronization to fix race conditions or TOCTOU bugs | 4 |
| `type_confusion` | Added type validation to prevent type confusion or wrong-object access | 3 |
| `authorization` | Added privilege, access mode, or ACL enforcement | 4 |
| `info_disclosure` | Added memory initialization or pointer scrubbing to prevent information leaks | 4 |
| `ioctl_hardening` | Added IOCTL-specific input validation or dispatch hardening | 3 |
| `mdl_handling` | Added safe MDL mapping, probe, or NULL checks | 3 |
| `object_management` | Added object reference balancing or handle access enforcement | 2 |
| `string_handling` | Replaced unsafe string operations with bounded variants | 2 |
| `pool_hardening` | Migrated to safer pool APIs or added pool allocation checks | 3 |
| `crypto_hardening` | Added secure memory wiping or constant-time comparisons | 2 |
| `error_path_hardening` | Added resource cleanup or correct status propagation on error paths | 3 |
| `dos_hardening` | Added recursion/loop bounds or resource quota checks to prevent DoS | 3 |
| `ndis_hardening` | Added NDIS OID/NBL validation for network driver security | 2 |
| `filesystem_filter` | Added minifilter context management or TOCTOU mitigations | 2 |
| `pnp_power` | Added PnP removal or power state guards | 3 |
| `dma_mmio` | Added MMIO/DMA bounds validation or mapping checks | 2 |
| `wdf_hardening` | Added WDF request buffer or completion guards | 2 |

---

## Rules Reference

### Bounds Check Rules

#### `added_len_check_before_memcpy`

| Field | Value |
|---|---|
| Category | `bounds_check` |
| Confidence | 0.92 |
| Base Score Weight | 6.0 |
| Required Signals | `sink_group: memory_copy`, `change_type: guard_added`, `guard_kind: length_check`, `proximity: near_sink` |

**What it detects:** A length or buffer size comparison was added within 10 lines of a memory copy operation (`RtlCopyMemory`, `memcpy`, `memmove`, etc.).

**Example patch:**
```c
// ADDED:
+ if (InputBufferLength < sizeof(REQUEST_STRUCT))
+     return STATUS_INVALID_PARAMETER;
  RtlCopyMemory(dest, src, InputBufferLength);
```

**Why it matters:** Missing length validation before memory copies is one of the most common sources of kernel buffer overflows. Without a bounds check, an attacker-controlled length value passed through an IOCTL can cause `RtlCopyMemory` to write past the end of a kernel buffer, corrupting adjacent pool memory. This primitive is highly reliable for exploitation because the attacker controls both the overflow size and the data written. Real-world examples include numerous Windows kernel CVEs where IOCTL handlers copy user data without first validating `InputBufferLength` against the destination buffer size.

---

#### `added_struct_size_validation`

| Field | Value |
|---|---|
| Category | `bounds_check` |
| Confidence | 0.88 |
| Base Score Weight | 4.5 |
| Required Signals | `change_type: guard_added`, `guard_kind: sizeof_check` |

**What it detects:** A `sizeof()` check or `RtlSizeT*` validation was added, typically to validate that an input buffer is large enough for the expected structure.

**Example patch:**
```c
// ADDED:
+ if (bufferSize < sizeof(MY_IOCTL_INPUT))
+     return STATUS_BUFFER_TOO_SMALL;
```

**Why it matters:** When a driver reads a complex structure from an IOCTL input buffer without first verifying the buffer is large enough, it can read past the end of the allocation. Depending on context this yields either an information leak (reading adjacent pool data), a kernel pool corruption (writing response data past the buffer), or a controlled out-of-bounds read that feeds attacker data into subsequent logic. The `sizeof` check is the standard idiom to prevent this entire class of issues.

---

#### `added_index_bounds_check`

| Field | Value |
|---|---|
| Category | `bounds_check` |
| Confidence | 0.86 |
| Base Score Weight | 4.0 |
| Required Signals | `change_type: guard_added`, `guard_kind: index_bounds` |

**What it detects:** An index or array bounds check was added (e.g., `if (index >= count)`).

**Example patch:**
```c
// ADDED:
+ if (idx >= MAX_ENTRIES)
+     return STATUS_INVALID_PARAMETER;
  table[idx] = value;
```

**Why it matters:** Unchecked array or table indices supplied from user-controlled input (IOCTL buffers, IRP parameters) allow an attacker to read or write at an arbitrary offset relative to the base of the array. In kernel pool memory, this is a direct primitive for pool corruption, arbitrary write, or information disclosure depending on the access pattern.

---

### Lifetime Fix Rules

#### `null_after_free_added`

| Field | Value |
|---|---|
| Category | `lifetime_fix` |
| Confidence | 0.88 |
| Base Score Weight | 5.0 |
| Required Signals | `sink_group: pool_free`, `change_type: post_free_hardening`, `hardening_kind: null_assignment`, `proximity: immediately_after_sink` |

**What it detects:** A pointer is set to `NULL` within 3 lines immediately after an `ExFreePool`/`ExFreePoolWithTag` call. This is the classic use-after-free mitigation pattern.

**Example patch:**
```c
  ExFreePoolWithTag(buffer, TAG);
// ADDED:
+ buffer = NULL;
```

**Why it matters:** Setting freed pointers to NULL prevents use-after-free exploitation by converting dangling pointer dereferences into NULL dereferences (which are typically non-exploitable in kernel mode). CVE-2025-60719 (afd.sys) and CVE-2025-62215 are recent examples of UAF vulnerabilities in Windows kernel drivers that arose from race conditions leaving dangling pointers. The NULL-after-free pattern is the simplest and most reliable mitigation for this entire vulnerability class.

---

#### `guard_before_free_added`

| Field | Value |
|---|---|
| Category | `lifetime_fix` |
| Confidence | 0.86 |
| Base Score Weight | 4.0 |
| Required Signals | `sink_group: pool_free`, `change_type: guard_added`, `guard_kind: null_check`, `proximity: near_sink` |

**What it detects:** A NULL check was added before a free operation, preventing double-free or free-of-invalid-pointer.

**Example patch:**
```c
// ADDED:
+ if (ptr != NULL) {
      ExFreePoolWithTag(ptr, TAG);
+     ptr = NULL;
+ }
```

**Why it matters:** Double-free vulnerabilities occur when a driver frees the same pool allocation twice. The Windows kernel pool allocator may have already reassigned that memory to another object, so freeing it again corrupts the pool metadata or destroys a live object. Attackers exploit this by spraying controlled objects into the freed slot between the first and second free, gaining arbitrary write or code execution. The NULL guard breaks the double-free chain entirely.

---

### User/Kernel Boundary Rules

#### `probe_for_read_or_write_added`

| Field | Value |
|---|---|
| Category | `user_boundary_check` |
| Confidence | 0.93 |
| Base Score Weight | 6.0 |
| Required Signals | `sink_group: user_probe`, `change_type: validation_added`, `validation_kind: probe` |

**What it detects:** `ProbeForRead` or `ProbeForWrite` calls were added to validate user-mode pointers before kernel-mode access.

**Example patch:**
```c
// ADDED:
+ ProbeForRead(userBuffer, bufferLength, sizeof(UCHAR));
  RtlCopyMemory(kernelBuffer, userBuffer, bufferLength);
```

**Why it matters:** Missing probe calls allow user-mode code to pass arbitrary kernel pointers, potentially leading to arbitrary read/write primitives. Without probing, a user-mode attacker can supply a kernel-mode address as a "user buffer," causing the driver to read from or write to arbitrary kernel memory. This is the foundation of numerous privilege escalation exploits against Windows drivers.

---

#### `previous_mode_gating_added`

| Field | Value |
|---|---|
| Category | `user_boundary_check` |
| Confidence | 0.90 |
| Base Score Weight | 5.0 |
| Required Signals | `sink_group: user_probe`, `change_type: validation_added`, `validation_kind: previous_mode_gate` |

**What it detects:** `ExGetPreviousMode` gating was added to distinguish user-mode callers from kernel-mode callers.

**Example patch:**
```c
// ADDED:
+ if (ExGetPreviousMode() != KernelMode) {
+     ProbeForRead(buffer, length, 1);
+ }
```

**Why it matters:** Without previous-mode checking, a driver treats all callers identically. An attacker in user-mode can invoke a kernel path that was designed to only be called by other kernel components, bypassing trust assumptions. The classic exploitation pattern is supplying kernel-mode addresses through an IOCTL that skips `ProbeForRead`/`ProbeForWrite` because it assumed the caller was already in kernel mode. Adding `ExGetPreviousMode` gating ensures user-mode callers go through the full validation path. Google Project Zero documented an entire bug class around access mode mismatches in the Windows IO Manager in 2019.

---

#### `seh_guard_added_around_user_deref`

| Field | Value |
|---|---|
| Category | `user_boundary_check` |
| Confidence | 0.82 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: exceptions`, `change_type: validation_added`, `validation_kind: seh_guard` |

**What it detects:** Structured exception handling (`__try`/`__except`) was added around pointer access, typically to safely handle user-mode pointer dereferences.

**Example patch:**
```c
// ADDED:
+ __try {
      value = *(PULONG)userPointer;
+ } __except(EXCEPTION_EXECUTE_HANDLER) {
+     return GetExceptionCode();
+ }
```

**Why it matters:** When a kernel driver dereferences a user-supplied pointer without SEH, the user can supply an invalid address (unmapped, paged-out, or a kernel address) causing an unhandled exception that blue-screens the system (denial of service) or, worse, is exploitable through controlled fault handling. Wrapping user pointer access in `__try`/`__except` ensures the driver gracefully handles invalid pointers instead of crashing. This is especially critical for `METHOD_NEITHER` IOCTLs where the driver receives raw user-mode pointers. CWE-781 specifically documents this vulnerability class.

---

### Integer Overflow Rules

#### `safe_size_math_helper_added`

| Field | Value |
|---|---|
| Category | `int_overflow` |
| Confidence | 0.88 |
| Base Score Weight | 4.5 |
| Required Signals | `sink_group: io_sanitization`, `change_type: validation_added`, `validation_kind: safe_math_helper` |

**What it detects:** Raw arithmetic was replaced with safe math helpers like `RtlULongAdd`, `RtlSizeTMult`, etc.

**Example patch:**
```c
// REMOVED:
- totalSize = count * elementSize;
// ADDED:
+ if (!NT_SUCCESS(RtlSizeTMult(count, elementSize, &totalSize)))
+     return STATUS_INTEGER_OVERFLOW;
```

**Why it matters:** Integer overflows in size calculations lead to undersized allocations, which become exploitable heap overflows. The Windows safe integer math library (`RtlULongAdd`, `RtlSizeTMult`, etc.) was specifically designed to catch these overflows. White Knight Labs documented how integer overflow in Windows kernel exploitation allows attackers to trigger small allocations followed by large copies, giving precise control over heap corruption.

---

#### `alloc_size_overflow_check_added`

| Field | Value |
|---|---|
| Category | `int_overflow` |
| Confidence | 0.90 |
| Base Score Weight | 5.5 |
| Required Signals | `sink_group: pool_alloc`, `change_type: guard_added`, `guard_kind: overflow_check`, `proximity: near_sink` |

**What it detects:** An overflow or size check was added before a pool allocation (`ExAllocatePool*`).

**Example patch:**
```c
// ADDED:
+ if (count > ULONG_MAX / elementSize)
+     return STATUS_INTEGER_OVERFLOW;
  totalSize = count * elementSize;
  buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, totalSize, 'fooB');
```

**Why it matters:** If an attacker controls `count` or `elementSize` through an IOCTL, they can trigger an integer overflow in the multiplication so that `totalSize` wraps to a small value. The kernel then allocates a tiny buffer while the driver proceeds to fill it with `count * elementSize` bytes of data, causing a heap buffer overflow. These are among the most reliably exploitable kernel vulnerabilities because the attacker controls both the overflow amount and the data written. Synacktiv's 2021 research on discovering and exploiting kernel pool overflows on modern Windows 10 demonstrated this class of attack in detail.

---

### State Hardening Rules

#### `interlocked_refcount_added`

| Field | Value |
|---|---|
| Category | `state_hardening` |
| Confidence | 0.78 |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: refcounting`, `change_type: hardening_added`, `hardening_kind: refcount` |

**What it detects:** `InterlockedIncrement`/`InterlockedDecrement`/`InterlockedExchange`/`InterlockedCompareExchange` operations were added to protect shared object lifetime.

**Example patch:**
```c
// ADDED:
+ InterlockedIncrement(&pObject->RefCount);
  UseObject(pObject);
  // ... later ...
+ if (InterlockedDecrement(&pObject->RefCount) == 0) {
+     ExFreePoolWithTag(pObject, 'jbO');
+ }
```

**Why it matters:** Without atomic reference counting, concurrent access from multiple threads or IRP handlers can create a race condition: one thread frees an object while another is still using it, producing a use-after-free. In kernel drivers, this is particularly dangerous because IRP dispatch routines, DPC callbacks, and work items can execute concurrently on different processors. Adding `Interlocked*` operations ensures the reference count is modified atomically, preventing the race. This has lower confidence (0.78) than other rules because interlocked operations are also used for benign concurrency patterns that are not security-relevant.

---

### Race Condition Rules

#### `spinlock_acquisition_added`

| Field | Value |
|---|---|
| Category | `race_condition` |
| Confidence | 0.80 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: synchronization`, `change_type: hardening_added`, `hardening_kind: spinlock` |

**What it detects:** A spinlock acquisition/release pair was added to protect shared data from concurrent access. This includes `KeAcquireSpinLock`/`KeReleaseSpinLock` and their DPC-level and in-stack queued variants.

**Example patch:**
```c
// ADDED:
+ KeAcquireSpinLock(&DeviceExtension->Lock, &OldIrql);
  SharedData->Field = newValue;
+ KeReleaseSpinLock(&DeviceExtension->Lock, OldIrql);
```

**Why it matters:** Race conditions in kernel drivers are a major source of use-after-free and state corruption vulnerabilities. CVE-2024-30088 and CVE-2024-30099 are TOCTOU race condition vulnerabilities in the Windows Kernel that allow local privilege escalation. CVE-2025-62215 is a race condition in the Windows Kernel exploited in the wild that allows attackers to manipulate system memory. Adding spinlock synchronization around shared data access prevents concurrent modification that leads to these exploitable conditions. The confidence is moderate (0.80) because spinlocks are sometimes added for non-security performance or correctness reasons.

---

#### `mutex_or_resource_lock_added`

| Field | Value |
|---|---|
| Category | `race_condition` |
| Confidence | 0.82 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: synchronization`, `change_type: hardening_added`, `hardening_kind: mutex_resource` |

**What it detects:** A mutex or executive resource lock was added to protect shared state. This includes `ExAcquireFastMutex`, `ExAcquireResourceExclusiveLite`/`ExAcquireResourceSharedLite`, `KeEnterCriticalRegion`, and `KeWaitForSingleObject`.

**Example patch:**
```c
// ADDED:
+ KeEnterCriticalRegion();
+ ExAcquireResourceExclusiveLite(&pObject->Resource, TRUE);
  pObject->RefCount++;
+ ExReleaseResourceLite(&pObject->Resource);
+ KeLeaveCriticalRegion();
```

**Why it matters:** CVE-2025-60719 is a use-after-free in afd.sys caused by a race condition where concurrent access to shared state corrupts kernel memory, allowing privilege escalation to SYSTEM. Executive resource locks and mutexes provide PASSIVE_LEVEL synchronization for operations that may take extended time or involve pageable memory. Their addition in a patch is a strong signal that the developer identified a race condition leading to exploitable state corruption.

---

#### `double_fetch_to_capture_fix`

| Field | Value |
|---|---|
| Category | `race_condition` |
| Confidence | 0.85 |
| Base Score Weight | 5.0 |
| Required Signals | `change_type: hardening_added`, `hardening_kind: buffer_capture` |

**What it detects:** A double-fetch TOCTOU vulnerability was fixed by capturing a user buffer value into a local (kernel-stack) variable instead of reading from user memory multiple times.

**Example patch:**
```c
// BEFORE: reads user buffer field twice (race window)
  if (UserBuffer->Length <= MAX_SIZE)
      RtlCopyMemory(KernelBuf, UserBuffer->Data, UserBuffer->Length);

// AFTER: capture once into local
+ CapturedLength = UserBuffer->Length;
+ if (CapturedLength <= MAX_SIZE)
+     RtlCopyMemory(KernelBuf, UserBuffer->Data, CapturedLength);
```

**Why it matters:** Double-fetch bugs are a well-documented TOCTOU class where kernel code reads a user-mode value for validation, then reads it again for use. Between the two reads, an attacker thread can change the value, bypassing the validation. CVE-2025-55236 (Windows Graphics Kernel TOCTOU), CVE-2025-53136 (KASLR info leak via TOCTOU), and CVE-2026-20809 (Windows Kernel TOCTOU LPE) are all recent examples. The fix pattern of capturing into a local variable is highly distinctive and almost always security-motivated, giving this rule strong confidence at 0.85.

---

#### `cancel_safe_irp_queue_added`

| Field | Value |
|---|---|
| Category | `race_condition` |
| Confidence | 0.78 |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: irp_cancel`, `change_type: hardening_added`, `hardening_kind: cancel_safe` |

**What it detects:** Manual IRP cancellation handling was replaced with a cancel-safe queue (`IoCsqInsertIrp`/`IoCsqRemoveIrp`) to fix IRP cancellation races.

**Example patch:**
```c
// REMOVED:
- IoSetCancelRoutine(Irp, MyCancelRoutine);
- InsertTailList(&DeviceExtension->IrpQueue, &Irp->Tail.Overlay.ListEntry);

// ADDED:
+ IoCsqInsertIrp(&DeviceExtension->CancelSafeQueue, Irp, NULL);
```

**Why it matters:** IRP cancellation races are a well-known vulnerability class in WDM drivers. When a driver manually manages IRP cancellation with `IoSetCancelRoutine`, there is a window between setting the cancel routine and inserting the IRP into the queue where cancellation can race with insertion. This leads to double-free, use-after-free, or deadlock conditions. The cancel-safe queue framework (`IoCsq*`) was specifically designed by Microsoft to eliminate this race. Its addition in a patch is a clear signal of a concurrency fix.

---

### Type Confusion Rules

#### `object_type_validation_added`

| Field | Value |
|---|---|
| Category | `type_confusion` |
| Confidence | 0.88 |
| Base Score Weight | 5.0 |
| Required Signals | `change_type: guard_added`, `guard_kind: object_type_check` |

**What it detects:** An object type tag or magic value validation was added before struct member access or vtable dispatch, preventing the wrong object type from being cast and used.

**Example patch:**
```c
// ADDED:
+ if (pStreamObj->ObjectType != KSOBJECT_TYPE_STREAM) {
+     return STATUS_INVALID_PARAMETER;
+ }
  pStreamObj->Handler(pStreamObj);
```

**Why it matters:** Type confusion occurs when a program treats a piece of memory as a different object type than it actually is, leading to memory corruption or arbitrary code execution. CVE-2022-21882 is a Win32k window object type confusion exploited in the wild. CVE-2023-36802 is a type confusion in Microsoft Kernel Streaming Server (MSKSSRV) that Synacktiv exploited at Pwn2Own 2023 for privilege escalation to SYSTEM. White Knight Labs documented that type confusion in IOCTL functions operating on stream objects is a particularly common pattern. Adding type tag validation before object use is the standard mitigation.

---

#### `handle_object_type_check_added`

| Field | Value |
|---|---|
| Category | `type_confusion` |
| Confidence | 0.92 |
| Base Score Weight | 5.5 |
| Required Signals | `sink_group: handle_validation`, `change_type: guard_added`, `guard_kind: handle_type_validation` |

**What it detects:** The `ObjectType` parameter was added to `ObReferenceObjectByHandle` to prevent handle type confusion, where a user-mode handle to one object type (e.g., a file) is passed where a different type (e.g., a process) is expected.

**Example patch:**
```c
// BEFORE: no ObjectType validation (NULL allows any type)
  ObReferenceObjectByHandle(Handle, GENERIC_READ, NULL, KernelMode, &Object, NULL);

// AFTER: ObjectType validated
+ ObReferenceObjectByHandle(Handle, GENERIC_READ, *IoFileObjectType, UserMode, &Object, NULL);
```

**Why it matters:** Microsoft's own documentation on "Failure to Validate Object Handles" warns that although `ObReferenceObjectByHandle` returns a pointer to an object, the driver has no guarantee that the pointer references the expected object type unless the `ObjectType` parameter is specified. Without it, a user-mode attacker can pass a handle to an arbitrary object type, causing the driver to interpret its memory as a different structure -- classic type confusion. This has very high confidence (0.92) because adding a non-NULL `ObjectType` parameter is almost always a security fix.

---

#### `wow64_thunk_validation_added`

| Field | Value |
|---|---|
| Category | `type_confusion` |
| Confidence | 0.85 |
| Base Score Weight | 4.5 |
| Required Signals | `change_type: guard_added`, `guard_kind: wow64_check` |

**What it detects:** An `IoIs32bitProcess` check was added to handle WOW64 (32-bit process on 64-bit Windows) struct layout differences, preventing type confusion between 32-bit and 64-bit structure layouts.

**Example patch:**
```c
// ADDED:
+ if (IoIs32bitProcess(Irp)) {
+     pInput32 = (PIOCTL_INPUT_32)Irp->AssociatedIrp.SystemBuffer;
+     // handle 32-bit struct layout
+ } else {
      pInput = (PIOCTL_INPUT)Irp->AssociatedIrp.SystemBuffer;
+ }
```

**Why it matters:** CVE-2025-53149 is a heap-based buffer overflow in the Windows Kernel Streaming WOW Thunk Service Driver (ksthunk.sys) caused by incorrect handling of 32-bit/64-bit structure layout differences. When a 32-bit (WOW64) process communicates with a 64-bit kernel driver, pointer sizes and struct alignment differ. If the driver reads the buffer using the wrong layout, it interprets fields at incorrect offsets, causing memory corruption. Adding `IoIs32bitProcess` gating ensures the correct struct layout is used for each caller architecture.

---

### Authorization Rules

#### `privilege_check_added`

| Field | Value |
|---|---|
| Category | `authorization` |
| Confidence | 0.90 |
| Base Score Weight | 5.5 |
| Required Signals | `sink_group: authorization`, `change_type: validation_added`, `validation_kind: privilege_check` |

**What it detects:** A privilege or access control check was added using `SeSinglePrivilegeCheck`, `SeAccessCheck`, or `SePrivilegeCheck` before a privileged operation.

**Example patch:**
```c
// ADDED:
+ if (!SeSinglePrivilegeCheck(SeLoadDriverPrivilege, UserMode)) {
+     return STATUS_PRIVILEGE_NOT_HELD;
+ }
  Status = ZwLoadDriver(&DriverPath);
```

**Why it matters:** Missing privilege checks allow unprivileged users to perform operations that should require elevated privileges, leading directly to elevation of privilege vulnerabilities. This is a fundamental access control pattern in the Windows security model. Microsoft's security model documentation emphasizes that drivers must check caller privileges before performing sensitive operations. The high confidence (0.90) reflects that adding `SeSinglePrivilegeCheck` or `SeAccessCheck` is almost exclusively a security fix.

---

#### `access_mode_enforcement_added`

| Field | Value |
|---|---|
| Category | `authorization` |
| Confidence | 0.93 |
| Base Score Weight | 6.0 |
| Required Signals | `change_type: validation_added`, `validation_kind: access_mode_fix` |

**What it detects:** An access mode mismatch was fixed by using the caller's actual `RequestorMode` instead of hardcoded `KernelMode`, or by adding `OBJ_FORCE_ACCESS_CHECK` to enforce access checks on handle operations initiated on behalf of user-mode callers.

**Example patch:**
```c
// BEFORE: KernelMode bypasses all access checks
  ObReferenceObjectByHandle(Handle, DesiredAccess, ObjectType, KernelMode, &Object, NULL);

// AFTER: uses caller's actual mode
+ AccessMode = Irp->RequestorMode;
+ ObReferenceObjectByHandle(Handle, DesiredAccess, ObjectType, AccessMode, &Object, NULL);
```

**Why it matters:** Google Project Zero documented an entire bug class around "Access Mode Mismatch in IO Manager" in 2019, where kernel code uses `KernelMode` instead of the actual caller's access mode, bypassing all security checks. This allows user-mode attackers to reference arbitrary kernel objects, open files with elevated permissions, or access registry keys they should not have access to. The fix of propagating `Irp->RequestorMode` or `ExGetPreviousMode()` is almost always a critical security fix. This has the highest confidence (0.93) in the authorization category.

---

#### `device_acl_hardening`

| Field | Value |
|---|---|
| Category | `authorization` |
| Confidence | 0.90 |
| Base Score Weight | 4.0 |
| Required Signals | `sink_group: device_security`, `change_type: hardening_added`, `hardening_kind: device_acl` |

**What it detects:** The device object ACL was hardened by using `IoCreateDeviceSecure` instead of `IoCreateDevice`, or by adding the `FILE_DEVICE_SECURE_OPEN` flag with a restrictive SDDL string.

**Example patch:**
```c
// BEFORE: permissive device creation
  IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

// AFTER: restricted ACL
+ IoCreateDeviceSecure(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN,
+     FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &DeviceObject);
```

**Why it matters:** When a driver creates a device object with `IoCreateDevice` and a permissive ACL (or no ACL at all), any user on the system can open a handle to the device and send IOCTLs. This is the root cause of numerous third-party driver privilege escalation vulnerabilities. Using `IoCreateDeviceSecure` with a restrictive SDDL string limits which users can interact with the driver, reducing the attack surface. The POPKORN research project found dozens of vulnerable drivers with overly permissive device objects.

---

#### `registry_access_mask_hardened`

| Field | Value |
|---|---|
| Category | `authorization` |
| Confidence | 0.82 |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: handle_validation`, `change_type: hardening_added`, `hardening_kind: access_mask_reduction` |

**What it detects:** A registry key access mask was reduced from an overly broad value like `KEY_ALL_ACCESS` to a least-privilege value like `KEY_READ`.

**Example patch:**
```c
// BEFORE: overly broad access
  ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);

// AFTER: least-privilege access
+ ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
```

**Why it matters:** When a driver opens a registry key with `KEY_ALL_ACCESS` on behalf of a user-mode caller without `OBJ_FORCE_ACCESS_CHECK`, the handle inherits kernel-mode access rights. If the handle leaks to user-mode or is used in a path reachable from user-mode, the attacker gains the ability to modify registry keys they should only be able to read. Reducing the access mask to the minimum required follows the principle of least privilege and limits the damage from any handle misuse. The confidence is moderate (0.82) because access mask changes can also be non-security cleanup.

---

### Information Disclosure Rules

#### `buffer_zeroing_before_copy_added`

| Field | Value |
|---|---|
| Category | `info_disclosure` |
| Confidence | 0.90 |
| Base Score Weight | 4.5 |
| Required Signals | `sink_group: memory_zeroing`, `change_type: validation_added`, `validation_kind: buffer_zeroing` |

**What it detects:** `RtlZeroMemory` was added before populating an output buffer that is returned to user mode, preventing kernel memory disclosure through uninitialized padding or partially-filled structures.

**Example patch:**
```c
// ADDED:
+ RtlZeroMemory(OutputBuffer, sizeof(*OutputBuffer));
  OutputBuffer->Field1 = Value1;
  OutputBuffer->Field2 = Value2;
  // padding bytes and Field3 are now zero instead of stale kernel data
```

**Why it matters:** CVE-2025-55699 and CVE-2025-59186 are kernel information disclosure vulnerabilities caused by returning uninitialized memory to user mode. CVE-2025-29829 in the Windows Trusted Runtime Interface Driver allows reading parts of kernel memory through uninitialized resources. Research by j00ru (Bochspwn Reloaded) discovered dozens of similar vulnerabilities through systematic taint tracking. MSRC addressed this class systemically through the ExAllocatePool2 API (which zeros allocations by default), but individual fixes still require explicit zeroing for stack buffers and partially-filled output structures.

---

#### `stack_variable_initialization_added`

| Field | Value |
|---|---|
| Category | `info_disclosure` |
| Confidence | 0.85 |
| Base Score Weight | 3.5 |
| Required Signals | `change_type: hardening_added`, `hardening_kind: buffer_zeroing` |

**What it detects:** Zero-initialization was added to stack variables (structs, unions, or arrays) to prevent uninitialized memory from leaking to user mode.

**Example patch:**
```c
// BEFORE:
  LARGE_INTEGER Timeout;
  MY_STRUCT LocalStruct;

// AFTER:
+ LARGE_INTEGER Timeout = {0};
+ MY_STRUCT LocalStruct = {0};
```

**Why it matters:** Uninitialized stack variables in kernel functions can contain sensitive data from previous function calls -- including kernel pointers that defeat KASLR, authentication tokens, or cryptographic key material. MSRC estimated that approximately 5-10% of Microsoft CVEs in 2017-2018 were caused by uninitialized memory disclosure. They subsequently introduced the InitAll compiler mitigation to zero-initialize stack variables by default, but driver code compiled without this mitigation still requires manual initialization. The confidence is 0.85 because zero-initialization can also be a benign defensive coding practice.

---

#### `output_length_truncation_added`

| Field | Value |
|---|---|
| Category | `info_disclosure` |
| Confidence | 0.82 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: irp_completion`, `change_type: guard_added`, `guard_kind: length_check` |

**What it detects:** The `IoStatus.Information` field was corrected to report only the number of initialized bytes, preventing stale kernel data from being returned in the output buffer.

**Example patch:**
```c
// BEFORE: reports full buffer size (may include uninitialized bytes)
  Irp->IoStatus.Information = sizeof(OUTPUT_STRUCT);

// AFTER: reports only initialized bytes
+ Irp->IoStatus.Information = FIELD_OFFSET(OUTPUT_STRUCT, LastInitializedField) + sizeof(ULONG);
```

**Why it matters:** CVE-2025-59186 describes a pattern where drivers report that N bytes were written to the output buffer while only populating M < N bytes, allowing stale kernel memory to be copied into user buffers. The `IoStatus.Information` field tells the I/O Manager how many bytes to copy back to the user-mode buffer. If this value exceeds the amount of data actually written, the remaining bytes contain whatever was in the kernel buffer previously -- potentially sensitive kernel addresses or data from other processes.

---

#### `kernel_pointer_scrubbing_added`

| Field | Value |
|---|---|
| Category | `info_disclosure` |
| Confidence | 0.88 |
| Base Score Weight | 5.0 |
| Required Signals | `change_type: hardening_added`, `hardening_kind: pointer_scrub` |

**What it detects:** A kernel pointer was removed or zeroed out from a user-accessible output buffer, fixing a KASLR bypass.

**Example patch:**
```c
// BEFORE: leaks kernel pointer
  UserBuffer->ObjectPointer = pKernelObject;

// AFTER: scrubbed
+ UserBuffer->ObjectPointer = (PVOID)0;
```

**Why it matters:** CVE-2025-53136 is a KASLR bypass caused by a TOCTOU vulnerability in `RtlSidHashInitialize()` that temporarily writes a sensitive kernel pointer into a userland buffer. Kernel address leaks are critical because they defeat Kernel Address Space Layout Randomization (KASLR), which is the primary defense against kernel exploitation. Once an attacker knows the base address of kernel modules, they can reliably construct ROP chains and exploit other vulnerabilities. Scrubbing kernel pointers from output buffers is a direct KASLR hardening measure with high security value.

---

### IOCTL Hardening Rules

#### `method_neither_probe_added`

| Field | Value |
|---|---|
| Category | `ioctl_hardening` |
| Confidence | 0.93 |
| Base Score Weight | 6.0 |
| Required Signals | `sink_group: user_probe`, `change_type: validation_added`, `validation_kind: probe`, `sink_group: exceptions` |

**What it detects:** `ProbeForRead`/`ProbeForWrite` with SEH (`__try`/`__except`) was added for `METHOD_NEITHER` IOCTL buffer access, where the I/O Manager does not validate buffers.

**Example patch:**
```c
// ADDED:
+ __try {
+     ProbeForRead(UserBuffer, InputLength, sizeof(UCHAR));
      RtlCopyMemory(KernelBuf, UserBuffer, InputLength);
+ } __except(EXCEPTION_EXECUTE_HANDLER) {
+     return GetExceptionCode();
+ }
```

**Why it matters:** CWE-781 (Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code) is a dedicated CWE for this exact vulnerability pattern. When METHOD_NEITHER is used, the I/O Manager performs no buffer validation -- the driver receives raw user-mode pointers and is entirely responsible for probing and protecting against invalid addresses. CyberArk's "Finding Bugs in Windows Drivers" research emphasized that any driver using METHOD_NEITHER without probing the buffers is a "major security hole." This has the highest confidence (0.93) in the IOCTL hardening category because the combination of probe + SEH for METHOD_NEITHER is almost exclusively a security fix.

---

#### `ioctl_input_size_validation_added`

| Field | Value |
|---|---|
| Category | `ioctl_hardening` |
| Confidence | 0.92 |
| Base Score Weight | 5.0 |
| Required Signals | `change_type: guard_added`, `guard_kind: sizeof_check`, `guard_kind: length_check` |

**What it detects:** `InputBufferLength`/`OutputBufferLength` size validation was added in an IOCTL handler, ensuring the buffer is large enough for the expected structure.

**Example patch:**
```c
// ADDED:
+ if (InputBufferLength < sizeof(MY_INPUT)) {
+     return STATUS_BUFFER_TOO_SMALL;
+ }
+ if (OutputBufferLength < sizeof(MY_OUTPUT)) {
+     return STATUS_BUFFER_TOO_SMALL;
+ }
  pInput = (PMY_INPUT)Irp->AssociatedIrp.SystemBuffer;
```

**Why it matters:** This is the single most common vulnerability pattern in Windows kernel drivers. Without size validation, the driver casts the system buffer to a structure pointer and reads fields that may extend past the allocated buffer, causing an out-of-bounds read. If the driver writes to the output buffer without size validation, it causes an out-of-bounds write. Microsoft's documentation on "Security Issues for I/O Control Codes" explicitly warns about this pattern. This rule requires both `sizeof_check` and `length_check` guards to reduce false positives.

---

#### `ioctl_code_default_case_added`

| Field | Value |
|---|---|
| Category | `ioctl_hardening` |
| Confidence | 0.70 |
| Base Score Weight | 2.0 |
| Required Signals | `change_type: hardening_added`, `hardening_kind: default_case` |

**What it detects:** A `default` case with an error return status was added to an IOCTL dispatch switch statement.

**Example patch:**
```c
  switch (IoControlCode) {
      case IOCTL_A: ...
      case IOCTL_B: ...
// ADDED:
+     default:
+         Status = STATUS_INVALID_DEVICE_REQUEST;
+         break;
  }
```

**Why it matters:** Without a default case, unrecognized IOCTL codes may fall through to unintended handlers or leave the IRP in an inconsistent state. While this is primarily a defensive coding practice, in some drivers the missing default allows an attacker to reach code paths that were intended to be unreachable. The low confidence (0.70) and low base weight (2.0) reflect that this pattern is often benign hardening rather than a direct vulnerability fix.

---

### MDL Handling Rules

#### `mdl_safe_mapping_replacement`

| Field | Value |
|---|---|
| Category | `mdl_handling` |
| Confidence | 0.88 |
| Base Score Weight | 4.0 |
| Required Signals | `sink_group: mdl_operations`, `change_type: hardening_added`, `hardening_kind: mdl_safe` |

**What it detects:** The deprecated `MmGetSystemAddressForMdl` was replaced with `MmGetSystemAddressForMdlSafe`, which returns NULL on failure instead of bugchecking the system.

**Example patch:**
```c
// BEFORE: unsafe, bugchecks on failure
  SystemAddress = MmGetSystemAddressForMdl(Mdl);

// AFTER: safe variant with NULL check
+ SystemAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
+ if (SystemAddress == NULL) {
+     return STATUS_INSUFFICIENT_RESOURCES;
+ }
```

**Why it matters:** `MmGetSystemAddressForMdl` is deprecated because it causes a system bugcheck (BSOD) when mapping fails due to low memory. An attacker can trigger this by exhausting system resources, creating a reliable denial-of-service primitive. `MmGetSystemAddressForMdlSafe` returns NULL instead, allowing the driver to handle the failure gracefully. Microsoft's documentation explicitly states that drivers must check for a NULL return from `MmGetSystemAddressForMdlSafe`.

---

#### `mdl_probe_access_mode_fix`

| Field | Value |
|---|---|
| Category | `mdl_handling` |
| Confidence | 0.93 |
| Base Score Weight | 6.0 |
| Required Signals | `sink_group: mdl_operations`, `change_type: validation_added`, `validation_kind: access_mode_fix` |

**What it detects:** The `AccessMode` parameter of `MmProbeAndLockPages` was changed from `KernelMode` to `UserMode` to enforce address validation on user-supplied MDL buffers.

**Example patch:**
```c
// BEFORE: KernelMode skips address validation
  MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);

// AFTER: UserMode enforces address range check
+ MmProbeAndLockPages(Mdl, UserMode, IoWriteAccess);
```

**Why it matters:** CVE-2023-29360 (MSKSSRV) is a privilege escalation vulnerability caused by exactly this pattern -- `MmProbeAndLockPages` called with `KernelMode` AccessMode, which skips the check that the buffer virtual address is in user-land. When AccessMode is `KernelMode`, the function does not verify that the buffer address is below `MmHighestUserAddress`, allowing a user to create an MDL pointing to critical kernel data. Changing to `UserMode` ensures the address range is validated. This has very high confidence (0.93) and the highest base weight (6.0) in this category because the `KernelMode` to `UserMode` change in `MmProbeAndLockPages` is almost always a critical security fix.

---

#### `mdl_null_check_added`

| Field | Value |
|---|---|
| Category | `mdl_handling` |
| Confidence | 0.84 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: mdl_operations`, `change_type: guard_added`, `guard_kind: null_check`, `proximity: near_sink` |

**What it detects:** A NULL check was added on `Irp->MdlAddress` before MDL mapping operations.

**Example patch:**
```c
// ADDED:
+ if (Irp->MdlAddress == NULL) {
+     return STATUS_INVALID_PARAMETER;
+ }
  SystemAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
```

**Why it matters:** For direct I/O operations, the I/O Manager creates an MDL and stores it in `Irp->MdlAddress`. However, in certain error conditions or when the user buffer is zero-length, `MdlAddress` can be NULL. Passing NULL to MDL functions causes a NULL pointer dereference in the kernel, leading to a system bugcheck. While modern Windows mitigates NULL dereferences somewhat, the resulting BSOD is still a denial-of-service condition. Adding the NULL check prevents this crash path.

---

### Object Management Rules

#### `ob_reference_balance_fix`

| Field | Value |
|---|---|
| Category | `object_management` |
| Confidence | 0.86 |
| Base Score Weight | 4.0 |
| Required Signals | `sink_group: object_management`, `change_type: hardening_added`, `hardening_kind: reference_balance` |

**What it detects:** A missing `ObDereferenceObject` was added on an error path, fixing a reference count imbalance that would lead to either a memory leak (if the reference is never released) or a use-after-free (if the reference count underflows elsewhere).

**Example patch:**
```c
  Status = ObReferenceObjectByHandle(Handle, ..., &Object, NULL);
  if (!NT_SUCCESS(Status)) return Status;
  Status = DoSomething(Object);
  if (!NT_SUCCESS(Status)) {
// ADDED:
+     ObDereferenceObject(Object);
      return Status;
  }
  ObDereferenceObject(Object);
```

**Why it matters:** j00ru's research on "Windows Kernel Reference Count Vulnerabilities" (ZeroNights 2012) documented how reference count imbalances lead to exploitable use-after-free conditions. When a driver calls `ObReferenceObjectByHandle` to get a pointer to an object but fails to call `ObDereferenceObject` on all exit paths, the object's reference count becomes permanently elevated (memory leak) or, if another path does an extra dereference, the object is freed prematurely while still in use. Project Zero's "Hunting for Bugs in Windows Mini-Filter Drivers" (2021) found similar reference leak bugs in filesystem filter drivers.

---

#### `handle_force_access_check_added`

| Field | Value |
|---|---|
| Category | `object_management` |
| Confidence | 0.90 |
| Base Score Weight | 5.0 |
| Required Signals | `sink_group: handle_validation`, `change_type: hardening_added`, `hardening_kind: force_access_check` |

**What it detects:** The `OBJ_FORCE_ACCESS_CHECK` flag was added to `OBJECT_ATTRIBUTES` to enforce access checks on handle operations performed on behalf of user-mode callers.

**Example patch:**
```c
// BEFORE:
  InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);

// AFTER:
+ InitializeObjectAttributes(&ObjectAttributes, &Name,
+     OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK, NULL, NULL);
```

**Why it matters:** Microsoft's security model documentation states that handles created by a user-mode component and passed to the driver should not be trusted, and if the driver must manipulate handles on behalf of user-mode applications, it should use the `OBJ_FORCE_ACCESS_CHECK` attribute to verify that the application has the necessary access. Without this flag, the kernel performs the operation with the driver's elevated privileges instead of the caller's, allowing privilege escalation through handle operations. Project Zero's "Access Mode Mismatch in IO Manager" research documented this exact pattern.

---

### String Handling Rules

#### `safe_string_function_replacement`

| Field | Value |
|---|---|
| Category | `string_handling` |
| Confidence | 0.88 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: string_copy`, `change_type: hardening_added`, `hardening_kind: safe_string_replacement` |

**What it detects:** An unsafe string function (`wcscpy`, `strcpy`, `strcat`, `sprintf`) was replaced with a bounded safe string variant (`RtlStringCbCopyW`, `RtlStringCchCatA`, `RtlStringCbPrintfW`, etc.).

**Example patch:**
```c
// BEFORE: unbounded copy
  wcscpy(Destination, Source);

// AFTER: bounded copy with size limit
+ RtlStringCbCopyW(Destination, DestSize, Source);
```

**Why it matters:** The Windows kernel-mode safe string library was specifically designed to prevent buffer overflows from string operations. Microsoft's documentation states that "safe string functions are intended to replace their built-in C/C++ counterparts" because the unsafe versions do not receive the size of the destination buffer, making overflow inevitable when input exceeds the buffer. Numerous kernel buffer overflow CVEs across all Windows driver types are caused by unbounded string copies. The safe string functions enforce boundary checks by requiring the destination buffer size as a parameter.

---

#### `unicode_string_length_validation_added`

| Field | Value |
|---|---|
| Category | `string_handling` |
| Confidence | 0.86 |
| Base Score Weight | 4.0 |
| Required Signals | `change_type: guard_added`, `guard_kind: length_check` |

**What it detects:** Validation was added to a `UNICODE_STRING` to check that `Length <= MaximumLength` and/or that `Length` is properly aligned to `sizeof(WCHAR)`.

**Example patch:**
```c
// ADDED:
+ if (UserString.Length > UserString.MaximumLength) {
+     return STATUS_INVALID_PARAMETER;
+ }
+ if (UserString.Length % sizeof(WCHAR) != 0) {
+     return STATUS_INVALID_PARAMETER;
+ }
  RtlCopyUnicodeString(&Destination, &UserString);
```

**Why it matters:** `UNICODE_STRING` structures received from user mode can have their `Length` and `MaximumLength` fields set to arbitrary values. If `Length` exceeds `MaximumLength`, or if the buffer pointer is NULL while `Length` is non-zero, string operations like `RtlCopyUnicodeString` will read past the end of the buffer. Misaligned `Length` values (not a multiple of 2) can cause alignment faults or incorrect character processing. Validating these fields before use prevents out-of-bounds reads and writes in kernel string operations.

---

### Pool Hardening Rules

#### `pool_type_nx_migration`

| Field | Value |
|---|---|
| Category | `pool_hardening` |
| Confidence | 0.85 |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: pool_alloc`, `change_type: hardening_added`, `hardening_kind: pool_type_hardening` |

**What it detects:** A pool allocation was migrated from executable `NonPagedPool` to non-executable `NonPagedPoolNx`.

**Example patch:**
```c
// BEFORE: executable pool
  Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, TAG);

// AFTER: non-executable pool
+ Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, Size, TAG);
```

**Why it matters:** Microsoft's NX pool documentation states that "instances of the NonPagedPool pool type should be replaced by either NonPagedPoolNx or NonPagedPoolExecute." Allocations from executable pool memory allow attackers who achieve a pool overflow to write and execute shellcode directly in the overflowed buffer. Migrating to `NonPagedPoolNx` marks pool memory as non-executable, requiring attackers to use ROP chains instead of direct code execution, significantly increasing exploitation difficulty. Connor McGarr's research on "Swimming In The (Kernel) Pool" demonstrated how NX pool complicates kernel pool exploitation.

---

#### `deprecated_pool_api_replacement`

| Field | Value |
|---|---|
| Category | `pool_hardening` |
| Confidence | 0.80 |
| Base Score Weight | 2.5 |
| Required Signals | `sink_group: pool_alloc`, `change_type: hardening_added`, `hardening_kind: pool_type_hardening` |

**What it detects:** The deprecated `ExAllocatePoolWithTag` was replaced with `ExAllocatePool2`, which zeros memory by default to prevent uninitialized memory disclosure.

**Example patch:**
```c
// BEFORE: deprecated, does not zero memory
  Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, Size, TAG);

// AFTER: modern API, zeros by default
+ Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, TAG);
```

**Why it matters:** MSRC's 2020 initiative to "solve uninitialized kernel pool memory on Windows" identified that uninitialized pool allocations are a major source of information disclosure vulnerabilities. `ExAllocatePool2` zeros allocations by default, deterministically preventing this entire vulnerability class rather than relying on static analysis or code review to find each instance. Microsoft's documentation explicitly states that `ExAllocatePoolWithTag` is deprecated starting with Windows 10 version 2004. The moderate confidence (0.80) reflects that this can be routine API modernization rather than a targeted security fix.

---

#### `pool_allocation_null_check_added`

| Field | Value |
|---|---|
| Category | `pool_hardening` |
| Confidence | 0.78 |
| Base Score Weight | 2.5 |
| Required Signals | `sink_group: pool_alloc`, `change_type: guard_added`, `guard_kind: null_check`, `proximity: near_sink` |

**What it detects:** A NULL check was added after a pool allocation to prevent NULL pointer dereference when allocation fails.

**Example patch:**
```c
  Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, TAG);
// ADDED:
+ if (Buffer == NULL) {
+     return STATUS_INSUFFICIENT_RESOURCES;
+ }
  RtlCopyMemory(Buffer, Source, Size);
```

**Why it matters:** Pool allocations can fail when system memory is low. If the driver does not check for NULL, it dereferences a NULL pointer, causing a system bugcheck (BSOD) -- a denial-of-service condition that an attacker can trigger by exhausting system memory. While NULL dereferences are generally not exploitable in kernel mode on modern Windows (due to NULL page protections), the BSOD itself constitutes a denial of service. The lower confidence (0.78) reflects that this is often defensive coding rather than fixing a specific vulnerability.

---

### Crypto Hardening Rules

#### `secure_zero_memory_added`

| Field | Value |
|---|---|
| Category | `crypto_hardening` |
| Confidence | 0.82 |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: memory_zeroing`, `change_type: hardening_added`, `hardening_kind: secure_zero` |

**What it detects:** `RtlSecureZeroMemory` was added to wipe sensitive data (cryptographic keys, passwords, authentication tokens) before freeing memory, using a zeroing function that cannot be optimized away by the compiler.

**Example patch:**
```c
// BEFORE: regular zeroing (may be optimized away)
  RtlZeroMemory(KeyBuffer, KeySize);
  ExFreePoolWithTag(KeyBuffer, TAG);

// AFTER: guaranteed non-optimizable wipe
+ RtlSecureZeroMemory(KeyBuffer, KeySize);
  ExFreePoolWithTag(KeyBuffer, TAG);
```

**Why it matters:** When sensitive data like cryptographic keys or passwords is stored in kernel memory, it should be zeroed before the memory is freed or reused. Regular `RtlZeroMemory` calls can be optimized away by the compiler if it determines the buffer is not read after zeroing (since the next operation is free). `RtlSecureZeroMemory` uses a volatile pointer to prevent this optimization, ensuring sensitive data is actually wiped. Without this, freed memory containing key material can be reallocated to another process, leaking cryptographic secrets.

---

#### `constant_time_comparison_added`

| Field | Value |
|---|---|
| Category | `crypto_hardening` |
| Confidence | 0.80 |
| Base Score Weight | 3.5 |
| Required Signals | `change_type: hardening_added`, `hardening_kind: constant_time_compare` |

**What it detects:** An early-exit byte comparison (using `memcmp`, `RtlCompareMemory`, or `RtlEqualMemory`) was replaced with a constant-time XOR-accumulate pattern for cryptographic values.

**Example patch:**
```c
// BEFORE: early-exit comparison (timing side-channel)
  if (RtlCompareMemory(Hash1, Hash2, HASH_SIZE) == HASH_SIZE) {

// AFTER: constant-time comparison
+ ULONG Result = 0;
+ for (i = 0; i < HASH_SIZE; i++) {
+     Result |= Hash1[i] ^ Hash2[i];
+ }
+ if (Result == 0) {
```

**Why it matters:** Standard comparison functions like `memcmp` exit early on the first differing byte, causing the comparison to take variable time depending on how many bytes match. An attacker who can measure this timing difference (through repeated requests) can recover the expected value one byte at a time. For cryptographic operations like HMAC verification, password comparison, or token validation, this timing side-channel allows authentication bypass. Constant-time comparison ensures the operation takes the same amount of time regardless of the input, eliminating the side-channel.

---

### Error Path Hardening Rules

#### `error_path_cleanup_added`

| Field | Value |
|---|---|
| Category | `error_path_hardening` |
| Confidence | 0.80 |
| Base Score Weight | 3.0 |
| Required Signals | `change_type: hardening_added`, `hardening_kind: error_cleanup` |

**What it detects:** Resource cleanup (free, release, dereference) was added on an error path that previously leaked resources.

**Example patch:**
```c
  Buffer1 = ExAllocatePool2(...);
  Buffer2 = ExAllocatePool2(...);
  if (!NT_SUCCESS(Status)) {
// ADDED:
+     if (Buffer1) ExFreePoolWithTag(Buffer1, TAG);
+     if (Buffer2) ExFreePoolWithTag(Buffer2, TAG);
      return Status;
  }
```

**Why it matters:** Resource leaks on error paths are extremely common in kernel drivers and lead to multiple security issues. Pool memory leaks can be triggered repeatedly by an attacker to exhaust kernel pool, causing denial of service. Object reference leaks prevent objects from being freed, consuming resources indefinitely. Lock leaks on error paths can cause deadlocks. In some cases, leaked resources (such as dangling references to objects) create exploitable conditions where a later operation encounters unexpected state. The confidence is 0.80 because error path cleanup can also be a pure reliability fix.

---

#### `goto_cleanup_pattern_added`

| Field | Value |
|---|---|
| Category | `error_path_hardening` |
| Confidence | 0.75 |
| Base Score Weight | 2.5 |
| Required Signals | `change_type: hardening_added`, `hardening_kind: goto_cleanup` |

**What it detects:** A centralized `goto` cleanup pattern was added to replace direct error returns, ensuring all resources are properly released on every exit path.

**Example patch:**
```c
// BEFORE: direct return on error (may leak resources)
  if (!NT_SUCCESS(Status)) return Status;

// AFTER: goto centralized cleanup
+ if (!NT_SUCCESS(Status)) goto Cleanup;
  ...
+ Cleanup:
+     if (Buffer) ExFreePoolWithTag(Buffer, TAG);
+     if (Lock) ExReleaseResourceLite(&Lock);
+     return Status;
```

**Why it matters:** The `goto` cleanup pattern is a standard C idiom for ensuring consistent resource cleanup across all error paths. When a function acquires multiple resources (allocations, locks, references), each error check must release all previously-acquired resources. Without centralized cleanup, it is easy to miss releasing a resource on one of many error paths. While this is primarily a code quality improvement, in kernel drivers these missed cleanups translate directly to exploitable conditions (pool exhaustion, deadlocks, UAF). The lower confidence (0.75) reflects that this refactoring is often preventive rather than fixing an active vulnerability.

---

#### `irp_completion_status_fix`

| Field | Value |
|---|---|
| Category | `error_path_hardening` |
| Confidence | 0.76 |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: irp_completion`, `change_type: hardening_added`, `hardening_kind: completion_status_fix` |

**What it detects:** An IRP completion was fixed to propagate the correct status code, or a guard was added to prevent double completion.

**Example patch:**
```c
// BEFORE: always completes with success (masks errors)
  Irp->IoStatus.Status = STATUS_SUCCESS;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

// AFTER: propagates actual error status
+ Irp->IoStatus.Status = Status;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
```

**Why it matters:** Completing an IRP with an incorrect status (e.g., `STATUS_SUCCESS` when the operation actually failed) can cause the I/O Manager and user-mode code to act on invalid data. If the IRP is completed with success but the output buffer was not populated, the user-mode caller reads stale kernel data (information disclosure). Double-completing an IRP (calling `IoCompleteRequest` twice) causes the I/O Manager to corrupt its internal tracking structures, leading to use-after-free or pool corruption. Both patterns are exploitable and have been the subject of real-world vulnerabilities.

---

### DoS Hardening Rules

#### `recursion_depth_limit_added`

| Field | Value |
|---|---|
| Category | `dos_hardening` |
| Confidence | 0.82 |
| Base Score Weight | 3.5 |
| Required Signals | `change_type: guard_added`, `guard_kind: depth_limit` |

**What it detects:** A recursion depth limit or `IoGetRemainingStackSize` check was added to prevent stack exhaustion from unbounded recursion.

**Example patch:**
```c
// BEFORE: unbounded recursion
  NTSTATUS ProcessNode(PNODE Node) {
      ProcessNode(Node->Left);
      ProcessNode(Node->Right);
  }

// AFTER: depth limited
+ NTSTATUS ProcessNode(PNODE Node, ULONG Depth) {
+     if (Depth > MAX_RECURSION_DEPTH) return STATUS_STACK_OVERFLOW;
+     ProcessNode(Node->Left, Depth + 1);
+     ProcessNode(Node->Right, Depth + 1);
  }
```

**Why it matters:** Uncontrolled recursion (CWE-674) in kernel code is particularly dangerous because kernel stacks are limited in size (typically 12-24 KB on Windows). An attacker who can control the input data structure (e.g., a deeply nested tree or linked list from an IOCTL buffer) can trigger unlimited recursion that exhausts the kernel stack, causing STATUS_STACK_OVERFLOW and a system bugcheck. Microsoft's kernel-mode hardware-enforced stack protection provides some mitigation, but prevention through depth limits is the primary defense. The `IoGetRemainingStackSize` API allows drivers to check available stack space before recursing.

---

#### `loop_iteration_bound_added`

| Field | Value |
|---|---|
| Category | `dos_hardening` |
| Confidence | 0.75 |
| Base Score Weight | 2.5 |
| Required Signals | `change_type: guard_added`, `guard_kind: index_bounds` |

**What it detects:** An iteration counter and maximum bound were added to a loop to prevent infinite loop denial of service.

**Example patch:**
```c
// BEFORE: unbounded while loop
  while (pEntry != NULL) {
      pEntry = pEntry->Next;
  }

// AFTER: bounded
+ ULONG Count = 0;
  while (pEntry != NULL) {
+     if (++Count > MAX_ENTRIES) break;
      pEntry = pEntry->Next;
  }
```

**Why it matters:** Linked list traversals in kernel drivers are vulnerable to infinite loops when an attacker can corrupt the list to create a cycle, or when the list comes from user-controlled input with no length limit. An infinite loop at elevated IRQL (e.g., while holding a spinlock at DISPATCH_LEVEL) is particularly devastating because it blocks the processor indefinitely and hangs the system. Adding a maximum iteration bound ensures the loop terminates even with malicious input. The lower confidence (0.75) reflects that loop bounds are sometimes added for performance rather than security.

---

#### `resource_quota_check_added`

| Field | Value |
|---|---|
| Category | `dos_hardening` |
| Confidence | 0.80 |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: pool_alloc`, `change_type: guard_added`, `guard_kind: length_check`, `proximity: near_sink` |

**What it detects:** An upper bound check was added on a user-supplied allocation size to prevent resource exhaustion through unbounded allocations.

**Example patch:**
```c
// ADDED:
+ if (UserRequestedSize > MAX_ALLOWED_SIZE) {
+     return STATUS_INVALID_PARAMETER;
+ }
  Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, UserRequestedSize, TAG);
```

**Why it matters:** Without an upper bound on allocation sizes, an attacker can request arbitrarily large allocations through an IOCTL, rapidly exhausting kernel pool memory. Non-paged pool exhaustion is particularly severe because it affects the entire system, potentially causing other drivers and the kernel itself to fail allocations. Even if individual allocations succeed, repeatedly allocating large buffers without a quota creates a denial-of-service condition. Adding a maximum size check limits the attacker's ability to consume system resources.

---

### NDIS Hardening Rules

#### `oid_request_validation_added`

| Field | Value |
|---|---|
| Category | `ndis_hardening` |
| Confidence | 0.88 |
| Base Score Weight | 5.0 |
| Required Signals | `sink_group: ndis_operations`, `change_type: guard_added`, `guard_kind: oid_validation` |

**What it detects:** NULL check and length validation were added for NDIS OID request `InformationBuffer` and `InformationBufferLength`.

**Example patch:**
```c
// ADDED:
+ if (OidRequest == NULL || Length < sizeof(MY_OID_STRUCT)) {
+     NdisRequest->DATA.SET_INFORMATION.BytesNeeded = sizeof(MY_OID_STRUCT);
+     return NDIS_STATUS_INVALID_LENGTH;
+ }
```

**Why it matters:** CVE-2021-28476 (CVSS 9.9) is a critical vulnerability in Hyper-V's virtual network switch driver (vmswitch.sys) caused by vmswitch never validating the value of `OidRequest`, allowing a NULL pointer dereference that leads to remote code execution or denial of service from a guest VM. CVE-2018-8342 is an EoP in NDIS where ndis.sys fails to check the length of a buffer prior to copying memory. CVE-2024-38048 is an NDIS denial of service vulnerability. Microsoft's documentation on "Vulnerability to Security Attacks in NDIS Drivers" explicitly warns that network drivers must validate all OID request parameters.

---

#### `nbl_chain_length_validation_added`

| Field | Value |
|---|---|
| Category | `ndis_hardening` |
| Confidence | 0.84 |
| Base Score Weight | 4.0 |
| Required Signals | `sink_group: ndis_operations`, `change_type: guard_added`, `guard_kind: length_check`, `proximity: near_sink` |

**What it detects:** A bounds check was added comparing `NET_BUFFER_DATA_LENGTH` against the actual MDL byte count to prevent out-of-bounds access in NBL processing.

**Example patch:**
```c
// BEFORE: trusts NBL metadata
  DataLength = NET_BUFFER_DATA_LENGTH(NetBuffer);
  RtlCopyMemory(Destination, MdlData, DataLength);

// AFTER: validated against MDL
+ if (DataLength > MdlByteCount) {
+     DataLength = MdlByteCount;
+ }
  RtlCopyMemory(Destination, MdlData, DataLength);
```

**Why it matters:** CVE-2015-6098 is a buffer overflow in the NDIS implementation caused by insufficient validation of packet data lengths. Network drivers frequently process chains of NET_BUFFER_LIST structures where the metadata (reported data length) may not match the actual underlying MDL byte count. When the driver trusts the metadata and copies `DataLength` bytes from the MDL, but the MDL only contains `MdlByteCount` bytes, the result is an out-of-bounds read or write. Attackers on the network can craft malicious packets with mismatched metadata to exploit this condition.

---

### Filesystem Filter Rules

#### `flt_context_reference_leak_fix`

| Field | Value |
|---|---|
| Category | `filesystem_filter` |
| Confidence | 0.84 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: filesystem_filter`, `change_type: hardening_added`, `hardening_kind: flt_context_release` |

**What it detects:** A missing `FltReleaseContext` was added on an error or early-return path to fix a minifilter context reference leak.

**Example patch:**
```c
  Status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, &StreamContext);
  if (NT_SUCCESS(Status)) {
      if (SomeCondition) {
// ADDED:
+         FltReleaseContext(StreamContext);
          return STATUS_UNSUCCESSFUL;
      }
      FltReleaseContext(StreamContext);
  }
```

**Why it matters:** Google Project Zero's 2021 research on "Hunting for Bugs in Windows Mini-Filter Drivers" systematically found reference leak bugs in filesystem filter drivers. When a minifilter calls `FltGetStreamContext` (or any `FltGet*Context` variant), it receives a reference-counted context pointer. If the driver returns without calling `FltReleaseContext`, the context is leaked -- its reference count never reaches zero, so it is never freed. Repeated triggering of this leak exhausts the non-paged pool. In some cases, the leaked context contains pointers that become stale, creating use-after-free conditions when the context is later cleaned up.

---

#### `flt_create_race_mitigation`

| Field | Value |
|---|---|
| Category | `filesystem_filter` |
| Confidence | 0.86 |
| Base Score Weight | 4.5 |
| Required Signals | `sink_group: filesystem_filter`, `change_type: hardening_added`, `hardening_kind: buffer_capture` |

**What it detects:** A TOCTOU vulnerability in `IRP_MJ_CREATE` handling was fixed by capturing a mapped buffer before validation, preventing an attacker from modifying the buffer between validation and use.

**Example patch:**
```c
// BEFORE: validates mapped buffer then uses it (race window)
  if (!ValidatePath(MappedBuffer)) return STATUS_ACCESS_DENIED;
  FltCreateFileEx2(..., MappedBuffer, ...);

// AFTER: capture buffer contents first
+ RtlCopyMemory(CapturedPath, MappedBuffer, PathLength);
+ if (!ValidatePath(CapturedPath)) return STATUS_ACCESS_DENIED;
+ FltCreateFileEx2(..., CapturedPath, ...);
```

**Why it matters:** CVE-2025-55680 is a TOCTOU vulnerability in the Windows Cloud Files Minifilter driver (CVSS 7.8) that allows local attackers to escalate privileges to SYSTEM. The vulnerability exists in `HsmpOpCreatePlaceholders()`, which maps a user-supplied buffer into kernel space (sharing physical memory), validates the filename, and then calls `FltCreateFileEx2`. Between validation and creation, the attacker modifies the mapped buffer to inject a directory traversal character, causing the driver to create files in privileged locations. CVE-2020-17136 was a similar earlier vulnerability in the same component. Exodus Intelligence discovered this vulnerability and Microsoft fixed it by capturing the buffer contents before validation.

---

### PnP/Power Rules

#### `surprise_removal_guard_added`

| Field | Value |
|---|---|
| Category | `pnp_power` |
| Confidence | 0.78 |
| Base Score Weight | 3.0 |
| Required Signals | `change_type: guard_added`, `guard_kind: removal_check` |

**What it detects:** A device-removed flag check was added before I/O dispatch to prevent use-after-remove conditions.

**Example patch:**
```c
// ADDED:
+ if (DeviceExtension->DeviceRemoved) {
+     Irp->IoStatus.Status = STATUS_DELETE_PENDING;
+     IoCompleteRequest(Irp, IO_NO_INCREMENT);
+     return STATUS_DELETE_PENDING;
+ }
  Status = IoCallDriver(DeviceExtension->LowerDevice, Irp);
```

**Why it matters:** Surprise removal occurs when a device is physically or logically detached without notice. If the driver continues to dispatch I/O to a removed device, it accesses freed device extension memory and lower device objects that no longer exist, creating use-after-free conditions. PnP drivers must check for removal state before processing any IRP and return `STATUS_DELETE_PENDING` for removed devices. The moderate confidence (0.78) reflects that removal checks are part of standard PnP handling and are sometimes added during routine PnP compliance work rather than fixing an active vulnerability.

---

#### `power_state_validation_added`

| Field | Value |
|---|---|
| Category | `pnp_power` |
| Confidence | 0.74 |
| Base Score Weight | 2.5 |
| Required Signals | `change_type: guard_added`, `guard_kind: power_state_check` |

**What it detects:** A power state validation check was added before device I/O, ensuring the device is in the working state (`PowerDeviceD0`) before performing operations.

**Example patch:**
```c
// ADDED:
+ if (DeviceExtension->DevicePowerState != PowerDeviceD0) {
+     return STATUS_DEVICE_NOT_READY;
+ }
  Status = PerformDeviceIO(DeviceExtension);
```

**Why it matters:** When a device is in a low-power state (D1, D2, or D3), its hardware may not be accessible. Attempting I/O to a device in a low-power state can cause hardware hangs, system bugchecks, or return corrupted data. If the device's memory-mapped registers are not accessible in the low-power state, register reads may return all-ones (0xFFFFFFFF), which the driver may interpret as valid data, leading to incorrect behavior or memory corruption. The lower confidence (0.74) reflects that this is often a reliability fix rather than a security fix.

---

#### `io_remove_lock_added`

| Field | Value |
|---|---|
| Category | `pnp_power` |
| Confidence | 0.80 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: pnp_power`, `change_type: hardening_added`, `hardening_kind: remove_lock` |

**What it detects:** `IoAcquireRemoveLock`/`IoReleaseRemoveLock` was added to protect against races between PnP removal and in-flight I/O operations.

**Example patch:**
```c
// ADDED:
+ Status = IoAcquireRemoveLock(&DeviceExtension->RemoveLock, Irp);
+ if (!NT_SUCCESS(Status)) {
+     Irp->IoStatus.Status = Status;
+     IoCompleteRequest(Irp, IO_NO_INCREMENT);
+     return Status;
+ }
  Status = IoCallDriver(NextDevice, Irp);
```

**Why it matters:** The remove lock mechanism prevents the driver from unloading or the device from being removed while I/O operations are in progress. Without it, there is a race window where `IRP_MN_REMOVE_DEVICE` can free the device extension and lower device object while another thread is still processing an IRP, creating a use-after-free condition. `IoAcquireRemoveLock` increments a reference count that `IRP_MN_REMOVE_DEVICE` waits for via `IoReleaseRemoveLockAndWait`. Adding this lock in a patch directly addresses a PnP removal race condition.

---

### DMA/MMIO Rules

#### `mmio_mapping_bounds_validation_added`

| Field | Value |
|---|---|
| Category | `dma_mmio` |
| Confidence | 0.90 |
| Base Score Weight | 5.5 |
| Required Signals | `sink_group: mmio_dma`, `change_type: guard_added`, `guard_kind: length_check`, `proximity: near_sink` |

**What it detects:** Physical address range validation was added before `MmMapIoSpace` to prevent arbitrary physical memory mapping.

**Example patch:**
```c
// ADDED:
+ if (!IsValidDevicePhysicalRange(PhysAddr, Length)) {
+     return STATUS_ACCESS_DENIED;
+ }
  MappedAddress = MmMapIoSpace(PhysAddr, Length, MmNonCached);
+ if (MappedAddress == NULL) {
+     return STATUS_INSUFFICIENT_RESOURCES;
+ }
```

**Why it matters:** `MmMapIoSpace` maps a physical address range into kernel virtual address space. If an attacker can control the physical address and length parameters (e.g., through an IOCTL), they can map arbitrary physical memory -- including other processes' private memory, kernel code, or hardware MMIO regions they should not access. The POPKORN research project found 24 drivers with `MmMapIoSpace` vulnerabilities where user-controlled physical addresses were mapped without validation. CVE-2025-0288 specifically exploits an IOCTL that passes user-controlled parameters directly to `MmMapIoSpace`, enabling arbitrary physical memory read/write. This has high confidence (0.90) because adding physical address validation before `MmMapIoSpace` is almost always a security fix.

---

#### `dma_buffer_bounds_check_added`

| Field | Value |
|---|---|
| Category | `dma_mmio` |
| Confidence | 0.82 |
| Base Score Weight | 4.0 |
| Required Signals | `sink_group: mmio_dma`, `change_type: guard_added`, `guard_kind: index_bounds` |

**What it detects:** A bounds check was added on indices or offsets used to access DMA-mapped memory regions.

**Example patch:**
```c
// ADDED:
+ if (HwOffset >= DmaBufferSize / sizeof(ULONG)) {
+     return STATUS_INVALID_PARAMETER;
+ }
  Value = DmaBuffer[HwOffset];
```

**Why it matters:** DMA common buffers are shared between the driver and hardware device. If indices or offsets into these buffers come from hardware registers or user-controlled input, an unchecked index can cause out-of-bounds access in kernel memory. For DMA scatter-gather operations, malicious hardware or corrupted descriptors can provide offsets that reference memory outside the DMA buffer, leading to arbitrary kernel memory read/write. Adding bounds checks on DMA buffer access indices prevents this class of vulnerability.

---

### WDF Hardening Rules

#### `wdf_request_buffer_size_check_added`

| Field | Value |
|---|---|
| Category | `wdf_hardening` |
| Confidence | 0.88 |
| Base Score Weight | 4.5 |
| Required Signals | `sink_group: wdf_operations`, `change_type: guard_added`, `guard_kind: sizeof_check`, `proximity: near_sink` |

**What it detects:** The `MinimumRequiredLength` parameter of `WdfRequestRetrieveInputBuffer`/`WdfRequestRetrieveOutputBuffer` was changed from 0 to `sizeof(struct)` to enforce minimum buffer size.

**Example patch:**
```c
// BEFORE: no minimum size check (accepts any size)
  Status = WdfRequestRetrieveInputBuffer(Request, 0, &Buffer, &Length);

// AFTER: minimum size enforced
+ Status = WdfRequestRetrieveInputBuffer(Request, sizeof(MY_INPUT), &Buffer, &Length);
+ if (!NT_SUCCESS(Status)) {
+     WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
+     return;
+ }
```

**Why it matters:** WDF provides the `MinimumRequiredLength` parameter specifically to prevent the buffer undersize vulnerability class at the framework level. When set to 0, the framework accepts any buffer size, including empty buffers. The driver then casts the buffer to a structure pointer and reads fields past the end of the allocation. Changing the parameter from 0 to `sizeof(struct)` is the WDF-idiomatic equivalent of adding an `InputBufferLength < sizeof(...)` check in WDM. This is a very common vulnerability pattern in KMDF drivers and the fix is highly distinctive.

---

#### `wdf_request_completion_guard_added`

| Field | Value |
|---|---|
| Category | `wdf_hardening` |
| Confidence | 0.76 |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: wdf_operations`, `change_type: guard_added`, `guard_kind: null_check` |

**What it detects:** A guard was added to prevent double completion of a WDF request, which occurs when `WdfRequestComplete` is called more than once on the same request object.

**Example patch:**
```c
// ADDED:
+ BOOLEAN Completed = FALSE;
  if (!NT_SUCCESS(Status)) {
+     if (!Completed) {
          WdfRequestComplete(Request, Status);
+         Completed = TRUE;
+     }
  }
```

**Why it matters:** Double-completing a WDF request causes the framework to reference a request object that has already been returned to the free pool, creating a use-after-free condition in the WDF internal tracking structures. In complex drivers with multiple asynchronous completion paths (timer callbacks, cancellation routines, I/O completion callbacks), it is easy for two paths to race and both attempt to complete the same request. Adding a completion tracking guard prevents this race. The moderate confidence (0.76) reflects that completion guards are sometimes added during code review or testing rather than in response to an active vulnerability.

---

## Sink Groups

Sinks are dangerous API symbols. When a patch adds guards near sinks, it becomes high-signal for vulnerability detection.

| Sink Group | Symbol Count | Sink Bonus | Description |
|---|---|---|---|
| `memory_copy` | 6 | +1.5 | `RtlCopyMemory`, `memcpy`, `memmove`, `RtlMoveMemory`, `RtlCopyBytes`, `RtlCopyMappedMemory` |
| `string_copy` | 18 | +0.8 | `RtlStringCb*`, `RtlStringCch*`, `strcpy`, `wcscpy`, `strncpy`, `wcsncpy`, `strcat`, `wcscat`, `sprintf`, `swprintf` |
| `pool_alloc` | 7 | +1.2 | `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExAllocatePool2/3`, `ExAllocatePoolZero`, quota variants |
| `pool_free` | 2 | +1.0 | `ExFreePool`, `ExFreePoolWithTag` |
| `user_probe` | 5 | +1.5 | `ProbeForRead`, `ProbeForWrite`, `ProbeForReadGeneric`, `ProbeForWriteGeneric`, `ExGetPreviousMode` |
| `io_sanitization` | 9 | +1.0 | `RtlULongAdd/Sub/Mult`, `RtlULongLongAdd/Mult`, `RtlSizeTAdd/Mult`, `RtlUIntPtrAdd/Sub` |
| `exceptions` | 3 | +0.6 | `__try`, `__except`, `ExRaiseAccessViolation` |
| `refcounting` | 5 | +0.4 | `InterlockedIncrement/Decrement/Exchange/CompareExchange/Add` |
| `synchronization` | 15 | +0.6 | `KeAcquireSpinLock*`, `KeReleaseSpinLock*`, `ExAcquireFastMutex`, `ExAcquireResourceExclusiveLite`, `ExAcquireResourceSharedLite`, `ExReleaseResourceLite`, `KeEnterCriticalRegion`, `KeLeaveCriticalRegion`, `KeWaitForSingleObject`, `KeWaitForMutexObject` |
| `object_management` | 7 | +0.8 | `ObReferenceObject*`, `ObDereferenceObject*`, `ObReferenceObjectByHandle`, `ObReferenceObjectByPointer` |
| `handle_validation` | 8 | +1.0 | `ObReferenceObjectByHandle`, `OBJ_FORCE_ACCESS_CHECK`, `OBJ_KERNEL_HANDLE`, `InitializeObjectAttributes`, `ZwOpenKey`, `ZwCreateKey`, `ZwCreateFile`, `ZwOpenFile` |
| `authorization` | 5 | +1.2 | `SeSinglePrivilegeCheck`, `SePrivilegeCheck`, `SeAccessCheck`, `SeFreePrivileges`, `IoCheckEaBufferValidity` |
| `mdl_operations` | 6 | +1.2 | `MmGetSystemAddressForMdl`, `MmGetSystemAddressForMdlSafe`, `MmProbeAndLockPages`, `MmUnlockPages`, `IoAllocateMdl`, `IoFreeMdl` |
| `memory_zeroing` | 6 | +0.6 | `RtlZeroMemory`, `RtlSecureZeroMemory`, `RtlSecureZeroMemory2`, `SecureZeroMemory`, `RtlFillMemory`, `memset` |
| `ndis_operations` | 6 | +1.0 | `NdisGetDataBuffer`, `NdisQueryMdl`, `NdisMOidRequestComplete`, `NET_BUFFER_DATA_LENGTH`, `InformationBuffer`, `InformationBufferLength` |
| `mmio_dma` | 5 | +1.5 | `MmMapIoSpace`, `MmMapIoSpaceEx`, `MmUnmapIoSpace`, `AllocateCommonBuffer`, `GetScatterGatherList` |
| `filesystem_filter` | 8 | +0.8 | `FltGetStreamContext`, `FltGetStreamHandleContext`, `FltGetInstanceContext`, `FltGetVolumeContext`, `FltReleaseContext`, `FltReferenceContext`, `FltCreateFileEx2`, `FltCreateFile` |
| `pnp_power` | 6 | +0.6 | `IoAcquireRemoveLock`, `IoReleaseRemoveLock`, `IoReleaseRemoveLockAndWait`, `IoInitializeRemoveLock`, `PoSetPowerState`, `PoStartNextPowerIrp` |
| `wdf_operations` | 6 | +0.8 | `WdfRequestRetrieveInputBuffer`, `WdfRequestRetrieveOutputBuffer`, `WdfRequestRetrieveInputMemory`, `WdfRequestComplete`, `WdfRequestCompleteWithInformation`, `WdfRequestCompleteWithPriorityBoost` |
| `device_security` | 4 | +1.0 | `IoCreateDevice`, `IoCreateDeviceSecure`, `IoIs32bitProcess`, `FILE_DEVICE_SECURE_OPEN` |
| `irp_cancel` | 5 | +0.4 | `IoCsqInsertIrp`, `IoCsqInsertIrpEx`, `IoCsqRemoveIrp`, `IoCsqRemoveNextIrp`, `IoSetCancelRoutine` |
| `irp_completion` | 3 | +0.6 | `IoCompleteRequest`, `IoCallDriver`, `PoCallDriver` |

---

## Rule Evaluation Pipeline

The `SemanticRuleEngine.evaluate()` method processes each changed function through this pipeline:

### Step 1: Global Exclusion Check

Before evaluating any rules, the engine checks whether the diff is exclusively logging/tracing changes. If all added lines (up to 4) match exclusion patterns, the function is skipped.

**Exclusion patterns:**
- `logging_only` -- matches `DbgPrint`, `WPP`, `EventWrite`, `Etw`
- `refactor_only` -- matches code reordering/renaming without new guards

### Step 2: Sink Detection

Scans every line of the diff for sink symbols. Records:
- Which sink group matched
- The exact symbol name
- The line number in the diff
- Whether the line is added (`+`) or context

### Step 3: Guard Detection

Scans only added lines (`+` prefix) for guard/validation patterns. Each guard type has compiled regex patterns:

| Guard Type | What It Matches |
|---|---|
| `length_check` | `InputBufferLength <`, `sizeof() >`, `if (.*Len <` |
| `sizeof_check` | `sizeof(...)`, `RtlSizeT*` |
| `index_bounds` | `if (index < N)`, `idx >= count` |
| `null_check` | `if (ptr != NULL)`, `if (!ptr)`, `if (ptr)` |
| `null_assignment` | `ptr = NULL;`, `ptr = 0;` |
| `probe` | `ProbeForRead`, `ProbeForWrite` |
| `previous_mode_gate` | `ExGetPreviousMode`, `PreviousMode`, `KernelMode.*UserMode` |
| `seh_guard` | `__try`, `__except`, `ExRaiseAccessViolation` |
| `safe_math_helper` | `Rtl(ULong|SizeT|UIntPtr)(Add|Sub|Mult)`, `NT_SUCCESS(Rtl*` |
| `overflow_check` | `overflow`, `ULONG_MAX`, `SIZE_T_MAX`, `Rtl*Mult` |
| `refcount` | `Interlocked(Increment|Decrement|Exchange|CompareExchange)` |
| `spinlock` | `KeAcquireSpinLock`, `KeReleaseSpinLock`, `KeAcquireInStackQueuedSpinLock` |
| `mutex_resource` | `ExAcquireFastMutex`, `ExAcquireResourceExclusiveLite`, `ExAcquireResourceSharedLite`, `KeEnterCriticalRegion`, `KeWaitForSingleObject` |
| `buffer_capture` | Local variable assignment capturing user-mode buffer field |
| `cancel_safe` | `IoCsqInsertIrp`, `IoCsqRemoveIrp` |
| `object_type_check` | `ObjectType == ...`, `TypeTag == ...`, type field comparisons |
| `handle_type_validation` | Non-NULL ObjectType in `ObReferenceObjectByHandle`, `OBJ_FORCE_ACCESS_CHECK` |
| `wow64_check` | `IoIs32bitProcess`, `PsGetProcessWow64Process` |
| `privilege_check` | `SeSinglePrivilegeCheck`, `SeAccessCheck`, `SePrivilegeCheck` |
| `access_mode_fix` | `Irp->RequestorMode`, `OBJ_FORCE_ACCESS_CHECK`, `UserMode` |
| `buffer_zeroing` | `RtlZeroMemory`, `RtlSecureZeroMemory`, `memset(..., 0, ...)`, `= {0}` |
| `pointer_scrub` | Removal or zeroing of kernel pointer in output buffer |
| `default_case` | `default:` with error status return |
| `mdl_safe` | `MmGetSystemAddressForMdlSafe`, `MmProbeAndLockPages(...UserMode...)` |
| `pool_type_hardening` | `NonPagedPoolNx`, `ExAllocatePool2`, `POOL_FLAG_NON_PAGED` |
| `secure_zero` | `RtlSecureZeroMemory`, `SecureZeroMemory` |
| `constant_time_compare` | XOR-accumulate comparison loop pattern |
| `error_cleanup` | `ExFreePool*`/`ObDereferenceObject` in error branches |
| `goto_cleanup` | `goto Cleanup` with resource release block |
| `completion_status_fix` | Change in `IoStatus.Status` assignment, double-completion guard |
| `depth_limit` | `IoGetRemainingStackSize`, depth counter comparisons |
| `oid_validation` | `InformationBufferLength` checks, `NDIS_STATUS_INVALID_LENGTH` |
| `safe_string_replacement` | `RtlStringCb*`/`RtlStringCch*` replacing `strcpy`/`wcscpy`/`strcat` |
| `reference_balance` | `ObDereferenceObject` in error/cleanup paths |
| `force_access_check` | `OBJ_FORCE_ACCESS_CHECK`, `OBJ_KERNEL_HANDLE` |
| `device_acl` | `IoCreateDeviceSecure`, `FILE_DEVICE_SECURE_OPEN`, SDDL strings |
| `access_mask_reduction` | `KEY_READ` replacing `KEY_ALL_ACCESS` |
| `flt_context_release` | `FltReleaseContext` on error/early-return paths |
| `removal_check` | Device-removed flag checks, `STATUS_DELETE_PENDING` |
| `power_state_check` | `PowerDeviceD0`, `DevicePowerState` comparisons |
| `remove_lock` | `IoAcquireRemoveLock`, `IoReleaseRemoveLock` |

### Step 4: Per-Rule Signal Matching

Each rule defines `required_signals` -- a list of conditions that must ALL be satisfied:

| Signal Key | What It Checks |
|---|---|
| `sink_group: <group>` | At least one sink from the specified group exists in the diff |
| `change_type: guard_added` | At least one guard/validation type was detected in added lines |
| `guard_kind: <type>` | A specific guard type (e.g., `length_check`) was detected |
| `validation_kind: <type>` | Alias for guard_kind, used for user boundary rules |
| `hardening_kind: <type>` | Alias for guard_kind, used for lifetime/state rules |
| `proximity: <mode>` | Guard and sink are within required proximity (see below) |

If ANY required signal fails, the rule does not match.

### Step 5: Proximity Check

Proximity constraints ensure the guard is actually related to the sink, not just coincidentally present in the same function:

| Proximity Mode | Constraint | Typical Use |
|---|---|---|
| `near_sink` | Guard within 10 lines of sink | Bounds checks before memcpy |
| `immediately_after_sink` | Guard 0-3 lines after sink | NULL assignment after free |
| `before_sink` | Guard 1-10 lines before sink | Overflow check before alloc |

---

## Scoring Model

After rule evaluation, findings are scored to rank them by exploit relevance.

### Score Composition

```
final_score = (semantic_score + reachability_score + sink_score) - penalties
```

Clamped to `[0.0, 15.0]`.

### Semantic Score

```
semantic_score = rule_base_weight * rule_confidence * category_multiplier
```

**Rule base weights** (from `scoring.yaml`):

| Rule | Weight |
|---|---|
| `added_len_check_before_memcpy` | 6.0 |
| `probe_for_read_or_write_added` | 6.0 |
| `method_neither_probe_added` | 6.0 |
| `access_mode_enforcement_added` | 6.0 |
| `mdl_probe_access_mode_fix` | 6.0 |
| `alloc_size_overflow_check_added` | 5.5 |
| `privilege_check_added` | 5.5 |
| `handle_object_type_check_added` | 5.5 |
| `mmio_mapping_bounds_validation_added` | 5.5 |
| `null_after_free_added` | 5.0 |
| `previous_mode_gating_added` | 5.0 |
| `double_fetch_to_capture_fix` | 5.0 |
| `object_type_validation_added` | 5.0 |
| `handle_force_access_check_added` | 5.0 |
| `ioctl_input_size_validation_added` | 5.0 |
| `kernel_pointer_scrubbing_added` | 5.0 |
| `oid_request_validation_added` | 5.0 |
| `added_struct_size_validation` | 4.5 |
| `safe_size_math_helper_added` | 4.5 |
| `wow64_thunk_validation_added` | 4.5 |
| `buffer_zeroing_before_copy_added` | 4.5 |
| `flt_create_race_mitigation` | 4.5 |
| `wdf_request_buffer_size_check_added` | 4.5 |
| `guard_before_free_added` | 4.0 |
| `added_index_bounds_check` | 4.0 |
| `device_acl_hardening` | 4.0 |
| `ob_reference_balance_fix` | 4.0 |
| `mdl_safe_mapping_replacement` | 4.0 |
| `unicode_string_length_validation_added` | 4.0 |
| `nbl_chain_length_validation_added` | 4.0 |
| `dma_buffer_bounds_check_added` | 4.0 |
| `seh_guard_added_around_user_deref` | 3.5 |
| `spinlock_acquisition_added` | 3.5 |
| `mutex_or_resource_lock_added` | 3.5 |
| `stack_variable_initialization_added` | 3.5 |
| `output_length_truncation_added` | 3.5 |
| `safe_string_function_replacement` | 3.5 |
| `mdl_null_check_added` | 3.5 |
| `constant_time_comparison_added` | 3.5 |
| `recursion_depth_limit_added` | 3.5 |
| `flt_context_reference_leak_fix` | 3.5 |
| `io_remove_lock_added` | 3.5 |
| `interlocked_refcount_added` | 3.0 |
| `cancel_safe_irp_queue_added` | 3.0 |
| `registry_access_mask_hardened` | 3.0 |
| `pool_type_nx_migration` | 3.0 |
| `secure_zero_memory_added` | 3.0 |
| `error_path_cleanup_added` | 3.0 |
| `irp_completion_status_fix` | 3.0 |
| `resource_quota_check_added` | 3.0 |
| `surprise_removal_guard_added` | 3.0 |
| `wdf_request_completion_guard_added` | 3.0 |
| `deprecated_pool_api_replacement` | 2.5 |
| `pool_allocation_null_check_added` | 2.5 |
| `goto_cleanup_pattern_added` | 2.5 |
| `loop_iteration_bound_added` | 2.5 |
| `power_state_validation_added` | 2.5 |
| `ioctl_code_default_case_added` | 2.0 |

**Category multipliers:**

| Category | Multiplier |
|---|---|
| `user_boundary_check` | 1.10x |
| `type_confusion` | 1.10x |
| `authorization` | 1.10x |
| `ioctl_hardening` | 1.10x |
| `dma_mmio` | 1.10x |
| `bounds_check` | 1.05x |
| `int_overflow` | 1.05x |
| `lifetime_fix` | 1.05x |
| `race_condition` | 1.05x |
| `mdl_handling` | 1.05x |
| `object_management` | 1.05x |
| `ndis_hardening` | 1.05x |
| `wdf_hardening` | 1.05x |
| `info_disclosure` | 1.00x |
| `string_handling` | 1.00x |
| `filesystem_filter` | 1.00x |
| `state_hardening` | 0.95x |
| `pool_hardening` | 0.95x |
| `pnp_power` | 0.95x |
| `crypto_hardening` | 0.90x |
| `error_path_hardening` | 0.90x |
| `dos_hardening` | 0.90x |

### Reachability Score

```
reachability_score = reachability_bonus[class]
```

| Reachability Class | Bonus |
|---|---|
| `ioctl` | +4.0 |
| `irp` | +2.5 |
| `pnp` | +2.0 |
| `internal` | +0.5 |
| `unknown` | +0.0 |

When full reachability analysis (Stage 5) has not run, the engine uses `surface_area` heuristics as a proxy -- if the function code contains IOCTL-related strings, it approximates as `ioctl`.

### Sink Score

```
sink_score = sum(sink_bonus[group]) * min(1.0, semantic_confidence)
```

### Penalties

| Penalty Source | Values |
|---|---|
| Pairing decision | accept: 0, quarantine: -2.0, reject: -999 |
| Noise risk | low: 0, medium: -1.0, high: -2.5 |
| Matching quality | high: 0, medium: -0.8, low: -1.8 |

### Gating

Gates cap or drop findings that fail confidence thresholds:

| Gate | Threshold | Effect |
|---|---|---|
| Semantic confidence hard min | < 0.45 | Finding dropped entirely |
| Semantic confidence soft min | < 0.60 | Score capped at 5.0 |
| Matching confidence min | < 0.40 | Score capped at 3.0 |
| Reachability confidence soft min | < 0.55 | Reachability bonus multiplied by 0.70 |

---

## Rule YAML Schema

Each rule in `semantic_rules.yaml` must follow this structure:

```yaml
- rule_id: <snake_case_identifier>      # Stable, unique ID
  category: <category_id>               # One of the 22 categories
  confidence: <0.0-1.0>                 # Rule's inherent precision
  required_signals:                      # ALL must be satisfied
    - sink_group: <group_name>           # Optional: require sink presence
    - change_type: <type>                # guard_added | validation_added | hardening_added | post_free_hardening
    - guard_kind: <guard_type>           # Specific guard pattern to require
    - proximity: <mode>                  # near_sink | immediately_after_sink | before_sink
  excluded_patterns:                     # Global exclusions that apply
    - logging_only
    - refactor_only
  plain_english_summary: <string>        # Human-readable explanation
  report:                                # Fields for report generation
    sinks: [<sink_group>]
    added_checks: [<check_type>]
```

---

## Adding New Rules

To add a new semantic rule:

1. **Choose a category** from the 22 existing categories, or propose a new one in `semantic_rules.yaml` under `categories:`.

2. **Define required signals** -- what must be present in the diff for the rule to fire. Be conservative: require at least a `change_type` and a specific `guard_kind` or `sink_group`.

3. **Set confidence** based on expected precision:
   - 0.90-0.95 -- Very high precision, direct guard before known-dangerous sink
   - 0.85-0.90 -- High precision, clear security-relevant hardening
   - 0.78-0.85 -- Moderate precision, pattern is security-relevant but may occasionally match benign changes
   - 0.70-0.78 -- Lower precision, pattern is often benign but sometimes security-relevant

4. **Add guard patterns** if the rule uses a new guard type. Edit `_compile_guard_patterns()` in `rule_engine.py` to add regex patterns for the new guard type.

5. **Add sink symbols** if the rule references a new sink group. Edit `rules/sinks.yaml` to add the group and its symbols.

6. **Add scoring weight** in `rules/scoring.yaml` under `weights.semantic_rule_base`.

7. **Write tests** in `tests/unit/test_rule_engine.py` -- include both positive (rule should fire) and negative (rule should not fire) test cases.

---

## Output Format

When a rule matches, it produces a `RuleHit`:

```json
{
  "rule_id": "added_len_check_before_memcpy",
  "category": "bounds_check",
  "confidence": 0.92,
  "sinks": ["memory_copy"],
  "indicators": ["RtlCopyMemory", "InputBufferLength <"],
  "why_matters": "Added a length/bounds check before a memory copy operation.",
  "diff_snippet": "..."
}
```

After scoring, each finding gains additional fields:

```json
{
  "final_score": 8.42,
  "score_breakdown": {
    "semantic": 5.80,
    "reachability": 4.0,
    "sinks": 1.5,
    "penalties": 0.0,
    "gates": []
  }
}
```

---

## Design Principles

1. **Conservative** -- Fewer findings, higher confidence. If in doubt, do not trigger.
2. **Explainable** -- Every hit includes a plain-English rationale, detected sinks, and added checks.
3. **Sink-aware** -- Rules consider proximity to dangerous APIs, not just pattern presence.
4. **Transparent scoring** -- Every score is reproducible from `scoring.yaml` with a full breakdown.
5. **Non-speculative** -- Rules detect explicit code changes, not inferred intent.
