# autopiff_reachability.py
# Ghidra headless script for reachability analysis.
# Must be run via analyzeHeadless -postScript.
#
# Usage: analyzeHeadless <project> <name> -import <file> \
#        -postScript autopiff_reachability.py <out_json_path> [semantic_deltas_path]

import sys
import json
import os
from collections import deque

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Enum Constants (matching schema)
CLASS_IOCTL = "ioctl"
CLASS_IRP = "irp"
CLASS_PNP = "pnp"
CLASS_INTERNAL = "internal"
CLASS_UNKNOWN = "unknown"

EVID_DRIVER_ENTRY = "driver_entry_dispatch_setup"
EVID_MAJOR_ASSIGN = "major_function_assignment"
EVID_SWITCH_IOCTL = "switch_on_IoControlCode"
EVID_IOCTL_CASE = "ioctl_case_call"
EVID_DIRECT_CALL = "direct_callgraph_edge"
EVID_IOCTL_UNKNOWN = "ioctl_values_unknown"

# Major Function Indices (standard WDM)
IRP_MJ_CREATE = 0
IRP_MJ_CLOSE = 2
IRP_MJ_DEVICE_CONTROL = 14
IRP_MJ_INTERNAL_DEVICE_CONTROL = 15


def get_driver_entry(program, fm):
    """Find DriverEntry function by symbol name or entry point."""
    st = program.getSymbolTable()

    # Prefer real symbol
    syms = st.getSymbols("DriverEntry")
    if syms.hasNext():
        addr = syms.next().getAddress()
        f = fm.getFunctionAt(addr)
        if f:
            return f

    # Common label
    syms = st.getSymbols("entry")
    if syms.hasNext():
        addr = syms.next().getAddress()
        f = fm.getFunctionAt(addr)
        if f:
            return f

    # Fallback: iterate external entry points
    ep_iter = st.getExternalEntryPointIterator()
    while ep_iter.hasNext():
        addr = ep_iter.next()
        f = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if f:
            return f

    return None


def find_function_by_name(fm, name):
    """Find a function by exact name match."""
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        if f.getName() == name:
            return f
    return None


def extract_dispatch_table(program, fm, decomplib, monitor, driver_entry):
    """Extract IRP major function dispatch table from DriverEntry decompilation."""
    table = {
        "IRP_MJ_CREATE": None,
        "IRP_MJ_CLOSE": None,
        "IRP_MJ_DEVICE_CONTROL": None,
        "IRP_MJ_INTERNAL_DEVICE_CONTROL": None
    }
    if not driver_entry:
        return table

    res = decomplib.decompileFunction(driver_entry, 60, monitor)
    if not res or not res.decompileCompleted():
        return table

    c = res.getDecompiledFunction().getC()

    candidates = {
        "IRP_MJ_CREATE": IRP_MJ_CREATE,
        "IRP_MJ_CLOSE": IRP_MJ_CLOSE,
        "IRP_MJ_DEVICE_CONTROL": IRP_MJ_DEVICE_CONTROL,
        "IRP_MJ_INTERNAL_DEVICE_CONTROL": IRP_MJ_INTERNAL_DEVICE_CONTROL,
    }

    for name, idx in candidates.items():
        marker = "MajorFunction[{}]".format(idx)
        if marker not in c:
            continue

        for line in c.splitlines():
            if marker in line and "=" in line:
                rhs = line.split("=", 1)[1].strip().rstrip(";")
                # Strip casts like (PDRIVER_DISPATCH)
                rhs = rhs.replace("(", " ").replace(")", " ")
                parts = rhs.split()
                for tok in parts:
                    f = find_function_by_name(fm, tok)
                    if f:
                        table[name] = f.getName()
                        break
            if table[name]:
                break

    return table


def analyze_ioctls(fm, dispatch_table):
    """Analyze IOCTL handlers from dispatch table."""
    dc_name = dispatch_table.get("IRP_MJ_DEVICE_CONTROL")
    if dc_name:
        return [{
            "ioctl": "unknown",
            "handler": dc_name,
            "confidence": 0.70,
            "evidence": [EVID_IOCTL_UNKNOWN]
        }], dc_name
    return [], None


def get_direct_callees(program, fm, func):
    """Return list of directly called functions."""
    callees = set()
    if not func:
        return []

    inst_iter = program.getListing().getInstructions(func.getBody())
    for inst in inst_iter:
        if inst.getFlowType().isCall():
            refs = inst.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType().isCall():
                    addr = ref.getToAddress()
                    target_func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
                    if target_func:
                        callees.add(target_func)

    return list(callees)


def bfs_reachability(program, fm, start_functions, target_func, max_depth=2):
    """BFS from start functions to target, return (reachable, path, depth)."""
    if not start_functions or not target_func:
        return False, [], None

    target_ep = target_func.getEntryPoint()
    queue = deque()
    visited = set()

    for f in start_functions:
        if f:
            # Check if start function IS the target
            if f.getEntryPoint() == target_ep:
                return True, [f.getName()], 0
            queue.append((f, 0, [f.getName()]))
            visited.add(f.getEntryPoint())

    while queue:
        curr_func, depth, path = queue.popleft()

        if depth >= max_depth:
            continue

        callees = get_direct_callees(program, fm, curr_func)
        for callee in callees:
            ep = callee.getEntryPoint()
            if ep not in visited:
                visited.add(ep)
                new_path = list(path) + [callee.getName()]
                if ep == target_ep:
                    return True, new_path, depth + 1
                queue.append((callee, depth + 1, new_path))

    return False, [], None


def resolve_delta_function(fm, delta):
    """Resolve a delta dict to (name, function)."""
    name = delta.get("function") or delta.get("function_name") or delta.get("functionName")
    if not name:
        return None, None
    f = find_function_by_name(fm, name)
    return name, f


def tag_semantic_deltas(program, fm, deltas_path, dispatch_table, ioctl_handler_name, ioctls):
    """Tag each semantic delta with reachability information."""
    if not os.path.exists(deltas_path):
        return []

    with open(deltas_path, 'r') as f:
        deltas_data = json.load(f)

    # Extract the delta list from the stage-4 output structure
    if isinstance(deltas_data, dict):
        delta_list = deltas_data.get("deltas", [])
    elif isinstance(deltas_data, list):
        delta_list = deltas_data
    else:
        delta_list = []

    tags = []

    # Build root function lists
    ioctl_roots = []
    dc_name = dispatch_table.get("IRP_MJ_DEVICE_CONTROL")
    if dc_name:
        f = find_function_by_name(fm, dc_name)
        if f:
            ioctl_roots.append(f)

    irp_roots = []
    for k, v in dispatch_table.items():
        if k in ("IRP_MJ_DEVICE_CONTROL", "IRP_MJ_INTERNAL_DEVICE_CONTROL"):
            continue
        if v:
            f = find_function_by_name(fm, v)
            if f:
                irp_roots.append(f)

    for delta in delta_list:
        func_name, target_func = resolve_delta_function(fm, delta)
        if not func_name:
            continue

        if not target_func:
            tags.append({
                "function": func_name,
                "reachability_class": CLASS_UNKNOWN,
                "confidence": 0.0,
                "paths": [],
                "evidence": [EVID_DRIVER_ENTRY]
            })
            continue

        # Check IOCTL reachability (N=2)
        is_ioctl, path, depth = bfs_reachability(program, fm, ioctl_roots, target_func, 2)

        if is_ioctl:
            conf = 0.70
            if depth == 0:
                conf = 0.95
            elif depth == 1:
                conf = 0.85

            evid = [EVID_MAJOR_ASSIGN]
            if depth > 0:
                evid.append(EVID_DIRECT_CALL)
            evid.append(EVID_IOCTL_UNKNOWN)

            path_tokens = ["IRP_MJ_DEVICE_CONTROL"] + path

            tags.append({
                "function": target_func.getName(),
                "reachability_class": CLASS_IOCTL,
                "confidence": conf,
                "paths": [path_tokens],
                "evidence": evid
            })
            continue

        # Check IRP reachability (N=2)
        is_irp, path, depth = bfs_reachability(program, fm, irp_roots, target_func, 2)

        if is_irp:
            conf = 0.85
            if depth == 2:
                conf = 0.65

            evid = [EVID_MAJOR_ASSIGN]
            if depth > 0:
                evid.append(EVID_DIRECT_CALL)

            tags.append({
                "function": target_func.getName(),
                "reachability_class": CLASS_IRP,
                "confidence": conf,
                "paths": [path],
                "evidence": evid
            })
            continue

        # Default: unknown reachability
        tags.append({
            "function": target_func.getName(),
            "reachability_class": CLASS_UNKNOWN,
            "confidence": 0.0,
            "paths": [],
            "evidence": [EVID_DRIVER_ENTRY]
        })

    return tags


def export_decompiled_c(program, fm, decomplib, monitor, out_dir):
    """Export all functions as decompiled C with FUNCTION_START/END delimiters.

    Returns the output file path, or None on failure.
    Same format as ExportDecompiled.py so PatchDiffer cache lookup works.
    """
    out_path = os.path.join(out_dir, "decompiled.c")
    func_count = 0
    error_count = 0

    try:
        with open(out_path, "w") as f:
            f.write("// Decompiled by Ghidra - AutoPiff Pipeline\n")
            f.write("// Source: " + program.getName() + "\n")
            f.write("// Architecture: " + str(program.getLanguage()) + "\n\n")

            funcs = fm.getFunctions(True)
            for func in funcs:
                try:
                    res = decomplib.decompileFunction(func, 60, monitor)
                    if res and res.decompileCompleted():
                        decomp_func = res.getDecompiledFunction()
                        if decomp_func:
                            c_code = decomp_func.getC()
                            if c_code:
                                entry = func.getEntryPoint().toString()
                                f.write("// FUNCTION_START: " + func.getName() + " @ " + entry + "\n")
                                f.write(c_code)
                                f.write("\n// FUNCTION_END\n\n")
                                func_count += 1
                    else:
                        error_count += 1
                except Exception as e:
                    error_count += 1
                    print("[AutoPiff] Error decompiling " + func.getName() + ": " + str(e))

        print("[AutoPiff] Decompilation export: " + str(func_count) + " functions, " + str(error_count) + " errors")
        return out_path

    except Exception as e:
        print("[AutoPiff] Fatal decompilation export error: " + str(e))
        return None


def format_dispatch_table(table):
    """Format dispatch table for output."""
    defaults = ["IRP_MJ_CREATE", "IRP_MJ_CLOSE", "IRP_MJ_DEVICE_CONTROL", "IRP_MJ_INTERNAL_DEVICE_CONTROL"]
    return {k: table.get(k, None) for k in defaults}


def run():
    """Main entry point, called by Ghidra headless."""
    args = getScriptArgs()
    if len(args) < 1:
        print("Usage: autopiff_reachability.py <out_json_path> [semantic_deltas_path]")
        return

    out_path = args[0]
    semantic_deltas_path = args[1] if len(args) > 1 else None

    program = currentProgram
    monitor_obj = ConsoleTaskMonitor()
    decomplib = DecompInterface()
    decomplib.openProgram(program)
    fm = program.getFunctionManager()

    # 1. Identify DriverEntry
    driver_entry = get_driver_entry(program, fm)

    # 2. Extract Dispatch Table
    dispatch_table = extract_dispatch_table(program, fm, decomplib, monitor_obj, driver_entry)

    # 3. Analyze IOCTLs
    ioctls, ioctl_handler = analyze_ioctls(fm, dispatch_table)

    # 4. Tag Reachability
    tags = []
    if semantic_deltas_path:
        tags = tag_semantic_deltas(program, fm, semantic_deltas_path, dispatch_table, ioctl_handler, ioctls)

    # 5. Export decompiled C (reuse open decomplib)
    out_dir = os.path.dirname(out_path)
    decomp_path = export_decompiled_c(program, fm, decomplib, monitor_obj, out_dir)

    # 6. Build Output
    notes = ["Analysis completed using Ghidra Headless"]

    if not dispatch_table["IRP_MJ_DEVICE_CONTROL"]:
        notes.append("IRP_MJ_DEVICE_CONTROL not found via static assignment scanning.")
    if not driver_entry:
        notes.append("DriverEntry could not be confidently identified.")

    output = {
        "autopiff_stage": "reachability",
        "driver": {
            "sha256": program.getExecutableSHA256(),
            "arch": str(program.getLanguage().getProcessor())
        },
        "dispatch": {
            "driver_entry": driver_entry.getName() if driver_entry else None,
            "major_functions": format_dispatch_table(dispatch_table)
        },
        "ioctls": ioctls,
        "tags": tags,
        "decompiled_c_path": decomp_path,
        "notes": notes
    }

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)

    print("[AutoPiff] Reachability analysis complete: " + str(len(tags)) + " functions tagged")


if __name__ == "__main__":
    run()
