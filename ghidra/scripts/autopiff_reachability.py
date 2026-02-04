#autopiff_reachability.py
# Must be run via Ghidra Headless

import sys
import json
import logging
from collections import deque

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.symbol import RefType
    from ghidra.app.script import GhidraScript
    from ghidra.program.model.block import BasicBlockModel
except ImportError:
    pass

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

class AutoPiffReachability(GhidraScript):
    def run(self):
        args = self.getScriptArgs()
        if len(args) < 1:
            print("Usage: autopiff_reachability.py <out_json_path> [semantic_deltas_path]")
            return

        out_path = args[0]
        semantic_deltas_path = args[1] if len(args) > 1 else None

        # 1. Setup
        self.monitor = ConsoleTaskMonitor()
        self.decomplib = DecompInterface()
        self.decomplib.openProgram(self.currentProgram)
        self.fm = self.currentProgram.getFunctionManager()
        
        # 2. Identify DriverEntry
        driver_entry = self.get_driver_entry()
        
        # 3. Extract Dispatch Table
        dispatch_table = self.extract_dispatch_table(driver_entry)
        
        # 4. Analyze IOCTLs
        ioctls, ioctl_handler = self.analyze_ioctls(dispatch_table)
        
        # 5. Tag Reachability
        tags = []
        if semantic_deltas_path:
             tags = self.tag_semantic_deltas(semantic_deltas_path, dispatch_table, ioctl_handler, ioctls)

        # 6. Build Output
        notes = ["Analysis completed using Ghidra Headless"]
        
        if not dispatch_table["IRP_MJ_DEVICE_CONTROL"]:
            notes.append("IRP_MJ_DEVICE_CONTROL not found via static assignment scanning.")
        if not driver_entry:
            notes.append("DriverEntry could not be confidently identified.")

        output = {
            "autopiff_stage": "reachability",
            "driver": {
                "sha256": self.currentProgram.getExecutableSHA256(),
                "arch": str(self.currentProgram.getLanguage().getProcessor())
            },
            "dispatch": {
                "driver_entry": driver_entry.getName() if driver_entry else None,
                "major_functions": self.format_dispatch_table(dispatch_table)
            },
            "ioctls": ioctls,
            "tags": tags,
            "notes": notes
        }
        
        with open(out_path, 'w') as f:
            json.dump(output, f, indent=2)

    def get_driver_entry(self):
        st = self.currentProgram.getSymbolTable()

        # Prefer real symbol
        syms = st.getSymbols("DriverEntry")
        if syms.hasNext():
            return self.fm.getFunctionAt(syms.next().getAddress())

        # Common label
        syms = st.getSymbols("entry")
        if syms.hasNext():
            return self.fm.getFunctionAt(syms.next().getAddress())

        # Fallback: program entry point address
        entry = self.currentProgram.getEntryPoint()
        if entry:
            return self.fm.getFunctionAt(entry) or self.fm.getFunctionContaining(entry)

        return None

    def find_function_by_name(self, name):
        it = self.fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            if f.getName() == name:
                return f
        return None

    def extract_dispatch_table(self, driver_entry):
        table = {
            "IRP_MJ_CREATE": None,
            "IRP_MJ_CLOSE": None,
            "IRP_MJ_DEVICE_CONTROL": None,
            "IRP_MJ_INTERNAL_DEVICE_CONTROL": None
        }
        if not driver_entry:
            return table

        res = self.decomplib.decompileFunction(driver_entry, 60, self.monitor)
        if not res or not res.decompileCompleted():
            return table

        c = res.getDecompiledFunction().getC()

        # Look for patterns like: DriverObject->MajorFunction[14] = FUN_1400...
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

            # crude parse: find '=' after marker on same line
            for line in c.splitlines():
                if marker in line and "=" in line:
                    rhs = line.split("=", 1)[1].strip().rstrip(";")
                    # rhs might be casted: (PDRIVER_DISPATCH)FUN_...
                    rhs = rhs.replace("(", " ").replace(")", " ")
                    parts = rhs.split()
                    # pick token that matches a function name in program
                    for tok in parts:
                        f = self.find_function_by_name(tok)
                        if f:
                            table[name] = f.getName()
                            break
                if table[name]:
                    break

        return table

    def analyze_ioctls(self, dispatch_table):
        # Fallback implementation: if device control exists, report generic unknown IOCTL entry
        dc_name = dispatch_table.get("IRP_MJ_DEVICE_CONTROL")
        if dc_name:
            return [{
                "ioctl": "unknown",
                "handler": dc_name,
                "confidence": 0.70,
                "evidence": [EVID_IOCTL_UNKNOWN]
            }], dc_name
        return [], None

    def get_direct_callees(self, func):
        """Returns list of called functions (direct calls only)."""
        callees = set()
        if not func: return []
        
        # Iterate instructions to find calls
        inst_iter = self.currentProgram.getListing().getInstructions(func.getBody())
        for inst in inst_iter:
            if inst.getFlowType().isCall():
                refs = inst.getReferencesFrom()
                for ref in refs:
                    if ref.getReferenceType().isCall():
                        addr = ref.getToAddress()
                        target_func = self.fm.getFunctionAt(addr) or self.fm.getFunctionContaining(addr)
                        if target_func:
                            callees.add(target_func)
                            
        return list(callees)

    def bfs_reachability(self, start_functions, target_func, max_depth=2):
        """
        Returns (reachable, path_list, depth)
        """
        if not start_functions or not target_func:
            return False, [], None

        target_ep = target_func.getEntryPoint()
        queue = deque()
        visited = set()
        
        for f in start_functions:
            if f:
                queue.append((f, 0, [f.getName()]))
                visited.add(f.getEntryPoint())

        while queue:
            curr_func, depth, path = queue.popleft()
            
            if curr_func.getEntryPoint() == target_ep:
                return True, path, depth
            
            if depth >= max_depth:
                continue
                
            callees = self.get_direct_callees(curr_func)
            for callee in callees:
                ep = callee.getEntryPoint()
                if ep not in visited:
                    visited.add(ep)
                    queue.append((callee, depth + 1, list(path) + [callee.getName()]))
                    
        return False, [], None

    def resolve_delta_function(self, delta):
        # Try common keys
        name = delta.get("function") or delta.get("function_name") or delta.get("functionName")
        if not name:
            return None, None

        # Name lookup (v1)
        f = self.find_function_by_name(name)
        return name, f

    def tag_semantic_deltas(self, deltas_path, dispatch_table, ioctl_handler_name, ioctls):
        import os
        if not os.path.exists(deltas_path):
             return []
             
        with open(deltas_path, 'r') as f:
            deltas = json.load(f)
            
        tags = []
        
        # Roots
        ioctl_roots = []
        dc_name = dispatch_table.get("IRP_MJ_DEVICE_CONTROL")
        if dc_name:
            f = self.find_function_by_name(dc_name)
            if f:
                ioctl_roots.append(f)
        
        irp_roots = []
        for k, v in dispatch_table.items():
            if k in ("IRP_MJ_DEVICE_CONTROL", "IRP_MJ_INTERNAL_DEVICE_CONTROL"):
                continue
            if v:
                 f = self.find_function_by_name(v)
                 if f:
                     irp_roots.append(f)

        for delta in deltas:
             func_name, target_func = self.resolve_delta_function(delta)
             if not func_name: continue
             
             if not target_func:
                 # couldn't resolve, stay conservative
                 tags.append({
                     "function": func_name,
                     "reachability_class": CLASS_UNKNOWN,
                     "confidence": 0.0,
                     "paths": [],
                     "evidence": [EVID_DRIVER_ENTRY] # Default evidence
                 })
                 continue

             # Check IOCTL reachability (N=2)
             is_ioctl, path, depth = self.bfs_reachability(ioctl_roots, target_func, 2)
             
             if is_ioctl:
                 conf = 0.70
                 if depth == 0: conf = 0.95
                 elif depth == 1: conf = 0.85
                 
                 evid = [EVID_MAJOR_ASSIGN]
                 if depth > 0:
                     evid.append(EVID_DIRECT_CALL)
                 # We didn't extract IOCTL values => mark unknown values
                 evid.append(EVID_IOCTL_UNKNOWN)
                 
                 # Build a better path array
                 path_tokens = ["IRP_MJ_DEVICE_CONTROL"] + path # Prefix with root type

                 tags.append({
                     "function": target_func.getName(),
                     "reachability_class": CLASS_IOCTL,
                     "confidence": conf,
                     "paths": [path_tokens],
                     "evidence": evid
                 })
                 continue
                 
             # Check IRP reachability (N=2)
             is_irp, path, depth = self.bfs_reachability(irp_roots, target_func, 2)
             
             if is_irp:
                 conf = 0.85 # Default high for IRP handler
                 if depth == 1: conf = 0.85
                 elif depth == 2: conf = 0.65
                 
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

             # Default
             tags.append({
                 "function": target_func.getName(),
                 "reachability_class": CLASS_UNKNOWN,
                 "confidence": 0.0,
                 "paths": [],
                 "evidence": [EVID_DRIVER_ENTRY]
             })
             
        return tags

    def format_dispatch_table(self, table):
        formatted = {}
        defaults = ["IRP_MJ_CREATE", "IRP_MJ_CLOSE", "IRP_MJ_DEVICE_CONTROL", "IRP_MJ_INTERNAL_DEVICE_CONTROL"]
        for k in defaults:
            formatted[k] = table.get(k, None)
        return formatted

# Ghidra Headless Entry Point
if __name__ == '__main__':
    try:
        script = AutoPiffReachability()
        script.run()
    except NameError:
        print("Not running inside Ghidra.")
