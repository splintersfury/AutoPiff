# ExportDecompiled.py
# Ghidra headless script for exporting decompiled C code.
# Usage: analyzeHeadless <project> <name> -import <file> -postScript ExportDecompiled.py <output_dir>
#
# Output format includes delimiters for reliable parsing:
#   // FUNCTION_START: <name> @ <address>
#   <decompiled C code>
#   // FUNCTION_END

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os


def run():
    program = currentProgram
    decomplib = DecompInterface()
    decomplib.openProgram(program)

    # Get output path from script arguments
    args = getScriptArgs()
    if len(args) > 0:
        out_path = args[0]
        # If argument is a directory, append filename
        if os.path.isdir(out_path):
            out_path = os.path.join(out_path, program.getName() + ".c")
    else:
        # Default: current directory / <filename>.c
        out_path = os.path.join(os.getcwd(), program.getName() + ".c")

    print("[AutoPiff] Exporting decompiled code to: " + out_path)

    fm = program.getFunctionManager()
    funcs = fm.getFunctions(True)

    func_count = 0
    error_count = 0

    try:
        with open(out_path, "w") as f:
            # Header
            f.write("// Decompiled by Ghidra - AutoPiff Pipeline\n")
            f.write("// Source: " + program.getName() + "\n")
            f.write("// Architecture: " + str(program.getLanguage()) + "\n\n")

            for func in funcs:
                try:
                    monitor = ConsoleTaskMonitor()
                    # 60 second timeout per function
                    res = decomplib.decompileFunction(func, 60, monitor)

                    if res.decompileCompleted():
                        decomp_func = res.getDecompiledFunction()
                        if decomp_func:
                            c_code = decomp_func.getC()
                            if c_code:
                                # Write with delimiters for parsing
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

        print("[AutoPiff] Export complete: " + str(func_count) + " functions, " + str(error_count) + " errors")

    except Exception as e:
        print("[AutoPiff] Fatal error: " + str(e))


if __name__ == "__main__":
    run()
