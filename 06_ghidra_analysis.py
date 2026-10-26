# 06_ghidra_analysis.py
# PyGhidra 3 analysis of ScreenConnect.ClientSetup.exe ("jmorgan")
import pyghidra
import traceback
import os

_here   = os.path.dirname(os.path.abspath(__file__))
SAMPLE  = os.path.join(_here, "ScreenConnect.ClientSetup.exe")
PROJECT = os.path.join(_here, "ghidra_project")
OUT     = os.path.join(_here, "ghidra_output.txt")

SUSPICIOUS_APIS = [
    "FindResourceW", "LoadResource", "LockResource", "SizeofResource",
    "CorBindToRuntimeEx", "CLRCreateInstance",
    "LoadLibraryW", "LoadLibraryExW", "GetProcAddress",
    "CreateProcessW", "CreateProcessA",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "CreateRemoteThread",
    "RegOpenKeyExW", "RegSetValueExW", "RegCreateKeyExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "WriteFile", "CreateFileW",
    "WinExec", "ShellExecuteW",
]

pyghidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Open file — use write-through so output is saved even if we crash later
fout = open(OUT, "w", encoding="utf-8")

def p(s=""):
    print(s)
    fout.write(s + "\n")
    fout.flush()

def hx(addr):
    return f"0x{addr.getOffset():08X}"

with pyghidra.open_program(SAMPLE, project_location=PROJECT,
                           project_name="jmorgan", analyze=True) as flat_api:
    prog    = flat_api.getCurrentProgram()
    monitor = ConsoleTaskMonitor()
    fm      = prog.getFunctionManager()
    sym_tbl = prog.getSymbolTable()
    ref_mgr = prog.getReferenceManager()

    # ------------------------------------------------------------------ #
    p("=" * 68)
    p("GHIDRA ANALYSIS  --  jmorgan (ScreenConnect.ClientSetup.exe)")
    p("=" * 68)

    # --- Program metadata ---
    p("\n[PROGRAM INFO]")
    p(f"  Name       : {prog.getName()}")
    p(f"  Language   : {prog.getLanguageID()}")
    p(f"  Format     : {prog.getExecutableFormat()}")
    p(f"  Image base : {hx(prog.getImageBase())}")
    p(f"  Compiler   : {prog.getCompiler()}")

    # --- Entry points ---
    p("\n[ENTRY POINTS]")
    for ep in sym_tbl.getExternalEntryPointIterator():
        fn = fm.getFunctionAt(ep)
        p(f"  {hx(ep)}  {fn.getName() if fn else '<unknown>'}")

    # --- Function list ---
    funcs = sorted(fm.getFunctions(True), key=lambda f: f.getEntryPoint().getOffset())
    p(f"\n[FUNCTIONS  --  {len(funcs)} total]")
    for fn in funcs:
        tag = " [THUNK]" if fn.isThunk() else ""
        p(f"  {hx(fn.getEntryPoint())}  {fn.getName():<45}  sz={fn.getBody().getNumAddresses()}{tag}")

    # --- Suspicious API xrefs ---
    p("\n[SUSPICIOUS API CROSS-REFERENCES]")
    for api in SUSPICIOUS_APIS:
        for sym in sym_tbl.getSymbols(api):
            refs = list(ref_mgr.getReferencesTo(sym.getAddress()))
            if not refs:
                continue
            p(f"\n  {api}  @  {hx(sym.getAddress())}")
            for ref in refs:
                caller = fm.getFunctionContaining(ref.getFromAddress())
                cname  = caller.getName() if caller else "<no function>"
                p(f"    <- {hx(ref.getFromAddress())}  in  {cname}")

    # --- Decompile interesting functions ---
    p("\n[DECOMPILED FUNCTIONS]")
    decomp = DecompInterface()
    decomp.openProgram(prog)
    decomp.setSimplificationStyle("decompile")

    KEYWORDS = {"main", "winmain", "entry", "resource", "payload",
                "clr", "corb", "load", "find", "install", "run",
                "start", "pe_sec", "dotnet"}

    count = 0
    seen  = set()

    for fn in funcs:
        if fn.isThunk():
            continue
        addr = fn.getEntryPoint().getOffset()
        if addr in seen:
            continue
        name_l = fn.getName().lower()
        want = any(kw in name_l for kw in KEYWORDS) or count < 5
        if not want:
            continue
        try:
            result = decomp.decompileFunction(fn, 60, monitor)
            if result and result.decompileCompleted():
                p(f"\n{'- ' * 34}")
                p(f"  {fn.getName()}  @  {hx(fn.getEntryPoint())}")
                p(f"{'- ' * 34}")
                p(result.getDecompiledFunction().getC())
                seen.add(addr)
                count += 1
        except Exception:
            p(f"  [decompile error for {fn.getName()}]")
            p(traceback.format_exc())
        if count >= 30:
            break

    decomp.dispose()

    # --- Imports ---
    p("\n[IMPORTS]")
    for sym in sym_tbl.getExternalSymbols():
        ns = sym.getParentNamespace().getName()
        p(f"  {ns:<28}  {sym.getName()}")

fout.close()
print(f"\n[+] Saved: {OUT}")
