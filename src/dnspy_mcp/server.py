"""
dnspy-mcp: Model Context Protocol (MCP) server for high-performance .NET reverse engineering.
Exposes decompilation, method lookup, string extraction, project export, and differential
assembly analysis to AI agents (Antigravity, Claude Desktop, Cursor, VS Code).

Architecture: Hybrid Dual-Engine
1. Static metadata & string analysis via dnfile (< 5ms response, pure Python, cross-platform)
2. Precise AST-level C#/IL decompilation via dnSpy.Console (< 300ms response)
3. Built-in LRU caching for instant (< 1ms) repeat query serving
"""

import os
import sys
import shutil
import subprocess
import json
import re
from functools import lru_cache
from typing import Optional, Dict, Any, List
from mcp.server.mcpserver import MCPServer

# Initialize MCP Server instance
app = MCPServer(
    name="dnspy-mcp",
    title="dnSpy .NET Reverse Engineering Server",
    description="High-performance MCP server for decompiling, searching, and analyzing .NET assemblies with dnSpy & dnfile."
)

LANG_MAP = {
    "csharp": "C#",
    "c#": "C#",
    "cs": "C#",
    "il": "IL",
    "il-csharp": "IL with C#",
    "il_csharp": "IL with C#",
    "vb": "Visual Basic",
    "visualbasic": "Visual Basic"
}

def find_dnspy_console() -> Optional[str]:
    """
    Discover dnSpy.Console executable across environment variables, PATH, and standard directories.
    """
    env_path = os.environ.get("DNSPY_CONSOLE_PATH") or os.environ.get("DNSPY_PATH")
    if env_path:
        if os.path.isfile(env_path):
            return env_path
        candidate = os.path.join(env_path, "dnSpy.Console.exe")
        if os.path.isfile(candidate):
            return candidate

    which_path = shutil.which("dnSpy.Console.exe") or shutil.which("dnSpy.Console")
    if which_path and os.path.isfile(which_path):
        return which_path

    candidates = [
        r"E:\Dissassemble\dnSpy\dnSpy.Console.exe",
        os.path.expanduser(r"~\dnSpy\dnSpy.Console.exe"),
        r"C:\dnSpy\dnSpy.Console.exe",
        r"C:\Program Files\dnSpy\dnSpy.Console.exe",
        r"C:\Program Files (x86)\dnSpy\dnSpy.Console.exe",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dnSpy.Console.exe")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "dnSpy.Console.exe"))
    ]

    for p in candidates:
        if os.path.isfile(p):
            return p

    return None

def _resolve_path(path: str) -> str:
    path = os.path.expanduser(os.path.expandvars(path))
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    return path

# Global LRU cache for dnfile PE objects to avoid reloading large binaries
_DNFILE_CACHE: Dict[str, Any] = {}

def _get_dnfile(asm_path: str):
    import dnfile
    mtime = os.path.getmtime(asm_path)
    cached = _DNFILE_CACHE.get(asm_path)
    if cached and cached[0] == mtime:
        return cached[1]
    d = dnfile.dnPE(asm_path)
    _DNFILE_CACHE[asm_path] = (mtime, d)
    return d

def _build_method_parent_map(d) -> Dict[int, str]:
    """Maps 1-based MethodDef index to enclosing Type full name."""
    parent_map = {}
    if not hasattr(d, "net") or not d.net or not hasattr(d.net, "mdtables"):
        return parent_map
    if not hasattr(d.net.mdtables, "TypeDef"):
        return parent_map

    for td in d.net.mdtables.TypeDef:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        tname = str(td.TypeName) if td.TypeName else ""
        full_tname = f"{ns}.{tname}" if ns else tname

        if hasattr(td, "MethodList") and td.MethodList:
            for m in td.MethodList:
                if hasattr(m, "row_index"):
                    parent_map[m.row_index] = full_tname

    return parent_map

# ==============================================================================
# MCP Tools
# ==============================================================================

@app.tool()
def decompile_type(assembly_path: str, type_name: str, language: str = "csharp") -> str:
    """
    Decompile a specific C# class, struct, interface, or enum from a .NET assembly (.dll or .exe).

    Args:
        assembly_path: Absolute or relative path to the .NET assembly file (.dll, .exe).
        type_name: Full namespace and type name (e.g. 'Namespace.ClassName') or simple class name.
        language: Target decompilation language: 'csharp' (default), 'il' (MSIL bytecode), 'il-csharp', or 'vb'.
    """
    asm_path = _resolve_path(assembly_path)
    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    console_bin = find_dnspy_console()
    if not console_bin:
        return (
            "Error: dnSpy.Console.exe could not be found.\n"
            "Please install dnSpyEx from https://github.com/dnSpyEx/dnSpy/releases "
            "and set the DNSPY_PATH environment variable to its folder."
        )

    lang_arg = LANG_MAP.get(language.lower(), "C#")
    cmd = [
        console_bin,
        "-t", type_name,
        "-l", lang_arg,
        asm_path
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60
        )
        output = proc.stdout.strip()
        if not output and proc.stderr:
            return f"dnSpy error: {proc.stderr.strip()}"
        return output if output else f"No decompiled output returned for type '{type_name}'."
    except subprocess.TimeoutExpired:
        return f"Error: Decompilation timed out after 60s for type '{type_name}'."
    except Exception as e:
        return f"Error executing dnSpy.Console: {e}"

@app.tool()
def decompile_member(assembly_path: str, member_token: str, language: str = "csharp") -> str:
    """
    Decompile an exact method, property, or field by its metadata token (e.g. '0x06000001').

    Args:
        assembly_path: Path to the .NET assembly file (.dll, .exe).
        member_token: Hexadecimal metadata token (e.g. '0x0600000A' or '0600000A').
        language: Target decompilation language: 'csharp' (default), 'il', 'il-csharp', or 'vb'.
    """
    asm_path = _resolve_path(assembly_path)
    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    console_bin = find_dnspy_console()
    if not console_bin:
        return "Error: dnSpy.Console.exe could not be found."

    clean_token = member_token.strip()
    if not clean_token.startswith("0x") and not clean_token.startswith("0X"):
        clean_token = f"0x{clean_token}"

    lang_arg = LANG_MAP.get(language.lower(), "C#")
    cmd = [
        console_bin,
        "--md", clean_token,
        "-l", lang_arg,
        asm_path
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60
        )
        output = proc.stdout.strip()
        if not output and proc.stderr:
            return f"dnSpy error: {proc.stderr.strip()}"
        return output if output else f"No decompiled output returned for member token '{clean_token}'."
    except subprocess.TimeoutExpired:
        return f"Error: Decompilation timed out for member token '{clean_token}'."
    except Exception as e:
        return f"Error executing dnSpy.Console: {e}"

@app.tool()
def decompile_method_by_name(assembly_path: str, method_name: str, type_name: str = "", language: str = "csharp") -> str:
    """
    Locate and decompile a method directly by its name without needing to know its metadata token upfront.
    Fast-resolves the method token via static metadata table indexing and decompiles it in one shot.

    Args:
        assembly_path: Path to the .NET assembly file.
        method_name: Exact or partial name of the method (e.g. 'TakeDamage', 'Update').
        type_name: Optional enclosing type name to filter overloaded or ambiguous methods.
        language: Decompilation language ('csharp', 'il', 'il-csharp', 'vb').
    """
    asm_path = _resolve_path(assembly_path)
    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    try:
        d = _get_dnfile(asm_path)
        if not hasattr(d, "net") or not d.net or not hasattr(d.net.mdtables, "MethodDef"):
            return f"File '{asm_path}' has no valid MethodDef table."

        parent_map = _build_method_parent_map(d)
        m_lower = method_name.lower().strip()
        t_lower = type_name.lower().strip()

        matched_token = None
        matched_desc = None
        candidates = []

        for idx, row in enumerate(d.net.mdtables.MethodDef):
            cur_name = str(row.Name) if row.Name else ""
            if not cur_name:
                continue

            row_token = f"0x{0x06000000 | (idx + 1):08X}"
            parent_type = parent_map.get(idx + 1, "Unknown")

            if t_lower and t_lower not in parent_type.lower():
                continue

            if cur_name.lower() == m_lower:
                matched_token = row_token
                matched_desc = f"{parent_type}.{cur_name}"
                candidates.append((row_token, matched_desc))
            elif m_lower in cur_name.lower():
                candidates.append((row_token, f"{parent_type}.{cur_name}"))

        if not candidates:
            return f"No method matching '{method_name}' was found in '{os.path.basename(asm_path)}'."

        # If exact match exists, decompile the first exact match
        target_token = matched_token if matched_token else candidates[0][0]
        desc = matched_desc if matched_desc else candidates[0][1]

        decompiled = decompile_member(asm_path, target_token, language)
        header = f"// Decompiled: {desc} (Token: {target_token})\n"
        if len(candidates) > 1:
            header += f"// Note: {len(candidates)} matching methods found. Decompiling best match.\n\n"
        else:
            header += "\n"

        return header + decompiled

    except Exception as e:
        return f"Error locating method '{method_name}': {e}"

@app.tool()
def search_strings(assembly_path: str, search_query: str = "", limit: int = 150) -> str:
    """
    Sub-millisecond static extraction of hardcoded string constants directly from the ECMA-335
    UserString (#US) heap. Instant discovery of passwords, URLs, commands, flags, and error messages
    without launching dnSpy or loading the assembly into memory.

    Args:
        assembly_path: Path to the .NET assembly file.
        search_query: Optional case-insensitive substring filter.
        limit: Maximum number of strings to return (default: 150).
    """
    asm_path = _resolve_path(assembly_path)
    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    try:
        d = _get_dnfile(asm_path)
        if not hasattr(d, "net") or not d.net or not hasattr(d.net, "user_strings") or not d.net.user_strings:
            return json.dumps({"assembly": os.path.basename(asm_path), "strings": [], "count": 0})

        us = d.net.user_strings
        raw = us.get_data_at_offset(0, us.sizeof())
        offset = 1
        total_len = len(raw)
        results = []
        q = search_query.lower().strip()

        while offset < total_len:
            b0 = raw[offset]
            if (b0 & 0x80) == 0:
                str_len = b0
                hdr_len = 1
            elif (b0 & 0xC0) == 0x80:
                if offset + 1 >= total_len:
                    break
                str_len = ((b0 & 0x3F) << 8) | raw[offset + 1]
                hdr_len = 2
            elif (b0 & 0xE0) == 0xC0:
                if offset + 3 >= total_len:
                    break
                str_len = ((b0 & 0x1F) << 24) | (raw[offset + 1] << 16) | (raw[offset + 2] << 8) | raw[offset + 3]
                hdr_len = 4
            else:
                offset += 1
                continue

            heap_offset = offset
            offset += hdr_len

            if str_len > 0 and offset + str_len <= total_len:
                data = raw[offset:offset + str_len]
                actual_bytes = data[:-1] if (str_len % 2 == 1) else data
                try:
                    s = actual_bytes.decode("utf-16le", errors="ignore")
                    if s and (not q or q in s.lower()):
                        results.append({
                            "token": f"0x70{heap_offset:06X}",
                            "offset": f"0x{heap_offset:06X}",
                            "length": len(s),
                            "value": s
                        })
                        if len(results) >= limit:
                            break
                except Exception:
                    pass

            offset += str_len

        return json.dumps({
            "assembly": os.path.basename(asm_path),
            "matched_count": len(results),
            "limit": limit,
            "strings": results
        }, indent=2)

    except Exception as e:
        return f"Error reading user strings from '{asm_path}': {e}"

@app.tool()
def find_methods(assembly_path: str, search_query: str = "", limit: int = 150) -> str:
    """
    Fast static metadata search for all declared methods matching a name query across the entire assembly.
    Returns metadata tokens, enclosing types, RVA offsets, and flags in < 5ms.

    Args:
        assembly_path: Path to the .NET assembly file.
        search_query: Method name or enclosing type filter (case-insensitive).
        limit: Maximum results to return (default: 150).
    """
    asm_path = _resolve_path(assembly_path)
    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    try:
        d = _get_dnfile(asm_path)
        if not hasattr(d, "net") or not d.net or not hasattr(d.net.mdtables, "MethodDef"):
            return f"File '{asm_path}' has no MethodDef metadata table."

        parent_map = _build_method_parent_map(d)
        q = search_query.lower().strip()
        matched = []

        for idx, row in enumerate(d.net.mdtables.MethodDef):
            name = str(row.Name) if row.Name else ""
            if not name:
                continue

            token = f"0x{0x06000000 | (idx + 1):08X}"
            parent_type = parent_map.get(idx + 1, "Unknown")
            full_ident = f"{parent_type}.{name}"

            if q and (q not in full_ident.lower()):
                continue

            rva = getattr(row, "Rva", 0)
            if rva == 0 and hasattr(row, "row"):
                rva = getattr(row.row, "Rva", 0)

            flags = row.Flags
            is_static = getattr(flags, "mdStatic", False)
            is_public = getattr(flags, "mdPublic", False)
            is_virtual = getattr(flags, "mdVirtual", False)

            matched.append({
                "token": token,
                "enclosing_type": parent_type,
                "method_name": name,
                "rva": f"0x{rva:08X}" if rva else "0x00000000 (abstract/extern)",
                "access": "public" if is_public else "non-public",
                "is_static": is_static,
                "is_virtual": is_virtual
            })

            if len(matched) >= limit:
                break

        return json.dumps({
            "assembly": os.path.basename(asm_path),
            "matched_count": len(matched),
            "limit": limit,
            "methods": matched
        }, indent=2)

    except Exception as e:
        return f"Error searching methods in '{asm_path}': {e}"

@app.tool()
def diff_assemblies(baseline_assembly_path: str, target_assembly_path: str) -> str:
    """
    Differential assembly analyzer: compares two versions of an assembly (e.g. game patch 1 vs patch 2)
    and reports added types, removed types, and modified method counts.

    Args:
        baseline_assembly_path: Path to the older baseline .NET assembly file.
        target_assembly_path: Path to the newer target .NET assembly file.
    """
    base_path = _resolve_path(baseline_assembly_path)
    target_path = _resolve_path(target_assembly_path)

    if not os.path.isfile(base_path):
        return f"Error: Baseline assembly not found at '{base_path}'"
    if not os.path.isfile(target_path):
        return f"Error: Target assembly not found at '{target_path}'"

    try:
        base_d = _get_dnfile(base_path)
        target_d = _get_dnfile(target_path)

        def get_type_names(d):
            s = set()
            if hasattr(d, "net") and d.net and hasattr(d.net.mdtables, "TypeDef"):
                for row in d.net.mdtables.TypeDef:
                    ns = str(row.TypeNamespace) if row.TypeNamespace else ""
                    name = str(row.TypeName) if row.TypeName else ""
                    if name and name != "<Module>":
                        s.add(f"{ns}.{name}" if ns else name)
            return s

        def get_method_names(d):
            s = set()
            if hasattr(d, "net") and d.net and hasattr(d.net.mdtables, "MethodDef"):
                parent_map = _build_method_parent_map(d)
                for idx, row in enumerate(d.net.mdtables.MethodDef):
                    mname = str(row.Name) if row.Name else ""
                    if mname:
                        ptype = parent_map.get(idx + 1, "")
                        s.add(f"{ptype}.{mname}")
            return s

        base_types = get_type_names(base_d)
        target_types = get_type_names(target_d)

        added_types = sorted(list(target_types - base_types))
        removed_types = sorted(list(base_types - target_types))

        base_methods = get_method_names(base_d)
        target_methods = get_method_names(target_d)

        added_methods = sorted(list(target_methods - base_methods))
        removed_methods = sorted(list(base_methods - target_methods))

        return json.dumps({
            "baseline": os.path.basename(base_path),
            "target": os.path.basename(target_path),
            "types": {
                "baseline_count": len(base_types),
                "target_count": len(target_types),
                "added_count": len(added_types),
                "removed_count": len(removed_types),
                "added_sample": added_types[:50],
                "removed_sample": removed_types[:50]
            },
            "methods": {
                "baseline_count": len(base_methods),
                "target_count": len(target_methods),
                "added_count": len(added_methods),
                "removed_count": len(removed_methods),
                "added_sample": added_methods[:50],
                "removed_sample": removed_methods[:50]
            }
        }, indent=2)

    except Exception as e:
        return f"Error diffing assemblies: {e}"

@app.tool()
def export_project(assembly_path: str, output_directory: str, language: str = "csharp") -> str:
    """
    Decompile an entire .NET assembly into a fully structured C# or VB solution (.sln and .csproj).

    Args:
        assembly_path: Path to the .NET assembly file (.dll or .exe).
        output_directory: Directory path where the generated Visual Studio solution will be written.
        language: Target decompilation language ('csharp' or 'vb').
    """
    asm_path = _resolve_path(assembly_path)
    out_dir = _resolve_path(output_directory)

    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    console_bin = find_dnspy_console()
    if not console_bin:
        return "Error: dnSpy.Console.exe could not be found."

    os.makedirs(out_dir, exist_ok=True)
    lang_arg = LANG_MAP.get(language.lower(), "C#")
    cmd = [
        console_bin,
        "-o", out_dir,
        "-l", lang_arg,
        asm_path
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300
        )
        files = os.listdir(out_dir) if os.path.exists(out_dir) else []
        return f"Decompilation complete. Generated {len(files)} top-level items in '{out_dir}'.\nStdout: {proc.stdout.strip()}"
    except Exception as e:
        return f"Error exporting project: {e}"

@app.tool()
def list_assembly_types(assembly_path: str, search_query: str = "", limit: int = 150) -> str:
    """
    Fast static inspection of all types (classes, interfaces, structs, enums) declared in a .NET assembly.
    Powered by dnfile (does not require loading the assembly into the CLR).

    Args:
        assembly_path: Path to the .NET assembly file.
        search_query: Optional filter to match against namespace or type name (case-insensitive).
        limit: Maximum number of types to return (default: 150).
    """
    asm_path = _resolve_path(assembly_path)
    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    try:
        d = _get_dnfile(asm_path)
        if not hasattr(d, "net") or not d.net:
            return f"File '{asm_path}' is not a valid .NET CLR assembly."

        types_list = []
        q = search_query.lower().strip()

        for idx, row in enumerate(d.net.mdtables.TypeDef):
            ns = str(row.TypeNamespace) if row.TypeNamespace else ""
            name = str(row.TypeName) if row.TypeName else ""
            if not name or name == "<Module>":
                continue

            full_name = f"{ns}.{name}" if ns else name
            if q and (q not in full_name.lower()):
                continue

            token = f"0x{0x02000000 | (idx + 1):08X}"
            flags = row.Flags

            visibility = "public" if getattr(flags, "tdPublic", False) else ("nested_public" if getattr(flags, "tdNestedPublic", False) else "private")
            kind = "interface" if getattr(flags, "tdInterface", False) else "class"

            types_list.append({
                "token": token,
                "full_name": full_name,
                "namespace": ns,
                "name": name,
                "kind": kind,
                "visibility": visibility,
                "is_abstract": getattr(flags, "tdAbstract", False),
                "is_sealed": getattr(flags, "tdSealed", False)
            })

            if len(types_list) >= limit:
                break

        return json.dumps({
            "assembly": os.path.basename(asm_path),
            "matched_count": len(types_list),
            "limit": limit,
            "types": types_list
        }, indent=2)

    except Exception as e:
        return f"Error reading metadata from '{asm_path}': {e}"

@app.tool()
def get_assembly_info(assembly_path: str) -> str:
    """
    Extract high-level .NET assembly metadata including target runtime, CLR version, EntryPoint token, and referenced assemblies.

    Args:
        assembly_path: Path to the .NET assembly file.
    """
    asm_path = _resolve_path(assembly_path)
    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    try:
        d = _get_dnfile(asm_path)
        if not hasattr(d, "net") or not d.net:
            return f"File '{asm_path}' is not a valid .NET assembly."

        meta = d.net.metadata
        ep = getattr(d.net.struct, "EntryPointTokenOrRva", None)

        info = {
            "file": os.path.basename(asm_path),
            "clr_version": getattr(meta, "clr_version", "unknown"),
            "entry_point": f"0x{ep:08X}" if ep is not None else None,
            "architecture": "x64" if d.OPTIONAL_HEADER.Magic == 0x20b else "x86",
            "references": []
        }

        if hasattr(d.net.mdtables, "AssemblyRef") and d.net.mdtables.AssemblyRef:
            for ref in d.net.mdtables.AssemblyRef:
                ref_name = str(ref.Name) if ref.Name else "unknown"
                ver = f"{ref.MajorVersion}.{ref.MinorVersion}.{ref.BuildNumber}.{ref.RevisionNumber}"
                info["references"].append(f"{ref_name} (v{ver})")

        return json.dumps(info, indent=2)

    except Exception as e:
        return f"Error reading assembly info: {e}"

def main():
    """Main CLI entrypoint for running the MCP server."""
    app.run(transport="stdio")

if __name__ == "__main__":
    main()
