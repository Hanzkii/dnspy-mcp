"""
dnspy-mcp: Model Context Protocol (MCP) server for .NET reverse engineering.
Exposes decompilation, project generation, and static assembly inspection tools
to AI agents (Antigravity, Claude Desktop, Cursor, VS Code).
"""

import os
import sys
import shutil
import subprocess
import json
from typing import Optional, Literal
from mcp.server.mcpserver import MCPServer

# Initialize MCP Server instance
app = MCPServer(
    name="dnspy-mcp",
    title="dnSpy .NET Reverse Engineering Server",
    description="Decompiles and inspects .NET assemblies, classes, methods, and metadata using dnSpy and dnfile."
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
    Intelligently discover the dnSpy.Console executable across common installation paths,
    environment variables, and PATH.
    """
    # 1. Direct environment variable override
    env_path = os.environ.get("DNSPY_CONSOLE_PATH") or os.environ.get("DNSPY_PATH")
    if env_path:
        if os.path.isfile(env_path):
            return env_path
        candidate = os.path.join(env_path, "dnSpy.Console.exe")
        if os.path.isfile(candidate):
            return candidate

    # 2. Check PATH
    which_path = shutil.which("dnSpy.Console.exe") or shutil.which("dnSpy.Console")
    if which_path and os.path.isfile(which_path):
        return which_path

    # 3. Known / Standard installation paths
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
        "--no-color",
        asm_path
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120
        )
        output = proc.stdout
        if proc.returncode != 0 and not output.strip():
            return f"Error: dnSpy.Console exited with code {proc.returncode}.\nStderr: {proc.stderr}"
        return output.strip() if output.strip() else f"No type found matching '{type_name}' in '{asm_path}'."
    except subprocess.TimeoutExpired:
        return f"Error: Decompilation timed out after 120s for '{type_name}'."
    except Exception as e:
        return f"Error executing decompilation: {e}"

@app.tool()
def decompile_member(assembly_path: str, metadata_token: str, language: str = "csharp") -> str:
    """
    Decompile a specific .NET member (method, property, or event) by its metadata token.

    Args:
        assembly_path: Path to the .NET assembly file.
        metadata_token: Metadata token in hex (e.g. '0x06001882' or '06001882').
        language: Decompilation language: 'csharp' (default), 'il', or 'vb'.
    """
    asm_path = _resolve_path(assembly_path)
    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    console_bin = find_dnspy_console()
    if not console_bin:
        return "Error: dnSpy.Console.exe not found. Set DNSPY_PATH."

    if not metadata_token.startswith("0x") and not metadata_token.startswith("0X"):
        metadata_token = f"0x{metadata_token}"

    lang_arg = LANG_MAP.get(language.lower(), "C#")
    cmd = [
        console_bin,
        "--md", metadata_token,
        "-l", lang_arg,
        "--no-color",
        asm_path
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120
        )
        output = proc.stdout
        if proc.returncode != 0 and not output.strip():
            return f"Error: dnSpy.Console exited with code {proc.returncode}.\nStderr: {proc.stderr}"
        return output.strip() if output.strip() else f"No member found with metadata token '{metadata_token}'."
    except Exception as e:
        return f"Error: {e}"

@app.tool()
def export_project(assembly_path: str, output_directory: str, sdk_style: bool = True) -> str:
    """
    Decompile an entire .NET assembly into a complete C# project (.csproj / .sln) on disk.

    Args:
        assembly_path: Path to the .NET assembly file (.dll or .exe).
        output_directory: Directory where project files and decompiled C# source files will be written.
        sdk_style: Whether to generate modern .NET SDK-style project files (default: True).
    """
    asm_path = _resolve_path(assembly_path)
    out_dir = _resolve_path(output_directory)

    if not os.path.isfile(asm_path):
        return f"Error: Assembly file not found at '{asm_path}'"

    console_bin = find_dnspy_console()
    if not console_bin:
        return "Error: dnSpy.Console.exe not found. Set DNSPY_PATH."

    os.makedirs(out_dir, exist_ok=True)

    cmd = [
        console_bin,
        "-o", out_dir,
    ]
    if sdk_style:
        cmd.append("--sdk-project")
    cmd.append(asm_path)

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
        import dnfile
        d = dnfile.dnPE(asm_path)
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
        import dnfile
        d = dnfile.dnPE(asm_path)
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
