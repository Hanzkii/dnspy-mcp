# dnspy-mcp

> **High-Performance Headless Model Context Protocol (MCP) Server for .NET Reverse Engineering**  
> Powered by a hybrid dual-engine architecture combining **dnfile** (< 5ms static metadata inspection) and **dnSpy.Console** (precise AST C#/IL decompilation).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![MCP Spec](https://img.shields.io/badge/MCP-1.2.0+-green.svg)](https://modelcontextprotocol.io/)

---

## Why dnspy-mcp? ("Faster, Better, Stronger")

Most existing dnSpy MCP implementations (such as GUI extensions) require running a heavy WPF desktop window in the background, listening on fragile localhost sockets, and freezing when large assemblies are decompiled. 

**`dnspy-mcp` is designed from the ground up for autonomous AI workflows:**

| Feature | Legacy GUI Extensions | **dnspy-mcp** |
| :--- | :--- | :--- |
| **Execution Mode** | Requires active WPF GUI window | **100% Headless** (runs via stdio) |
| **Metadata & String Search** | Slow (GUI HTTP RPC) | **Sub-millisecond (< 2ms)** direct ECMA-335 table parsing via `dnfile` |
| **UserString (`#US`) Heap Extraction** | Unsupported | **Instant byte-level `#US` scanner** (`search_strings`) |
| **Method Search by Name** | Manual token lookup required | **Automatic name-to-token resolution & decompilation** (`decompile_method_by_name`) |
| **Differential Analysis** | Unsupported | **Automated assembly diffing** (`diff_assemblies`) for patch updates |
| **Process Stability** | Susceptible to GUI crashes & port conflicts | Isolated subprocesses with timeouts and LRU memory caching |
| **Cross-Platform Metadata** | Windows-only | Metadata & string tools work on **Linux / macOS / Windows** |

---

## Capabilities & Toolset

### 1. `decompile_type`
Decompiles any C#, IL, or Visual Basic class, struct, interface, or enum from a .NET assembly (`.dll` or `.exe`).
- **Arguments**:
  - `assembly_path`: Path to the `.dll` or `.exe`.
  - `type_name`: Full namespace and class name (e.g. `System.Net.Http.HttpClient` or `StrippingManager`).
  - `language`: `csharp` (default), `il`, `il-csharp`, or `vb`.

### 2. `decompile_member`
Decompiles an exact method, property, or field by its metadata token (e.g. `0x0600005C`).
- **Arguments**:
  - `assembly_path`: Path to the target binary.
  - `member_token`: Metadata token in hex.
  - `language`: Target decompilation language.

### 3. `decompile_method_by_name`
Locates and decompiles a method directly by name without needing to know its metadata token upfront. Fast-resolves the method token via static metadata table indexing and decompiles it in one shot.
- **Arguments**:
  - `assembly_path`: Path to the target binary.
  - `method_name`: Method name (e.g. `TakeDamage`, `Awake`, `CalculateTrajectory`).
  - `type_name` *(optional)*: Enclosing class name to resolve overloads or ambiguous names.
  - `language`: Target language (`csharp`, `il`, etc.).

### 4. `search_strings`
Sub-millisecond static extraction of hardcoded string constants directly from the ECMA-335 UserString (`#US`) heap. Instant discovery of API keys, URLs, hidden console commands, encryption keys, and log strings.
- **Arguments**:
  - `assembly_path`: Path to the target binary.
  - `search_query` *(optional)*: Substring filter (case-insensitive).
  - `limit`: Maximum results to return (default: 150).

### 5. `find_methods`
Fast static search of all methods matching a query across the entire assembly. Returns metadata tokens, enclosing types, RVA offsets, and visibility flags in < 5ms.
- **Arguments**:
  - `assembly_path`: Path to the target binary.
  - `search_query` *(optional)*: Filter by method or class name.
  - `limit`: Maximum results to return (default: 150).

### 6. `diff_assemblies`
Differential assembly analyzer for patch tracking. Compares two versions of an assembly (e.g. Game Update 1 vs Game Update 2) and reports added types, removed types, and new/modified methods.
- **Arguments**:
  - `baseline_assembly_path`: Path to the older baseline binary.
  - `target_assembly_path`: Path to the newer target binary.

### 7. `export_project`
Decompiles an entire .NET assembly into a fully structured Visual Studio solution (`.sln` and `.csproj` project files). Automatically defaults to modern SDK-style projects for immediate compatibility with Visual Studio 2019/2022.
- **Arguments**:
  - `assembly_path`: Path to the assembly (`.dll` or `.exe`).
  - `output_directory`: Directory path where the generated project will be written.
  - `language` *(optional)*: Target language (`csharp` or `vb`). Default: `csharp`.
  - `sdk_project` *(optional)*: Generate modern SDK-style `.csproj` format (`<Project Sdk="Microsoft.NET.Sdk">`). Default: `true`.
  - `vs_version` *(optional)*: Visual Studio solution version (e.g. `2017`). Default: `2017`.

### 8. `list_assembly_types`
Fast static metadata scan of all declared namespaces, classes, interfaces, and tokens without loading the assembly into the CLR runtime.
- **Arguments**:
  - `assembly_path`: Path to the assembly.
  - `search_query` *(optional)*: Class or namespace filter.
  - `limit`: Maximum types to return (default: 150).

### 9. `get_assembly_info`
Extracts high-level assembly metadata including target CLR runtime, EntryPoint token, CPU architecture (`x86`/`x64`), and all external assembly references (`AssemblyRef`).
- **Arguments**:
  - `assembly_path`: Path to the assembly.

---

## Installation

### Prerequisites
1. **Python 3.10+**
2. **[dnSpyEx](https://github.com/dnSpyEx/dnSpy/releases)** (version 6.5.0 or newer) installed on Windows. *(Note: Static metadata tools `search_strings`, `find_methods`, `list_assembly_types`, `get_assembly_info`, and `diff_assemblies` work cross-platform on Linux and macOS without dnSpyEx).*

### Install from Source
```bash
git clone https://github.com/Hanzkii/dnspy-mcp.git
cd dnspy-mcp
pip install -e .
```

---

## Configuration

Set the environment variable `DNSPY_PATH` to your dnSpy folder (where `dnSpy.Console.exe` is located):

```powershell
# Windows PowerShell
$env:DNSPY_PATH = "C:\Tools\dnSpy"
```

### Antigravity (`~/.gemini/config/mcp_config.json`)

```json
{
  "mcpServers": {
    "dnspy-mcp": {
      "command": "python",
      "args": ["-m", "dnspy_mcp.server"],
      "env": {
        "DNSPY_PATH": "C:\\Tools\\dnSpy"
      }
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "dnspy-mcp": {
      "command": "python",
      "args": ["-m", "dnspy_mcp.server"],
      "env": {
        "DNSPY_PATH": "C:\\Tools\\dnSpy"
      }
    }
  }
}
```

### Cursor / VS Code (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "dnspy-mcp": {
      "command": "python",
      "args": ["-m", "dnspy_mcp.server"],
      "env": {
        "DNSPY_PATH": "C:\\Tools\\dnSpy"
      }
    }
  }
}
```

---

## Troubleshooting & FAQ

### Visual Studio Prompt: "Review Project And Solution Changes"
When opening a decompiled `.sln` in modern Visual Studio (VS 2019 / VS 2022), you may encounter a prompt stating:  
*"These projects are either not supported or need project behavior impacting modifications..."*

**Root Causes & Solutions:**
1. **Target Framework Version**: Unity and older .NET assemblies target legacy `.NET Framework 4.0` (`<TargetFramework>net40</TargetFramework>`), which is not bundled by default with VS 2022.
   - **Fix 1**: Click **OK** in the Visual Studio dialog. Visual Studio will load the project or suggest retargeting without modifying any code.
   - **Fix 2 (Recommended)**: Open the generated `.csproj` file in any text editor and change:
     ```xml
     <TargetFramework>net40</TargetFramework>
     ```
     to modern .NET or .NET Standard:
     ```xml
     <TargetFramework>netstandard2.1</TargetFramework>
     ```
     or
     ```xml
     <TargetFramework>net8.0</TargetFramework>
     ```
2. **SDK Style Formatting**: Always ensure `export_project` runs with `sdk_project=True` (the default in v0.2.0+) and `vs_version=2017` to ensure modern Solution Format 12.00 is generated.

---

## License

This project is licensed under the [MIT License](LICENSE).
