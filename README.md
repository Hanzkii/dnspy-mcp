# dnspy-mcp

Model Context Protocol (MCP) server for .NET decompilation and static assembly inspection. Connects AI models and agents directly to dnSpy and dnfile.

---

## Capabilities

- **`decompile_type`**: Decompiles any C#, IL, or VB type from a .NET assembly (.dll / .exe).
- **`decompile_member`**: Decompiles an individual method, property, or event by its metadata token.
- **`export_project`**: Decompiles an entire assembly into an SDK-style Visual Studio C# project.
- **`list_assembly_types`**: Fast static metadata scan of declared namespaces, classes, interfaces, and tokens via `dnfile`.
- **`get_assembly_info`**: Extracts CLR runtime target, entry point token, architecture, and external assembly dependencies.

---

## Prerequisites

1. Python 3.10+
2. [dnSpyEx](https://github.com/dnSpyEx/dnSpy/releases) installed on the system.

---

## Installation

```bash
git clone https://github.com/Hanzkii/dnspy-mcp.git
cd dnspy-mcp
pip install -e .
```

Set the path to your dnSpy folder (optional if installed in standard locations):
```bash
# Windows PowerShell
$env:DNSPY_PATH = "E:\Dissassemble\dnSpy"
```

---

## MCP Client Configuration

### Antigravity (`~/.gemini/config/mcp_config.json`)

```json
{
  "mcpServers": {
    "dnspy-mcp": {
      "command": "python",
      "args": ["-m", "dnspy_mcp.server"],
      "env": {
        "DNSPY_PATH": "E:\\Dissassemble\\dnSpy"
      }
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "dnspy": {
      "command": "python",
      "args": ["-m", "dnspy_mcp.server"],
      "env": {
        "DNSPY_PATH": "E:\\Dissassemble\\dnSpy"
      }
    }
  }
}
```

---

## Tool Reference

### `decompile_type`
- `assembly_path` (string, required): Path to the target .NET binary.
- `type_name` (string, required): Full namespace and class name (e.g. `System.Net.Http.HttpClient`).
- `language` (string, optional): Target language (`csharp`, `il`, `il-csharp`, `vb`). Default: `csharp`.

### `decompile_member`
- `assembly_path` (string, required): Path to the assembly.
- `metadata_token` (string, required): Member metadata token in hex (e.g. `0x06001882`).
- `language` (string, optional): Target language (`csharp`, `il`, `vb`). Default: `csharp`.

### `export_project`
- `assembly_path` (string, required): Source assembly file.
- `output_directory` (string, required): Destination folder for the decompiled solution and `.csproj`.
- `sdk_style` (boolean, optional): Whether to output modern SDK project files. Default: `true`.

### `list_assembly_types`
- `assembly_path` (string, required): Path to the assembly.
- `search_query` (string, optional): Substring filter for class or namespace names.
- `limit` (integer, optional): Maximum results returned. Default: `150`.

### `get_assembly_info`
- `assembly_path` (string, required): Path to the assembly.
