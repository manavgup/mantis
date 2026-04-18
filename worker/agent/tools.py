"""Tool definitions and implementations for the vulnerability research agent."""

import subprocess

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Execute a bash command and return its stdout and stderr. Use this to compile code, run binaries, inspect crashes, read ASAN output, and explore the filesystem.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The bash command to execute"
                    }
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file. Use this to examine source code, configuration files, and other text files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file to read"
                    }
                },
                "required": ["path"]
            }
        }
    }
]

TOOL_TIMEOUT_SECONDS = 120


def execute_bash(command: str) -> str:
    """Execute a bash command with timeout, return combined stdout+stderr."""
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += ("\n" if output else "") + result.stderr
        if result.returncode != 0:
            output += f"\n[exit code: {result.returncode}]"
        return output or "[no output]"
    except subprocess.TimeoutExpired:
        return f"[command timed out after {TOOL_TIMEOUT_SECONDS}s]"
    except Exception as e:
        return f"[error: {e}]"


def read_file(path: str) -> str:
    """Read a file's contents, return error message on failure."""
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        return f"[error reading {path}: {e}]"


def execute_tool(name: str, arguments: dict) -> str:
    """Dispatch a tool call by name."""
    if name == "bash":
        return execute_bash(arguments["command"])
    elif name == "read_file":
        return read_file(arguments["path"])
    else:
        return f"[unknown tool: {name}]"
