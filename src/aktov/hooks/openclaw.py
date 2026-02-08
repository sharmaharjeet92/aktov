"""OpenClaw session log hook for Aktov.

Monitors OpenClaw agent sessions by reading session logs from
``~/.openclaw/agents/*/sessions/*.jsonl``, extracting tool calls,
and evaluating them against Aktov detection rules.

Two modes of operation:

1. **One-shot check** (``python3 -m aktov.hooks.openclaw check``):
   Scans the latest session log and prints alerts.

2. **Real-time watcher** (``python3 -m aktov.hooks.openclaw watch``
   or ``aktov watch``):
   Continuously monitors session logs for new tool calls.
   Uses OS-level file events (watchdog) if installed, otherwise
   falls back to lightweight stdlib polling.

Setup::

    aktov init openclaw

Environment variables::

    AK_AGENT_NAME     — optional, name for the agent being traced (default: "openclaw")
    AK_RULES_DIR      — optional, path to custom YAML rules directory
    AK_API_KEY        — optional, Aktov API key for cloud features
    AK_OPENCLAW_DIR   — optional, path to OpenClaw home (default: ~/.openclaw)
"""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aktov.client import Aktov

# ---------------------------------------------------------------------------
# Watchdog availability (hybrid: event-driven if installed, polling otherwise)
# ---------------------------------------------------------------------------

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    _HAS_WATCHDOG = True
except ImportError:  # pragma: no cover
    _HAS_WATCHDOG = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

OPENCLAW_DIR = Path(os.environ.get("AK_OPENCLAW_DIR", Path.home() / ".openclaw"))
TRACES_DIR = Path.home() / ".aktov" / "traces"

SEVERITY_SYMBOLS = {
    "critical": "!!!",
    "high": "!! ",
    "medium": "!  ",
    "low": ".  ",
}

# ---------------------------------------------------------------------------
# Exec command → Aktov tool name mapping
# ---------------------------------------------------------------------------

_EXEC_TOOL_MAP: dict[str, str] = {
    # Network
    "curl": "http_request",
    "wget": "http_request",
    "http": "http_request",
    "httpie": "http_request",
    "fetch": "http_request",
    # Read
    "cat": "read_file",
    "head": "read_file",
    "tail": "read_file",
    "less": "read_file",
    "more": "read_file",
    "bat": "read_file",
    # Write
    "cp": "write_file",
    "mv": "write_file",
    "tee": "write_file",
    # Delete
    "rm": "delete_file",
    "rmdir": "delete_file",
    "unlink": "delete_file",
    # Remote
    "ssh": "remote_exec",
    "scp": "remote_exec",
    "rsync": "remote_exec",
    "sftp": "remote_exec",
    # Package install
    "pip": "package_install",
    "pip3": "package_install",
    "npm": "package_install",
    "yarn": "package_install",
    "pnpm": "package_install",
    "apt": "package_install",
    "apt-get": "package_install",
    "brew": "package_install",
    "uv": "package_install",
    # Database
    "psql": "database_query",
    "mysql": "database_query",
    "sqlite3": "database_query",
    "mongosh": "database_query",
    "redis-cli": "database_query",
    # Container / orchestration
    "docker": "container_exec",
    "kubectl": "container_exec",
    "podman": "container_exec",
    # Git
    "git": "git_operation",
    # Execute
    "python": "eval_code",
    "python3": "eval_code",
    "node": "eval_code",
    "ruby": "eval_code",
    "perl": "eval_code",
    "bash": "run_command",
    "sh": "run_command",
    "zsh": "run_command",
    "chmod": "run_command",
    "chown": "run_command",
}

# OpenClaw native tool → Aktov tool name
# OpenClaw uses both short names (read, write) and dotted names (system.run)
_NATIVE_TOOL_MAP: dict[str, str] = {
    "read": "read_file",
    "write": "write_file",
    "edit": "write_file",
    "apply_patch": "write_file",
    "browser": "http_request",
    "web_fetch": "http_request",
    "web_search": "http_request",
    "message": "send_message",
    "canvas": "write_file",
    "memory_search": "read_file",
    "memory_get": "read_file",
    "cron": "run_command",
    "gateway": "run_command",
    "process": "run_command",
    "sessions_list": "read_file",
    "sessions_history": "read_file",
    "sessions_send": "send_message",
    "sessions_spawn": "run_command",
    # Dotted names (real OpenClaw format)
    "system.notify": "send_message",
    "canvas.update": "write_file",
    "canvas.clear": "delete_file",
    "camera.capture": "read_file",
    "location.get": "read_file",
}


def _parse_exec_command(command: str) -> tuple[str, dict[str, Any] | None]:
    """Parse a shell command string into an Aktov tool name and arguments.

    Returns ``(tool_name, arguments_dict_or_None)``.
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts:
        return ("unknown", None)

    binary = Path(parts[0]).name  # strip path prefix (e.g., /usr/bin/curl → curl)
    tool_name = _EXEC_TOOL_MAP.get(binary, binary)

    # Build a minimal arguments dict for semantic flag extraction
    arguments: dict[str, Any] = {"command": command}

    # Extract URL for network tools
    if tool_name == "http_request":
        for part in parts[1:]:
            if part.startswith("http://") or part.startswith("https://"):
                arguments["url"] = part
                break

    # Extract path for file tools
    if tool_name in ("read_file", "write_file", "delete_file"):
        non_flag_args = [p for p in parts[1:] if not p.startswith("-")]
        if non_flag_args:
            arguments["path"] = non_flag_args[0]

    return (tool_name, arguments)


def _map_tool(name: str, input_dict: dict[str, Any] | None) -> tuple[str, dict[str, Any] | None]:
    """Map an OpenClaw tool call to an Aktov tool name and arguments.

    Handles both native tools (read, write, browser, ...) and
    exec/bash commands (delegates to ``_parse_exec_command``).
    """
    # OpenClaw uses dotted names: system.run, system.exec
    if name in ("exec", "bash", "system.run", "system.exec"):
        cmd = (input_dict or {}).get("command", "")
        if cmd:
            return _parse_exec_command(cmd)
        return (name, input_dict)

    tool_name = _NATIVE_TOOL_MAP.get(name, name)
    return (tool_name, input_dict)


# ---------------------------------------------------------------------------
# Session log parsing
# ---------------------------------------------------------------------------

def _find_sessions(openclaw_dir: Path | None = None) -> list[Path]:
    """Find all OpenClaw session JSONL files, sorted by mtime (newest first)."""
    base = openclaw_dir or OPENCLAW_DIR
    agents_dir = base / "agents"

    if not agents_dir.is_dir():
        return []

    session_files: list[Path] = []
    for agent_dir in agents_dir.iterdir():
        sessions_dir = agent_dir / "sessions"
        if sessions_dir.is_dir():
            session_files.extend(sessions_dir.glob("*.jsonl"))

    return sorted(session_files, key=lambda p: p.stat().st_mtime, reverse=True)


def _parse_session_log(
    session_file: Path,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Parse an OpenClaw session JSONL file from *offset* bytes.

    Returns ``(actions, new_offset)`` where *actions* is a list of
    Aktov-compatible action dicts and *new_offset* is the byte position
    after the last line read (for incremental reads).
    """
    actions: list[dict[str, Any]] = []

    try:
        with open(session_file, encoding="utf-8") as f:
            f.seek(offset)
            raw = f.read()
            new_offset = f.tell()
    except OSError:
        return (actions, offset)

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Real OpenClaw session logs use an envelope format:
        #   {"type": "message", "message": {"role": "assistant", "content": [...]}, ...}
        # Also support flat format (no envelope) for backwards compatibility.
        if entry.get("type") == "message" and isinstance(entry.get("message"), dict):
            msg = entry["message"]
        else:
            msg = entry

        content = msg.get("content")
        if not isinstance(content, list):
            continue

        for block in content:
            if not isinstance(block, dict):
                continue
            # Real OpenClaw uses "toolCall"; Anthropic API uses "tool_use"
            if block.get("type") not in ("tool_use", "toolCall"):
                continue

            oc_name = block.get("name", "unknown")
            # Real OpenClaw uses "arguments"; Anthropic API uses "input"
            oc_input = block.get("arguments") or block.get("input")
            if not isinstance(oc_input, dict):
                oc_input = None

            tool_name, arguments = _map_tool(oc_name, oc_input)

            actions.append({
                "tool_name": tool_name,
                "arguments": arguments,
                "timestamp": datetime.now(UTC).isoformat(),
            })

    return (actions, new_offset)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _evaluate_and_alert(
    agent_name: str,
    actions: list[dict[str, Any]],
    rules_dir: str | None = None,
    api_key: str | None = None,
) -> int:
    """Evaluate actions against rules and print alerts to stderr.

    Returns the number of alerts fired.
    """
    if not actions:
        return 0

    ak = Aktov(
        api_key=api_key,
        agent_id=agent_name,
        agent_type="openclaw",
        rules_dir=rules_dir,
    )
    trace = ak.start_trace(agent_id=agent_name, agent_type="openclaw")

    for action in actions:
        trace.record_action(
            tool_name=action.get("tool_name", "unknown"),
            arguments=action.get("arguments"),
        )

    response = trace.end()

    for alert in response.alerts:
        severity = alert.get("severity", "medium")
        symbol = SEVERITY_SYMBOLS.get(severity, "?  ")
        rule_id = alert.get("rule_id", "???")
        rule_name = alert.get("rule_name", "unknown")
        print(
            f"[aktov] {symbol} [{rule_id}] {severity.upper()}: {rule_name}",
            file=sys.stderr,
        )

    return len(response.alerts)


def _save_to_aktov_traces(session_name: str, actions: list[dict[str, Any]]) -> Path:
    """Write actions to ``~/.aktov/traces/`` so ``aktov report`` picks them up."""
    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    trace_file = TRACES_DIR / f"openclaw-{session_name}.jsonl"
    with open(trace_file, "w", encoding="utf-8") as f:
        for action in actions:
            f.write(json.dumps(action, default=str) + "\n")
    return trace_file


# ---------------------------------------------------------------------------
# One-shot check
# ---------------------------------------------------------------------------

def check(
    openclaw_dir: Path | None = None,
    agent_name: str = "openclaw",
    rules_dir: str | None = None,
    api_key: str | None = None,
) -> None:
    """One-shot scan of the latest OpenClaw session."""
    sessions = _find_sessions(openclaw_dir)
    if not sessions:
        print("[aktov] No OpenClaw session logs found.", file=sys.stderr)
        print("[aktov] Expected at: ~/.openclaw/agents/*/sessions/*.jsonl", file=sys.stderr)
        return

    session_file = sessions[0]
    actions, _ = _parse_session_log(session_file)

    if not actions:
        print(f"[aktov] Session: {session_file.name} — no tool calls found.", file=sys.stderr)
        return

    # Save for aktov report
    session_name = session_file.stem
    _save_to_aktov_traces(session_name, actions)

    print(f"[aktov] Session: {session_file.name} — {len(actions)} tool call(s)", file=sys.stderr)
    alert_count = _evaluate_and_alert(agent_name, actions, rules_dir, api_key)

    if alert_count == 0:
        print("[aktov] No security issues detected.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Real-time watcher
# ---------------------------------------------------------------------------

class _StdlibPoller:
    """Lightweight session file poller using ``os.stat()``."""

    def __init__(self, openclaw_dir: Path | None = None) -> None:
        self._openclaw_dir = openclaw_dir
        # {filepath_str: last_known_size}
        self._offsets: dict[str, int] = {}
        self._refresh_files()

    def _refresh_files(self) -> None:
        """Discover session files and record sizes for any new ones."""
        for sf in _find_sessions(self._openclaw_dir):
            key = str(sf)
            if key not in self._offsets:
                try:
                    self._offsets[key] = sf.stat().st_size
                except OSError:
                    pass

    def poll_once(self) -> list[tuple[Path, list[dict[str, Any]]]]:
        """Check all tracked files for growth. Returns new actions per file."""
        self._refresh_files()
        results: list[tuple[Path, list[dict[str, Any]]]] = []

        for key, last_offset in list(self._offsets.items()):
            path = Path(key)
            try:
                current_size = path.stat().st_size
            except OSError:
                continue

            if current_size <= last_offset:
                continue

            actions, new_offset = _parse_session_log(path, offset=last_offset)
            self._offsets[key] = new_offset

            if actions:
                results.append((path, actions))

        return results


if _HAS_WATCHDOG:

    class _WatchdogHandler(FileSystemEventHandler):  # type: ignore[misc]
        """Event-driven session file watcher using OS-level file events."""

        def __init__(self) -> None:
            super().__init__()
            self._offsets: dict[str, int] = {}
            self.pending: list[tuple[Path, list[dict[str, Any]]]] = []

        def on_modified(self, event: Any) -> None:
            if event.is_directory:
                return
            path = Path(event.src_path)
            if path.suffix != ".jsonl":
                return

            key = str(path)
            last_offset = self._offsets.get(key, 0)

            try:
                current_size = path.stat().st_size
            except OSError:
                return

            if current_size <= last_offset:
                return

            actions, new_offset = _parse_session_log(path, offset=last_offset)
            self._offsets[key] = new_offset

            if actions:
                self.pending.append((path, actions))

        def on_created(self, event: Any) -> None:
            # New session file — track from the start
            self.on_modified(event)

        def drain(self) -> list[tuple[Path, list[dict[str, Any]]]]:
            """Return and clear pending results."""
            results = self.pending[:]
            self.pending.clear()
            return results


def watch(
    openclaw_dir: Path | None = None,
    interval: float = 0.5,
    agent_name: str = "openclaw",
    rules_dir: str | None = None,
    api_key: str | None = None,
) -> None:
    """Real-time OpenClaw session monitor.

    Runs until interrupted with Ctrl+C.
    """
    base = openclaw_dir or OPENCLAW_DIR
    agents_dir = base / "agents"

    if not agents_dir.is_dir():
        print(f"[aktov] OpenClaw agents directory not found: {agents_dir}", file=sys.stderr)
        print("[aktov] Is OpenClaw installed? Expected: ~/.openclaw/agents/", file=sys.stderr)
        return

    total_alerts = 0
    total_tool_calls = 0
    _running = True

    def _on_sigint(signum: int, frame: Any) -> None:
        nonlocal _running
        _running = False

    signal.signal(signal.SIGINT, _on_sigint)

    print("[aktov] Starting OpenClaw session watcher...", file=sys.stderr)

    if _HAS_WATCHDOG:
        print("[aktov] Mode: event-driven (watchdog installed)", file=sys.stderr)

        handler = _WatchdogHandler()

        # Initialise offsets to current file sizes (only watch new content)
        for sf in _find_sessions(openclaw_dir):
            try:
                handler._offsets[str(sf)] = sf.stat().st_size
            except OSError:
                pass

        observer = Observer()
        # Watch each agent's sessions directory
        watched_dirs: set[str] = set()
        for agent_dir in agents_dir.iterdir():
            sessions_dir = agent_dir / "sessions"
            if sessions_dir.is_dir():
                dir_str = str(sessions_dir)
                if dir_str not in watched_dirs:
                    observer.schedule(handler, dir_str, recursive=False)
                    watched_dirs.add(dir_str)

        observer.start()
        print(
            f"[aktov] Watching {len(watched_dirs)} session dir(s). Ctrl+C to stop.",
            file=sys.stderr,
        )

        try:
            while _running:
                time.sleep(interval)
                results = handler.drain()
                for path, actions in results:
                    total_tool_calls += len(actions)
                    session_name = path.stem
                    _save_to_aktov_traces(session_name, actions)
                    n = _evaluate_and_alert(agent_name, actions, rules_dir, api_key)
                    total_alerts += n
                    if n == 0 and actions:
                        print(
                            f"[aktov] {len(actions)} new tool call(s) in {path.name} — OK",
                            file=sys.stderr,
                        )
        finally:
            observer.stop()
            observer.join()
    else:
        print("[aktov] Mode: polling (install watchdog for event-driven)", file=sys.stderr)

        poller = _StdlibPoller(openclaw_dir)

        session_count = len(poller._offsets)
        print(f"[aktov] Tracking {session_count} session file(s). Ctrl+C to stop.", file=sys.stderr)

        while _running:
            time.sleep(interval)
            results = poller.poll_once()
            for path, actions in results:
                total_tool_calls += len(actions)
                session_name = path.stem
                _save_to_aktov_traces(session_name, actions)
                n = _evaluate_and_alert(agent_name, actions, rules_dir, api_key)
                total_alerts += n
                if n == 0 and actions:
                    print(
                        f"[aktov] {len(actions)} new tool call(s) in {path.name} — OK",
                        file=sys.stderr,
                    )

    print(file=sys.stderr)
    print(
        f"[aktov] Stopped. {total_tool_calls} tool calls monitored, {total_alerts} alerts.",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Service installer (launchd / systemd)
# ---------------------------------------------------------------------------

_LAUNCHD_LABEL = "io.aktov.watch"
_SYSTEMD_UNIT = "aktov-watch.service"

_LAUNCHD_PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{aktov_path}</string>
        <string>watch</string>
        <string>--interval</string>
        <string>{interval}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_path}</string>
    <key>StandardErrorPath</key>
    <string>{log_path}</string>
</dict>
</plist>
"""

_SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=Aktov OpenClaw Session Watcher
After=default.target

[Service]
ExecStart={aktov_path} watch --interval {interval}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"""


def _get_aktov_executable() -> str:
    """Find the ``aktov`` binary path."""
    path = shutil.which("aktov")
    if path:
        return path
    return f"{sys.executable} -m aktov.cli.main"


def _install_launchd(interval: float) -> None:
    """Install the watcher as a macOS launchd agent."""
    plist_dir = Path.home() / "Library" / "LaunchAgents"
    plist_file = plist_dir / f"{_LAUNCHD_LABEL}.plist"

    if plist_file.exists():
        print(f"[aktov] Already installed: {plist_file}", file=sys.stderr)
        print("[aktov] Use `aktov watch --status` or `--uninstall` first.", file=sys.stderr)
        return

    log_dir = Path.home() / ".aktov" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "watch.log"

    aktov_path = _get_aktov_executable()

    plist_content = _LAUNCHD_PLIST.format(
        label=_LAUNCHD_LABEL,
        aktov_path=aktov_path,
        interval=str(interval),
        log_path=str(log_path),
    )

    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_file.write_text(plist_content)

    subprocess.run(["launchctl", "load", str(plist_file)], check=False)

    print(f"[aktov] Installed: {plist_file}", file=sys.stderr)
    print(f"[aktov] Logs: {log_path}", file=sys.stderr)
    print("[aktov] Watcher will start now and on every login.", file=sys.stderr)


def _uninstall_launchd() -> None:
    """Remove the macOS launchd agent."""
    plist_file = Path.home() / "Library" / "LaunchAgents" / f"{_LAUNCHD_LABEL}.plist"

    if not plist_file.exists():
        print("[aktov] Not installed (no plist found).", file=sys.stderr)
        return

    subprocess.run(["launchctl", "unload", str(plist_file)], check=False)
    plist_file.unlink()
    print("[aktov] Uninstalled. Watcher stopped.", file=sys.stderr)


def _status_launchd() -> None:
    """Check macOS launchd agent status."""
    plist_file = Path.home() / "Library" / "LaunchAgents" / f"{_LAUNCHD_LABEL}.plist"

    if not plist_file.exists():
        print("[aktov] Not installed.", file=sys.stderr)
        return

    result = subprocess.run(
        ["launchctl", "list", _LAUNCHD_LABEL],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(f"[aktov] Running (launchd label: {_LAUNCHD_LABEL})", file=sys.stderr)
        for line in result.stdout.strip().splitlines():
            print(f"  {line}", file=sys.stderr)
    else:
        print(f"[aktov] Installed but not running: {plist_file}", file=sys.stderr)


def _install_systemd(interval: float) -> None:
    """Install the watcher as a systemd user service."""
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_file = unit_dir / _SYSTEMD_UNIT

    if unit_file.exists():
        print(f"[aktov] Already installed: {unit_file}", file=sys.stderr)
        print("[aktov] Use `aktov watch --status` or `--uninstall` first.", file=sys.stderr)
        return

    aktov_path = _get_aktov_executable()

    unit_content = _SYSTEMD_UNIT_TEMPLATE.format(
        aktov_path=aktov_path,
        interval=str(interval),
    )

    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_file.write_text(unit_content)

    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "--user", "enable", "--now", _SYSTEMD_UNIT], check=False)

    print(f"[aktov] Installed: {unit_file}", file=sys.stderr)
    print("[aktov] Watcher will start now and on every login.", file=sys.stderr)


def _uninstall_systemd() -> None:
    """Remove the systemd user service."""
    unit_file = Path.home() / ".config" / "systemd" / "user" / _SYSTEMD_UNIT

    if not unit_file.exists():
        print("[aktov] Not installed (no unit file found).", file=sys.stderr)
        return

    subprocess.run(["systemctl", "--user", "disable", "--now", _SYSTEMD_UNIT], check=False)
    unit_file.unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    print("[aktov] Uninstalled. Watcher stopped.", file=sys.stderr)


def _status_systemd() -> None:
    """Check systemd user service status."""
    unit_file = Path.home() / ".config" / "systemd" / "user" / _SYSTEMD_UNIT

    if not unit_file.exists():
        print("[aktov] Not installed.", file=sys.stderr)
        return

    result = subprocess.run(
        ["systemctl", "--user", "status", _SYSTEMD_UNIT],
        capture_output=True, text=True,
    )
    print(result.stdout or result.stderr, file=sys.stderr)


def install_watcher(interval: float = 0.5) -> None:
    """Install the watcher as a background service (launchd or systemd)."""
    system = platform.system()
    if system == "Darwin":
        _install_launchd(interval)
    elif system == "Linux":
        _install_systemd(interval)
    else:
        print(f"[aktov] Unsupported platform: {system}", file=sys.stderr)
        print("[aktov] Manual setup: run `aktov watch` in a background process.", file=sys.stderr)


def uninstall_watcher() -> None:
    """Remove the background watcher service."""
    system = platform.system()
    if system == "Darwin":
        _uninstall_launchd()
    elif system == "Linux":
        _uninstall_systemd()
    else:
        print(f"[aktov] Unsupported platform: {system}", file=sys.stderr)


def status_watcher() -> None:
    """Check the background watcher service status."""
    system = platform.system()
    if system == "Darwin":
        _status_launchd()
    elif system == "Linux":
        _status_systemd()
    else:
        print(f"[aktov] Unsupported platform: {system}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point: ``python3 -m aktov.hooks.openclaw [check|watch]``."""
    agent_name = os.environ.get("AK_AGENT_NAME", "openclaw")
    rules_dir = os.environ.get("AK_RULES_DIR")
    api_key = os.environ.get("AK_API_KEY")
    oc_dir_env = os.environ.get("AK_OPENCLAW_DIR")
    openclaw_dir = Path(oc_dir_env) if oc_dir_env else None

    subcommand = sys.argv[1] if len(sys.argv) > 1 else "check"

    if subcommand == "watch":
        watch(
            openclaw_dir=openclaw_dir,
            agent_name=agent_name,
            rules_dir=rules_dir,
            api_key=api_key,
        )
    else:
        check(
            openclaw_dir=openclaw_dir,
            agent_name=agent_name,
            rules_dir=rules_dir,
            api_key=api_key,
        )


if __name__ == "__main__":
    main()
