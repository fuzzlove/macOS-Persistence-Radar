"""MITRE ATT&CK mappings used by findings."""

MITRE = {
    "launch_agent": ("T1543.001", "Launch Agent"),
    "launch_daemon": ("T1543.004", "Launch Daemon"),
    "login_item": ("T1547.015", "Login Items"),
    "reopened_application": ("T1547.007", "Re-opened Applications"),
    "command_interpreter": ("T1059", "Command and Scripting Interpreter"),
    "startup_script": ("T1037", "Boot or Logon Initialization Scripts"),
    "host_binary": ("T1554", "Compromise Host Software Binary"),
    "impair_defenses": ("T1562", "Impair Defenses"),
}


def technique(key: str) -> tuple[str, str]:
    return MITRE.get(key, ("", ""))
