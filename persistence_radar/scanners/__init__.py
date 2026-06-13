from persistence_radar.scanners.application_support import scan_application_support
from persistence_radar.scanners.authorization_plugins import scan_authorization_plugins
from persistence_radar.scanners.background_tasks import scan_background_tasks
from persistence_radar.scanners.browser_extensions import scan_browser_extensions
from persistence_radar.scanners.certificates import scan_certificates
from persistence_radar.scanners.cron import scan_cron
from persistence_radar.scanners.launchd import scan_launchd
from persistence_radar.scanners.launchctl_state import scan_launchctl_state
from persistence_radar.scanners.login_items import scan_login_items
from persistence_radar.scanners.native_messaging import scan_native_messaging
from persistence_radar.scanners.path_hijack import scan_path_hijack
from persistence_radar.scanners.privileged_helpers import scan_privileged_helpers
from persistence_radar.scanners.profiles import scan_profiles
from persistence_radar.scanners.shell_startup import scan_shell_startup
from persistence_radar.scanners.system_extensions import scan_system_extensions
from persistence_radar.scanners.tcc import scan_tcc
from persistence_radar.scanners.users_groups import scan_users_groups

SCANNERS = (
    ("LaunchAgents/Daemons", scan_launchd),
    ("launchctl Runtime", scan_launchctl_state),
    ("Background Tasks", scan_background_tasks),
    ("Login Items", scan_login_items),
    ("Cron/At", scan_cron),
    ("Shell Startup", scan_shell_startup),
    ("PATH Hijack", scan_path_hijack),
    ("Browser Extensions", scan_browser_extensions),
    ("Native Messaging", scan_native_messaging),
    ("Profiles", scan_profiles),
    ("Certificate Trust", scan_certificates),
    ("System Extensions", scan_system_extensions),
    ("Authorization Plugins", scan_authorization_plugins),
    ("Privileged Helpers", scan_privileged_helpers),
    ("Application Support Hunt", scan_application_support),
    ("Users/Groups", scan_users_groups),
    ("TCC", scan_tcc),
)

SCANNER_MODULES = {
    "launchd": scan_launchd,
    "launchctl": scan_launchctl_state,
    "background_tasks": scan_background_tasks,
    "login_items": scan_login_items,
    "cron": scan_cron,
    "shell_startup": scan_shell_startup,
    "path_hijack": scan_path_hijack,
    "browser_extensions": scan_browser_extensions,
    "native_messaging": scan_native_messaging,
    "profiles": scan_profiles,
    "certificates": scan_certificates,
    "system_extensions": scan_system_extensions,
    "authorization_plugins": scan_authorization_plugins,
    "privileged_helpers": scan_privileged_helpers,
    "application_support": scan_application_support,
    "users_groups": scan_users_groups,
    "tcc": scan_tcc,
}


def run_all_scanners(root: str = "/") -> list:
    findings = []
    for _name, scanner in SCANNERS:
        findings.extend(scanner(root=root))
    return findings
