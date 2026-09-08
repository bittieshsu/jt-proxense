"""The systemd unit and installer are part of the security boundary.

A hardening directive that is present but hands back the thing it was meant to
protect is worse than none, because it reads as protection in review.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
UNIT = ROOT / "packaging" / "jt-proxense.service"
if not UNIT.exists():                       # project root keeps it under github/
    UNIT = ROOT / "github" / "packaging" / "jt-proxense.service"
INSTALL = ROOT / "install.sh"
if not INSTALL.exists():
    INSTALL = ROOT / "github" / "install.sh"

pytestmark = pytest.mark.skipif(
    not UNIT.exists(), reason="packaging not present in this tree")


def _rw_paths() -> list[str]:
    for line in UNIT.read_text().splitlines():
        if line.startswith("ReadWritePaths="):
            return line.split("=", 1)[1].split()
    return []


def test_service_cannot_write_its_own_code():
    """`ReadWritePaths=/opt/jt-proxense` gave the web process write access to
    run.py and the whole server/ package — command execution in the service
    would have survived a restart."""
    assert "/opt/jt-proxense" not in _rw_paths(), (
        "the whole install dir is writable by the service account again")


def test_writable_paths_are_data_not_code():
    for p in _rw_paths():
        if not p.startswith("/opt/jt-proxense"):
            continue
        assert p in ("/opt/jt-proxense/config.yaml",
                     "/opt/jt-proxense/config_backups",
                     "/opt/jt-proxense/.ssh"), f"unexpected writable path: {p}"


def test_the_paths_the_app_actually_writes_are_writable():
    """Each of these has a feature behind it: adding a cluster from the UI, the
    backup taken before that write, and the keypair every SSH-backed feature
    uses to reach a PVE node."""
    rw = _rw_paths()
    for needed in ("/opt/jt-proxense/config.yaml",
                   "/opt/jt-proxense/config_backups",
                   "/opt/jt-proxense/.ssh",
                   "/var/lib/jt-proxense",
                   "/etc/jt-proxense"):
        assert needed in rw, f"{needed} is not writable — the feature behind it breaks"


def test_hardening_directives_are_still_present():
    text = UNIT.read_text()
    for directive in ("NoNewPrivileges=true", "ProtectSystem=strict",
                      "PrivateTmp=true", "ProtectHome=true"):
        assert directive in text


@pytest.mark.skipif(not INSTALL.exists(), reason="install.sh not in this tree")
def test_installer_does_not_hand_the_tree_to_the_service_user():
    text = INSTALL.read_text()
    assert not re.search(r'chown\s+-R\s+"\$\{SERVICE_USER\}[^"]*"\s+"\$INSTALL_DIR"\s*$',
                         text, re.M), "installer chowns the whole tree to the service user"
    assert 'chown -R root:root "$INSTALL_DIR"' in text


@pytest.mark.skipif(not INSTALL.exists(), reason="install.sh not in this tree")
def test_installer_keeps_the_ssh_key_usable():
    """chown -R root on the tree would have taken the PVE node key away from
    the service account and broken every SSH feature at the next restart."""
    text = INSTALL.read_text()
    assert '"$INSTALL_DIR/.ssh"' in text
    idx_root = text.index('chown -R root:root "$INSTALL_DIR"')
    idx_ssh = text.index('"$INSTALL_DIR/.ssh"', idx_root)
    assert idx_ssh > idx_root, ".ssh ownership must be restored AFTER the root chown"


@pytest.mark.skipif(not INSTALL.exists(), reason="install.sh not in this tree")
def test_installer_creates_config_yaml_owner_only():
    text = INSTALL.read_text()
    assert "umask 077" in text, "config.yaml is created without a restrictive umask"
    assert 'chmod 600 "$INSTALL_DIR/config.yaml"' in text
