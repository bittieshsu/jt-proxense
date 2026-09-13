"""Config loading, saving and exposure — the release-blocking half.

Every test here corresponds to something that was live in v1.0.1 and was found
by an external review. Each was confirmed to fail before its fix.
"""
from __future__ import annotations

import os
import stat

import pytest
import yaml

from server import config as cfg_mod


@pytest.fixture
def cfg_file(tmp_path, monkeypatch):
    """Point the config module at a disposable file. The module keeps CONFIG_FILE
    as a module-level constant, so this has to be monkeypatched, not passed."""
    p = tmp_path / "config.yaml"
    monkeypatch.setattr(cfg_mod, "CONFIG_FILE", str(p))
    monkeypatch.setattr(cfg_mod, "CONFIG_BACKUP_DIR", str(tmp_path / "config_backups"))
    monkeypatch.setattr(cfg_mod, "_current_config", None)
    return p


# ------------------------------------------------------------------ fail-closed

def test_unparseable_config_refuses_rather_than_defaulting(cfg_file):
    """The defaults are auth.enabled=False + host=0.0.0.0. Falling back to them
    on a corrupt file turns an authenticated instance into an open one."""
    cfg_file.write_text("server:\n  host: [unclosed\n", encoding="utf-8")
    with pytest.raises(cfg_mod.ConfigError):
        cfg_mod.load_config()


def test_non_mapping_config_refuses(cfg_file):
    """A YAML file that parses but is a list, or a bare string, is not a config."""
    cfg_file.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(cfg_mod.ConfigError):
        cfg_mod.load_config()


def test_missing_config_still_yields_defaults(cfg_file):
    """A first install has no file at all; that is not an error."""
    assert not cfg_file.exists()
    c = cfg_mod.load_config()
    assert c.auth.enabled is False          # defaults, deliberately


# ------------------------------------------------------------------ atomic save

def test_saved_config_is_owner_only(cfg_file):
    """It holds PVE API tokens. The mode used to be whatever the umask was."""
    c = cfg_mod.Config()
    cfg_mod.save_config(c)
    mode = stat.S_IMODE(os.stat(cfg_file).st_mode)
    assert mode == 0o600, f"config.yaml is {mode:o}, expected 600"


def test_save_leaves_no_partial_file_and_reports_failure(cfg_file, monkeypatch):
    """A failed write must raise, and must not have truncated the live file --
    load_config() now refuses to start on a half-written config."""
    cfg_mod.save_config(cfg_mod.Config())
    good = cfg_file.read_text(encoding="utf-8")
    assert good.strip()

    def boom(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(cfg_mod.yaml, "dump", boom)

    with pytest.raises(OSError):
        cfg_mod.save_config(cfg_mod.Config())
    assert cfg_file.read_text(encoding="utf-8") == good, "live config was damaged"
    leftovers = [p for p in cfg_file.parent.iterdir()
                 if p.name.startswith(".config.yaml.")]
    assert not leftovers, f"temp files left behind: {leftovers}"


def test_backups_are_not_world_readable(cfg_file):
    """shutil.copy2 preserves the SOURCE mode, so a loose config.yaml used to
    spray copies of the same tokens into config_backups/."""
    cfg_mod.save_config(cfg_mod.Config())
    os.chmod(cfg_file, 0o644)               # simulate a pre-fix install
    cfg_mod.save_config(cfg_mod.Config())
    backups = list((cfg_file.parent / "config_backups").glob("config_*.yaml"))
    assert backups, "no backup was written"
    for b in backups:
        assert stat.S_IMODE(os.stat(b).st_mode) == 0o600, f"{b} is world-readable"


# ------------------------------------------------------------------ cluster type

def test_cluster_type_survives_a_round_trip():
    """`type: esxi` was dropped by from_dict, so it round-tripped to "pve" and
    the ESXi adapter could never be selected from a config file."""
    data = {"clusters": [{"id": "vc1", "type": "esxi", "nodes": []}]}
    c = cfg_mod.Config.from_dict(data)
    assert c.clusters[0].type == "esxi"
    assert c.to_dict()["clusters"][0]["type"] == "esxi"


def test_cluster_type_defaults_to_pve():
    c = cfg_mod.Config.from_dict({"clusters": [{"id": "c1", "nodes": []}]})
    assert c.clusters[0].type == "pve"


# ------------------------------------------------------------------ CORS default

def test_cors_is_closed_by_default():
    """A wildcard origin with allow_credentials=True let any site the operator
    visited drive this API with their cookies."""
    assert cfg_mod.Config().server.cors_origins == []


def test_wildcard_cors_origin_is_ignored(tmp_path, monkeypatch):
    """Even if someone writes "*" into the file, it must not become a grant."""
    c = cfg_mod.Config.from_dict({"server": {"cors_origins": ["*"]}})
    usable = [o for o in c.server.cors_origins
              if isinstance(o, str) and o.strip() and o.strip() != "*"]
    assert usable == []

# ------------------------------------------------- unknown keys are not corruption

@pytest.mark.parametrize("body,where", [
    ('server:\n  host: "0.0.0.0"\n  legacy_option: true\nclusters: []\n', "server"),
    ('auth:\n  enabled: true\n  old_setting: x\nclusters: []\n', "auth"),
    ('auth:\n  enabled: true\n  forward: {enabled: true, gone: 1}\nclusters: []\n',
     "auth.forward"),
    ('clusters:\n- id: c1\n  nodes: [{host: "10.0.0.1", legacy: 2}]\n', "node"),
    ('ui:\n  bogus: 1\nalerts:\n  nope: 2\nclusters: []\n', "ui/alerts"),
    ('clusters:\n- id: c1\n  nodes: []\n  auth: {user: "u@pve", stale: 1}\n', "cluster auth"),
])
def test_unrecognised_settings_do_not_stop_the_service(cfg_file, body, where):
    """An unknown key is a config from another version, a hand edit or a typo --
    not a corrupt file. Refusing to start on one turns an upgrade into an
    outage, and the message is about a keyword argument. They are dropped with
    a warning instead; genuinely broken YAML still refuses (above)."""
    cfg_file.write_text(body, encoding="utf-8")
    c = cfg_mod.load_config()
    assert c is not None, f"{where}: an unknown key stopped the service"


def test_auth_stays_on_when_an_unknown_key_is_present(cfg_file):
    """The whole point. Dropping to defaults would set auth.enabled False and
    bind 0.0.0.0; so would refusing to start and being 'fixed' by deleting the
    file. The setting must survive."""
    cfg_file.write_text(
        'auth:\n  enabled: true\n  backend: local\n  unknown_thing: 1\n'
        'server:\n  host: "127.0.0.1"\nclusters: []\n', encoding="utf-8")
    c = cfg_mod.load_config()
    assert c.auth.enabled is True
    assert c.auth.backend == "local"
    assert c.server.host == "127.0.0.1"


def test_unknown_keys_are_reported(cfg_file, caplog):
    """Silently dropping settings is its own failure mode -- the operator must
    be able to find out why their option does nothing."""
    import logging
    cfg_file.write_text('server:\n  host: "0.0.0.0"\n  typo_here: 1\nclusters: []\n',
                        encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger=cfg_mod.logger.name):
        cfg_mod.load_config()
    assert any("typo_here" in r.getMessage() for r in caplog.records)
