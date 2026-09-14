"""The installer's failure path has to lead somewhere.

An error message that names no next step is where an evaluation stops. These
pin the pieces that make the link work: the pages exist, the installer points
at them, and it picks the reader's language.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs" if (ROOT / "docs" / "index.html").exists() else ROOT / "github" / "docs"
INSTALL = ROOT / "install.sh" if (ROOT / "install.sh").exists() else ROOT / "github" / "install.sh"

EN = DOCS / "troubleshooting.html"
ZH = DOCS / "troubleshooting.zh-tw.html"

pytestmark = pytest.mark.skipif(not DOCS.exists(), reason="docs not in this tree")


def test_both_language_pages_exist():
    assert EN.exists() and ZH.exists()


def test_the_two_pages_cover_the_same_questions():
    """Rendered from one content model; if they drift, a reader following a
    deep link from a Chinese installer lands on a missing anchor."""
    ids = lambda p: re.findall(r'<details class="qa" id="([a-z0-9-]+)"', p.read_text(encoding="utf-8"))
    assert ids(EN) == ids(ZH) != []


def test_each_page_links_to_the_other():
    assert 'href="troubleshooting.zh-tw.html"' in EN.read_text(encoding="utf-8")
    assert 'href="troubleshooting.html"' in ZH.read_text(encoding="utf-8")


def test_pages_have_a_contents_list_and_a_search_box():
    for p in (EN, ZH):
        t = p.read_text(encoding="utf-8")
        assert 'class="ts-toc"' in t, f"{p.name}: no contents list"
        assert 'id="ts-q"' in t, f"{p.name}: no search box"


def test_no_external_resources():
    """The site vendors everything; a docs page that pulls a CDN font breaks on
    an air-gapped viewer and leaks a request."""
    for p in (EN, ZH):
        for m in re.findall(r'(?:src|href)="(https?://[^"]+)"', p.read_text(encoding="utf-8")):
            assert "github.com" in m, f"{p.name}: external resource {m}"


UNINSTALL = ROOT / "uninstall.sh" if (ROOT / "uninstall.sh").exists() else ROOT / "github" / "uninstall.sh"


@pytest.mark.skipif(not UNINSTALL.exists(), reason="uninstall.sh not in this tree")
def test_uninstaller_points_at_the_page_when_it_fails():
    """Its two failure paths -- not root, and no TTY to confirm on -- are as
    likely to be someone's first contact with the project as the installer's."""
    t = UNINSTALL.read_text(encoding="utf-8")
    assert "troubleshooting.html" in t and "troubleshooting.zh-tw.html" in t
    die = next((l for l in t.splitlines() if l.startswith("die()")), "")
    assert "help_line" in die, "uninstall.sh die() does not print the URL"
    # Every bare `exit 1` should now be die(), with one deliberate exception:
    # typing something other than "remove" is the user aborting on purpose, not
    # a failure, and pointing them at a troubleshooting page would be noise.
    bare = [l.strip() for l in t.splitlines()
            if "exit 1" in l and not l.startswith("die()")]
    assert bare == ['[ "$reply" = "remove" ] || { echo "aborted."; exit 1; }'], (
        f"unexpected bare exit path(s): {bare}")


@pytest.mark.skipif(not INSTALL.exists(), reason="install.sh not in this tree")
def test_installer_points_at_the_page_when_it_fails():
    t = INSTALL.read_text(encoding="utf-8")
    assert "troubleshooting.html" in t and "troubleshooting.zh-tw.html" in t
    # die() must emit it, or the most common failure says nothing.
    die = next(l for l in t.splitlines() if l.startswith("die()"))
    assert "help_line" in die, "die() does not print the troubleshooting URL"


@pytest.mark.skipif(not INSTALL.exists(), reason="install.sh not in this tree")
@pytest.mark.parametrize("locale,expected", [
    ("zh_TW.UTF-8", "troubleshooting.zh-tw.html"),
    ("zh_CN.UTF-8", "troubleshooting.zh-tw.html"),
    ("zh_HK.UTF-8", "troubleshooting.zh-tw.html"),
    ("en_US.UTF-8", "troubleshooting.html"),
    ("ja_JP.UTF-8", "troubleshooting.html"),
    ("C",           "troubleshooting.html"),
    ("",            "troubleshooting.html"),
])
def test_help_url_follows_the_system_locale(locale, expected):
    """A Chinese system gets the Chinese page; everything else gets English."""
    body = INSTALL.read_text(encoding="utf-8")
    start = body.index("help_url() {")
    end = body.index("}", body.index("esac", start))
    fn = body[start:end + 1]
    out = subprocess.run(
        ["bash", "-c", f'DOCS_BASE=X\n{fn}\nhelp_url'],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": locale, "LC_ALL": "", "LC_MESSAGES": ""},
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.endswith(expected), f"LANG={locale!r} -> {out.stdout!r}"


def test_landing_pages_link_to_their_own_language():
    """English landing -> English troubleshooting, Chinese -> Chinese."""
    en = (DOCS / "index.html").read_text(encoding="utf-8")
    zh = (DOCS / "index.zh-tw.html").read_text(encoding="utf-8")
    assert 'href="troubleshooting.html"' in en
    assert 'href="troubleshooting.zh-tw.html"' not in en
    assert 'href="troubleshooting.zh-tw.html"' in zh
    assert 'href="troubleshooting.html"' not in zh


def test_vendored_fonts_are_actually_fonts():
    """Five Rajdhani files were Google 404 pages saved with a .woff2 extension,
    and the fonts.css that style.css imports did not exist at all -- so the site
    rendered in system-ui while shipping the fonts it was designed for."""
    css = DOCS / "fonts" / "fonts.css"
    assert css.exists(), "style.css imports fonts/fonts.css but it is missing"
    for w in DOCS.glob("fonts/*.woff2"):
        head = w.read_bytes()[:4]
        assert head == b"wOF2", f"{w.name} is not a woff2 file (starts {head!r})"
