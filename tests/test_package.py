"""Package-level contracts: lazy import, and independence from every client."""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import pytest

import xrdcore
import xrdhttp
import xrdhttp.s3


def _child_path() -> list[str]:
    """The ``sys.path`` for a ``python -I`` child: this xrdhttp and xrdcore, then the rest.

    Both come from wherever they were imported from (``src/`` in a checkout,
    site-packages in a wheel install, a store path in a Nix build), never a
    sibling checkout. ``-I`` drops ``PYTHONPATH``, which is where a Nix build
    puts every dependency, so the child is given this interpreter's own path
    after them, without the tests directory.
    """
    tests = Path(__file__).resolve().parent
    first = [
        str(Path(xrdhttp.__file__).resolve().parent.parent),
        str(Path(xrdcore.__file__).resolve().parent.parent),
    ]
    rest = [entry for entry in sys.path if entry and Path(entry).resolve() != tests]
    return list(dict.fromkeys(first + rest))


PATHS = _child_path()
MODULES = [
    "connection",
    "engine",
    "expect",
    "metalink",
    "ranges",
    "redirects",
    "s3",
    "s3.codec",
    "s3.sigv4",
    "session",
    "tape",
    "tpc",
    "webdav",
    "wire",
]
FORBIDDEN = {"xrdclient", "xgfalclient", "xrdarc", "xrdsec"}


def _imported_after(statement: str) -> set[str]:
    code = f"import sys; sys.path[:] = {PATHS!r}; {statement}; print('\\n'.join(sys.modules))"
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], check=True, capture_output=True, text=True
    ).stdout
    return set(out.split())


def test_version_and_dir():
    assert xrdhttp.__version__
    assert "tape" in dir(xrdhttp) and "sigv4" in dir(xrdhttp.s3)
    with pytest.raises(AttributeError):
        _ = xrdhttp.nonexistent
    with pytest.raises(AttributeError):
        _ = xrdhttp.s3.nonexistent


def test_importing_the_package_imports_no_submodule():
    loaded = _imported_after("import xrdhttp")
    assert not {m for m in loaded if m.startswith("xrdhttp.") and m != "xrdhttp._version"}


def test_botocore_waits_for_the_s3_modules():
    loaded = _imported_after(
        "import xrdhttp.s3, xrdhttp.tape, xrdhttp.tpc, xrdhttp.engine, xrdhttp.session"
    )
    assert not {m for m in loaded if m.split(".")[0] == "botocore"}
    assert "xrdhttp.s3.sigv4" not in loaded


@pytest.mark.parametrize("module", MODULES)
def test_no_client_package_is_ever_imported(module):
    loaded = _imported_after(f"import xrdhttp.{module}")
    assert f"xrdhttp.{module}" in loaded
    assert not {m for m in loaded if m.split(".")[0] in FORBIDDEN}


def test_s3_without_botocore_names_the_extra(monkeypatch):
    """botocore is the ``s3`` extra: without it, ``xrdhttp.s3`` says what to install."""
    monkeypatch.setitem(sys.modules, "botocore", None)  # as if it were not installed
    monkeypatch.delitem(sys.modules, "xrdhttp.s3")
    with pytest.raises(ModuleNotFoundError, match=r"xrdhttp\[s3\]") as caught:
        importlib.import_module("xrdhttp.s3")
    assert caught.value.name == "botocore"


def test_only_the_test_support_imports_xrdsec():
    """``xrdhttp.testing`` (the ``testing`` extra) is built on xrdsec's test server; no client."""
    loaded = _imported_after("import xrdhttp.testing")
    assert "xrdsec.testing.https" in loaded
    assert not {m for m in loaded if m.split(".")[0] in FORBIDDEN - {"xrdsec"}}


def test_lazy_attributes_resolve():
    assert xrdhttp.tape.API == "/api/v1"
    assert xrdhttp.s3.sigv4.ALGORITHM == "AWS4-HMAC-SHA256"
