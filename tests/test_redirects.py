"""Which credentials may follow a redirect, and how the next hop is spelt."""

from __future__ import annotations

import pytest

from xrdhttp import redirects


@pytest.mark.parametrize(
    ("origin", "target", "trusted", "expected"),
    [
        ("https://se.example/f", "https://se.example:443/g", (), True),
        ("davs://se.example/f", "https://SE.example/g", (), True),
        ("https://se.example/f", "https://se.example:8443/g", (), False),
        ("https://se.example/f", "https://other.example/g", (), False),
        ("https://se.example/f", "http://se.example/g", (), False),
        ("http://se.example/f", "https://se.example/g", (), False),
        ("https://head.cern.ch/f", "https://disk.cern.ch:8443/g", ("cern.ch",), True),
        ("https://head.cern.ch/f", "https://evilcern.ch/g", ("cern.ch",), False),
        ("https://head.cern.ch/f", "http://disk.cern.ch/g", ("cern.ch",), False),
        ("https://a.example/f", "https://b.other/g", ("*",), True),
        ("dav://se.example/f", "http://se.example:80/g", (), True),
    ],
)
def test_who_carries_credentials(origin, target, trusted, expected):
    assert redirects.carries_credentials(origin, target, trusted) is expected


@pytest.mark.parametrize(
    ("origin", "target", "expected"),
    [
        ("https://eospublic.cern.ch/f", "http://st-1.cern.ch:8443/f", True),
        ("https://eospublic.cern.ch/f", "https://evil.example/f", False),
        ("https://se.ac.uk/f", "https://other.ac.uk/f", False),  # parent is a registry
        ("https://se.gla.ac.uk/f", "https://disk.gla.ac.uk/f", True),
        ("https://se.uni.edu.au/f", "https://x.uni.edu.au/f", True),
        ("https://se.example.de/f", "https://example.de/f", True),
        ("https://cern.ch/f", "https://cern.ch/g", True),  # a bare domain: itself only
        ("https://cern.ch/f", "https://x.cern.ch/g", False),
        ("https://10.0.0.1/f", "https://10.0.0.2/f", False),  # an address
        ("https://se.ac.at/f", "https://ac.at/f", False),
    ],
)
def test_transfer_headers_stay_within_the_site(origin, target, expected):
    assert redirects.relays_transfer_headers(origin, target) is expected


def test_public_suffixes():
    assert redirects.public_suffix("ac.uk")
    assert redirects.public_suffix("edu.zz")  # the generic registry rule
    assert not redirects.public_suffix("cern.ch")
    assert not redirects.public_suffix("fnal.gov")


def test_in_domain():
    assert redirects.in_domain("disk.CERN.ch", ".cern.ch.")
    assert redirects.in_domain("cern.ch", "cern.ch")
    assert not redirects.in_domain("evilcern.ch", "cern.ch")


def test_without_credentials():
    headers = {
        "Authorization": "Bearer x",
        "Cookie": "c",
        "Proxy-Authorization": "p",
        "TransferHeaderAuthorization": "Bearer far",
        "Overwrite": "T",
    }
    assert redirects.without_credentials(headers) == {"Overwrite": "T"}
    assert redirects.without_credentials(headers, keep_transfer=True) == {
        "TransferHeaderAuthorization": "Bearer far",
        "Overwrite": "T",
    }


def test_query_token():
    assert redirects.query_token({"authz": "Bearer abc "}) == "abc"
    assert redirects.query_token({"access_token": "t", "x": "1"}) == "t"
    assert redirects.query_token({"authz": ""}) is None


def test_endpoint_and_schemes():
    assert redirects.endpoint("davs://SE.example/f") == ("https", "se.example", 443)
    assert redirects.endpoint("webdav://h:81/f") == ("http", "h", 81)
    assert redirects.uses_tls("https://h/") and not redirects.uses_tls("dav://h/")
    with pytest.raises(ValueError, match="not an HTTP scheme"):
        redirects.wire_scheme("root")


@pytest.mark.parametrize(
    ("path", "wire"),
    [
        ("/a b/c~d", "/a%20b/c~d"),
        ("/a%41b", "/a%2541b"),
        ("/x%2fy", "/x%2Fy"),
        ("/€", "/%E2%82%AC"),
    ],
)
def test_wire_path(path, wire):
    assert redirects.wire_path(path) == wire


@pytest.mark.parametrize(
    ("current", "location", "expected"),
    [
        ("https://h/a/b", "https://other/x", "https://other/x"),
        ("https://h/a/b", "c?x=1", "https://h/a/c?x=1"),
        ("https://h/a/b", "/root", "https://h/root"),
        ("https://u:p@h/a/b", "c", "https://u:p@h/a/c"),
        ("https://u@h/a/b", "//other/x", "https://other/x"),
        ("davs://h/a/b", "c", "davs://h/a/c"),
        ("dav://u@h/a/b", "/x", "dav://u@h/x"),
        ("davs://h/a/b", "davs://other/x", "davs://other/x"),
        ("davs://u@h/a/b", "//other/x", "davs://other/x"),
        ("s3s://bucket.h/k/a", "b?partNumber=1", "s3s://bucket.h/k/b?partNumber=1"),
        ("https://h/a/b", "https://other/x?y", "https://other/x?y"),
    ],
)
def test_resolve_location(current, location, expected):
    assert redirects.resolve_location(current, location) == expected


def test_resolve_location_refuses_a_relative_base():
    with pytest.raises(ValueError, match="not an absolute URL"):
        redirects.resolve_location("/a/b", "c")
    with pytest.raises(ValueError, match="not an absolute URL"):
        redirects.resolve_location("://h/a", "c")


@pytest.mark.parametrize(
    ("origin", "target", "carried"),
    [
        ("https://door/f", "https://pool7/f", True),  # door to data server
        ("https://door/f", "http://pool7/f", False),  # downgrade to another host
        ("https://door/f", "http://door:8080/f", True),  # same host: davix allows it
        ("http://door/f", "https://pool7/f", True),
        ("davs://door/f", "dav://pool7/f", False),
    ],
)
def test_davix_rule(origin, target, carried):
    assert redirects.davix_carries_credentials(origin, target) is carried
