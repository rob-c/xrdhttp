"""Metalink 3 and 4 descriptors: ranking, checksums, bounds and the two readings."""

from __future__ import annotations

import hashlib

import pytest

from xrdcore.checksum import checksum_bytes
from xrdcore.errors import MetalinkError
from xrdhttp import metalink
from xrdhttp.metalink import ChecksumInfo, MetalinkPolicy, parse_metalink

BODY = b"the bytes named by every replica"


def meta4(name: str, urls: list[tuple[int, str]], body: bytes = BODY) -> bytes:
    replicas = "".join(f'<url priority="{priority}">{url}</url>' for priority, url in urls)
    digest = hashlib.sha256(body).hexdigest()
    return (
        '<metalink xmlns="urn:ietf:params:xml:ns:metalink">'
        f'<file name="{name}"><size>{len(body)}</size>'
        f'<hash type="sha-256">{digest}</hash>{replicas}</file></metalink>'
    ).encode()


def test_metalink_4_is_ranked_low_priority_first_with_checksums_and_size():
    document = meta4(
        "f.bin",
        [(2, "root://b//f"), (1, "https://a/f"), (2, "root://b//f"), (1, "relative/f")],
    )
    parsed = parse_metalink(document, base_url="https://cat/dir/x.meta4")
    assert parsed.name == "f.bin" and parsed.size == len(BODY)
    assert parsed.replicas == ("https://a/f", "https://cat/dir/relative/f", "root://b//f")
    sha = ChecksumInfo("sha256", hashlib.sha256(BODY).hexdigest())
    assert parsed.checksums == (sha,) and parsed.checksum == sha
    assert str(sha) == f"sha256:{sha.value}"


def test_metalink_3_is_ranked_high_preference_first():
    adler = checksum_bytes("adler32", BODY)
    document = f"""<?xml version="1.0"?>
      <metalink version="3.0" xmlns="http://www.metalinker.org/">
        <files><file name="remote.bin"><size>x</size>
          <verification><hash type="a32">{adler}</hash><hash type="md5">short</hash>
            <hash type="whirlpool">{"0" * 128}</hash>
            <pieces type="sha1"><hash>{"a" * 40}</hash></pieces></verification>
          <resources>
            <url preference="1">root://low//f</url>
            <url preference="100">root://high//f</url>
            <url preference="junk">root://unranked//f</url>
            <url>   </url>
            <url>relative</url>
          </resources>
        </file></files>
      </metalink>"""
    parsed = parse_metalink(document)
    # "relative" has no base to resolve against, and so is no usable replica.
    assert parsed.replicas == ("root://high//f", "root://low//f", "root://unranked//f")
    assert parsed.checksums == (ChecksumInfo("adler32", adler),)
    assert parsed.size is None


@pytest.mark.parametrize(
    ("document", "match"),
    [
        (b"<!DOCTYPE x><metalink/>", "DOCTYPE"),
        (b"<metalink><file name='a'>", "Malformed"),
        (b"<notmetalink/>", "root must be"),
        (b"<metalink><file name='a'/><file name='b'/></metalink>", "exactly one file"),
        (b"<metalink><file><url>root://h//f</url></file></metalink>", "has no name"),
        (b"<metalink><file name='a'><url>no-scheme</url></file></metalink>", "no usable replica"),
    ],
)
def test_unusable_descriptors_are_refused(document, match):
    with pytest.raises(MetalinkError, match=match):
        parse_metalink(document)


def test_the_bounds(monkeypatch):
    with pytest.raises(MetalinkError, match="limit is"):
        parse_metalink(b" " * (metalink.MAX_DESCRIPTOR_SIZE + 1))
    monkeypatch.setattr(metalink, "MAX_REPLICAS", 2)
    urls = [(1, f"root://h{i}//f") for i in range(3)]
    with pytest.raises(MetalinkError, match="more than 2"):
        parse_metalink(meta4("f", urls))
    long_url = "root://h//" + "x" * metalink.MAX_URL_SIZE
    parsed = parse_metalink(meta4("f", [(1, long_url), (2, "root://ok//f")]))
    assert parsed.replicas == ("root://ok//f",)


def test_a_policy_can_read_a_descriptor_the_way_davix_does():
    """Every <url> in the document, HTTP replicas only, no name."""
    document = b"""<metalink version="3.0">
      <size>7</size>
      <file><url preference="1">https://a/f</url><url>root://b//f</url></file>
      <file name="other"><url preference="9">../g</url></file>
    </metalink>"""
    http_only = MetalinkPolicy(single_file=False, accepts=lambda url: url.startswith("https:"))
    parsed = parse_metalink(document, base_url="https://h/c/x.meta4", policy=http_only)
    assert parsed.replicas == ("https://h/g", "https://a/f")
    assert parsed.name == "" and parsed.size == 7
    with pytest.raises(MetalinkError, match="exactly one file"):
        parse_metalink(document)


def test_file_urls_are_usable_replicas_under_xrdcls_reading():
    assert parse_metalink(meta4("f", [(1, "file:///tmp/f")])).replicas == ("file:///tmp/f",)


def test_streams_are_not_mistaken_for_descriptors() -> None:
    class NamedStream:
        def read(self) -> bytes:
            return b""

        def __str__(self) -> str:
            return "looks.meta4"

    assert not metalink.is_metalink(NamedStream())
    assert metalink.is_metalink("file:///tmp/UPPER.META4?token=x")
    assert metalink.is_metalink("/local/a.metalink?x")
    assert not metalink.is_metalink("root://h//f.root")


@pytest.mark.parametrize(
    ("base", "reference", "resolved"),
    [
        ("root://h//store/d/x.meta4", "f", "root://h//store/d/f"),
        ("root://h//store/d/x.meta4", "/abs", "root://h//abs"),
        ("https://h/a/b", "//other/x", "https://other/x"),
        ("https://h/a/b", "https://else/y", "https://else/y"),
        ("", "rel", "rel"),
        ("https://h/a/b/c", "../d", "https://h/a/d"),
    ],
)
def test_resolve(base, reference, resolved):
    assert metalink.resolve(base, reference) == resolved


# Ported from xrdclient's suite (tests/test_metalink.py) when the parser moved
# here: XrdCl's URLs as bases, and the documents a catalogue gets wrong.


def test_relative_urls_resolve_against_xrootd_bases_and_duplicates_and_unknown_hashes_go():
    document = """<metalink xmlns="urn:ietf:params:xml:ns:metalink">
      <file name="f"><size>not-a-number</size>
        <hash type="unknown">xx</hash><hash type="md5">bad</hash>
        <url priority="bad">../f</url><url>../f</url><url></url>
      </file></metalink>"""
    parsed = parse_metalink(document, base_url="root://host:1094//catalog/x.meta4")
    assert parsed.replicas == ("root://host:1094//f",)
    assert parsed.size is None and parsed.checksum is None
    network = parse_metalink(
        "<metalink><file name='f'><url>//mirror.example/f</url></file></metalink>",
        base_url="root://origin.example//catalog/f.meta4",
    )
    assert network.replicas == ("root://mirror.example/f",)
    triple_slash = parse_metalink(
        "<metalink><file name='f'><url>../f</url></file></metalink>",
        base_url="root://origin.example///catalog/f.meta4",
    )
    assert triple_slash.replicas == ("root://origin.example//f",)


@pytest.mark.parametrize(
    ("document", "match"),
    [
        ("<metalink/>", "exactly one"),
        ("<metalink><file name='f'/></metalink>", "no usable"),
    ],
)
def test_an_empty_descriptor_and_a_file_without_urls_are_refused(document, match):
    with pytest.raises(MetalinkError, match=match):
        parse_metalink(document)
