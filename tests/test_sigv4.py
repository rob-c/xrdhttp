"""AWS Signature Version 4: AWS's worked examples, golden values, and credentials."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from xrdhttp.s3.sigv4 import EMPTY_SHA256, UNSIGNED_PAYLOAD, Credentials, hash_payload, sign

#: The account every AWS worked example is signed with.
ACCESS = "AKIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
CREDENTIALS = Credentials(ACCESS, SECRET)


@pytest.fixture(autouse=True)
def no_aws_environment(monkeypatch):
    """Nothing here may pick up the machine's own AWS configuration."""
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ENDPOINT_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(Credentials, "from_file", classmethod(lambda cls, *a, **k: None))


# ---------------------------------------------------------------------------
# Signature Version 4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "signature"),
    [
        # Both of these are worked examples from AWS's own documentation, so
        # what they check is that this signer agrees with the specification
        # rather than merely with itself.
        ("/?lifecycle", "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"),
        (
            "/?max-keys=2&prefix=J",
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
        ),
    ],
)
def test_a_signature_matches_the_worked_example_aws_publishes(target, signature):
    headers = sign(
        "GET",
        target,
        "examplebucket.s3.amazonaws.com",
        {},
        EMPTY_SHA256,
        credentials=CREDENTIALS,
        region="us-east-1",
        when=datetime(2013, 5, 24, tzinfo=UTC),
    )
    assert headers["Authorization"] == (
        f"AWS4-HMAC-SHA256 Credential={ACCESS}/20130524/us-east-1/s3/aws4_request, "
        f"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
    )
    assert headers["x-amz-date"] == "20130524T000000Z"


def test_only_the_host_and_the_amazon_headers_are_signed():
    headers = sign(
        "GET",
        "/k",
        "h",
        {"Range": "bytes=0-9", "x-amz-acl": "private"},
        EMPTY_SHA256,
        credentials=CREDENTIALS,
        region="us-east-1",
    )
    names = headers["Authorization"].partition("SignedHeaders=")[2].partition(",")[0]
    assert names == "host;x-amz-acl;x-amz-content-sha256;x-amz-date"


def test_a_temporary_credential_signs_its_session_token_too():
    headers = sign(
        "GET",
        "/k",
        "h",
        {},
        EMPTY_SHA256,
        credentials=Credentials(ACCESS, SECRET, "session-token-value"),
        region="us-east-1",
    )
    assert headers["x-amz-security-token"] == "session-token-value"
    assert "x-amz-security-token" in headers["Authorization"]


def test_a_path_signs_the_same_however_its_spaces_were_encoded():
    """The server canonicalises what it receives, so this must match it."""

    def signature(target: str) -> str:
        return sign(
            "GET",
            target,
            "h",
            {},
            EMPTY_SHA256,
            credentials=CREDENTIALS,
            region="us-east-1",
            when=datetime(2024, 1, 1, tzinfo=UTC),
        )["Authorization"]

    assert signature("/a%20b") == signature("/a b")
    assert signature("/a%20b") != signature("/ab")


#: Fixed-clock signatures captured from the botocore-private-method signer
#: this one replaced, so the change is proven not to have moved a byte.
WHEN = datetime(2024, 3, 9, 12, 34, 56, tzinfo=UTC)
GOLDEN = [
    (
        ("GET", "/bucket/key", "s3.example.org", {}, EMPTY_SHA256, CREDENTIALS, "us-east-1"),
        "f70f1751a55fa8796512739026b6ee6f9b27a61be5c8103bdbc64b2f88746155",
    ),
    (
        (
            "PUT",
            "/bucket/a%20b/c~d",
            "s3.example.org:9000",
            {"x-amz-acl": "private", "Range": "bytes=0-9", "Content-Type": "x"},
            UNSIGNED_PAYLOAD,
            Credentials(ACCESS, SECRET, "tok/en+="),
            "eu-west-2",
        ),
        "fe36ae21c81e0bf869204f16be2b6cc1f87d182ed6799d667350f9c87af67293",
    ),
    (
        ("GET", "/b/a b/%E2%82%AC", "h", {}, EMPTY_SHA256, CREDENTIALS, "auto"),
        "789b457b6f8411d60b2598aece15abe00b68b3fc901d6d359d0b26530fb65236",
    ),
]


@pytest.mark.parametrize(("request_", "signature"), GOLDEN)
def test_signatures_are_unchanged_from_the_previous_signer(request_, signature):
    method, target, host, headers, payload, credentials, region = request_
    signed = sign(
        method, target, host, headers, payload, credentials=credentials, region=region, when=WHEN
    )
    assert signed["Authorization"].endswith(f"Signature={signature}")
    assert signed["x-amz-date"] == "20240309T123456Z"
    assert signed["x-amz-content-sha256"] == payload
    assert "Range" not in signed  # only what is signed comes back


@pytest.mark.parametrize(("request_", "signature"), GOLDEN)
def test_signing_agrees_with_botocores_own_add_auth(monkeypatch, request_, signature):
    """The public steps, composed here, sign exactly what ``add_auth`` signs.

    ``add_auth`` reads the clock itself, so it is frozen for this comparison;
    any drift in a future botocore shows up here first.
    """
    import botocore.auth
    from botocore.awsrequest import AWSRequest

    from xrdhttp.s3 import sigv4

    method, target, host, headers, payload, credentials, region = request_
    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda: WHEN.replace(tzinfo=None))
    url = sigv4._wire_url(target, host)
    request = AWSRequest(
        method=method,
        url=url,
        headers={**sigv4._selected_headers(headers), "host": host},
    )
    signer = sigv4._PayloadSigner(sigv4._botocore_credentials(credentials), "s3", region, payload)
    signer.add_auth(request)
    assert request.headers["Authorization"].endswith(f"Signature={signature}")


#: AWS's worked example of a pre-signed URL ("Authenticating Requests: Using
#: Query Parameters"), so presigning is checked against the specification.
AWS_PRESIGNED = (
    "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256"
    f"&X-Amz-Credential={ACCESS}%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
    "&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
    "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
)


def test_a_presigned_url_matches_the_worked_example_aws_publishes():
    from xrdhttp.s3.sigv4 import presign

    url = presign(
        "GET",
        "/test.txt",
        "examplebucket.s3.amazonaws.com",
        credentials=CREDENTIALS,
        region="us-east-1",
        expires=86400,
        when=datetime(2013, 5, 24, tzinfo=UTC),
    )
    assert url == AWS_PRESIGNED


@pytest.mark.parametrize(
    ("url", "token", "expected"),
    [
        (
            "https://h/b/k",
            None,
            "https://h/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AK%2F20240309"
            "%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240309T123456Z&X-Amz-Expires=600"
            "&X-Amz-SignedHeaders=host&X-Amz-Signature="
            "494d607fd4dbfb0094d9ede857d73326efa556694d80c9b178d944e3e809f632",
        ),
        (
            "https://h:9000/b/a%20b?versionId=3",
            "tok",
            "https://h:9000/b/a%20b?versionId=3&X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&X-Amz-Credential=AK%2F20240309%2Fus-east-1%2Fs3%2Faws4_request"
            "&X-Amz-Date=20240309T123456Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host"
            "&X-Amz-Security-Token=tok&X-Amz-Signature="
            "44abb7e0b0398b3b4c0225f3069cb4d6b3aa9161aaecc22e32c241cc3ba96ee2",
        ),
    ],
)
def test_botocore_query_signers_handed_in_still_presign_unchanged(url, token, expected):
    """A caller may hand its own ``S3SigV4QueryAuth`` to ``_authorize``."""
    from botocore.auth import S3SigV4QueryAuth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials as AWSCredentials

    from xrdhttp.s3.sigv4 import _authorize, _presigned_url, _Request

    request = AWSRequest(method="GET", url=url, headers={"host": url.split("/")[2]})
    signer = S3SigV4QueryAuth(AWSCredentials("AK", "SK", token), "s3", "us-east-1", expires=600)
    _authorize(signer, request, WHEN)
    assert request.url == expected
    direct = _presigned_url(
        _Request("GET", url, url.split("/")[2], AWSCredentials("AK", "SK", token), "us-east-1"),
        expires=600,
        when=WHEN,
    )
    assert direct == expected


def test_signing_twice_replaces_rather_than_repeats_the_headers():
    from botocore.awsrequest import AWSRequest

    from xrdhttp.s3 import sigv4

    request = AWSRequest(method="GET", url="https://h/k", headers={"host": "h"})
    signer = sigv4._PayloadSigner(
        sigv4._botocore_credentials(Credentials(ACCESS, SECRET, "t")), "s3", "r", EMPTY_SHA256
    )
    sigv4._authorize(signer, request, WHEN)
    first = request.headers["Authorization"]
    sigv4._authorize(signer, request, WHEN)
    assert request.headers.get_all("Authorization") == [first]
    assert request.headers.get_all("X-Amz-Date") == ["20240309T123456Z"]
    assert request.headers.get_all("X-Amz-Security-Token") == ["t"]


def test_a_body_that_is_still_being_written_signs_as_unsigned():
    assert hash_payload(None) == UNSIGNED_PAYLOAD
    assert hash_payload(b"") == EMPTY_SHA256
    assert hash_payload(b"abc").startswith("ba7816bf")


def test_credentials_never_print_the_secret_they_hold():
    plain = repr(Credentials("AKIA-VISIBLE", "shhh"))
    assert "shhh" not in plain
    assert "AKIA-VISIBLE" in plain and "<redacted>" in plain
    temporary = repr(Credentials("AKIA-VISIBLE", "shhh", "also-secret"))
    assert "also-secret" not in temporary and temporary.count("<redacted>") == 2


def test_credentials_come_from_the_environment_when_it_has_them(monkeypatch):
    assert Credentials.from_env() is None
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-ENV")
    assert Credentials.from_env() is None  # half a credential is none of one
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "env-token")
    found = Credentials.from_env()
    assert found == Credentials("AKIA-ENV", "env-secret", "env-token")
    assert Credentials.discover() == found


def test_credentials_come_from_the_shared_file_when_the_environment_is_quiet(tmp_path, monkeypatch):
    monkeypatch.undo()  # the autouse fixture stubs ``from_file`` out
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "credentials"
    path.write_text(
        "[default]\naws_access_key_id = AKIA-FILE\naws_secret_access_key = file-secret\n"
        "[other]\naws_access_key_id = AKIA-OTHER\naws_secret_access_key = other-secret\n"
        "aws_session_token = other-token\n[empty]\n"
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(path))
    assert Credentials.from_file() == Credentials("AKIA-FILE", "file-secret")
    assert Credentials.discover() == Credentials("AKIA-FILE", "file-secret")
    monkeypatch.setenv("AWS_PROFILE", "other")
    assert Credentials.from_file() == Credentials("AKIA-OTHER", "other-secret", "other-token")
    assert Credentials.from_file(profile="empty") is None
    assert Credentials.from_file(profile="absent") is None


@pytest.mark.parametrize("content", ["", "this is not an ini file at all\n[[["])
def test_a_credentials_file_that_cannot_be_read_is_simply_no_credentials(
    tmp_path, monkeypatch, content
):
    monkeypatch.undo()
    path = tmp_path / "credentials"
    path.write_text(content)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(path))
    assert Credentials.from_file() is None
    assert Credentials.from_file(str(tmp_path / "nothing-here")) is None


def test_a_handed_in_query_signer_needs_a_request_with_a_url():
    """botocore lets an ``AWSRequest`` have no URL; there is nothing to pre-sign then."""
    from botocore.auth import S3SigV4QueryAuth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials as AWSCredentials

    from xrdhttp.s3.sigv4 import _authorize

    request = AWSRequest(method="GET", headers={"host": "h"})
    signer = S3SigV4QueryAuth(AWSCredentials("AK", "SK"), "s3", "us-east-1", expires=600)
    with pytest.raises(ValueError, match="needs a URL"):
        _authorize(signer, request, WHEN)
