"""The conformance suites, run against the reference adapter on :mod:`xrdhttp.session`.

Every suite in :mod:`xrdhttp.testing.conformance` runs here in both of the
fake's styles, so each check is proved passable by a client made of this
library alone, whichever kind of server a client meets.
"""

from __future__ import annotations

import errno

import pytest

from xrdhttp.testing import StorageServer
from xrdhttp.testing.conformance import (
    Adapter,
    ChecksumSuite,
    Conformance,
    ConnectionSuite,
    CopySuite,
    Kind,
    NamespaceSuite,
    ReadSuite,
    RedirectSuite,
    S3Suite,
    TapeSuite,
    TokenSuite,
    UploadSuite,
    failure,
    kind_of_errno,
)

from tests._reference import ReferenceAdapter
from tests._reference_s3 import ReferenceS3


class Reference(Conformance):
    """The hook every suite needs: the reference client."""

    def make_adapter(self, server: StorageServer) -> Adapter:
        """A reference client for ``server``."""
        return ReferenceAdapter(server)


class Davix(Reference):
    """The same, against the davix-style fake."""

    style = "davix"


class TestNamespace(Reference, NamespaceSuite):
    """The namespace suite, XrdCl style."""


class TestNamespaceDavix(Davix, NamespaceSuite):
    """The namespace suite, davix style."""


class TestRead(Reference, ReadSuite):
    """The read suite, XrdCl style."""


class TestReadDavix(Davix, ReadSuite):
    """The read suite, davix style."""


class TestUpload(Reference, UploadSuite):
    """The upload suite, XrdCl style."""


class TestUploadDavix(Davix, UploadSuite):
    """The upload suite, davix style."""


class TestChecksum(Reference, ChecksumSuite):
    """The checksum suite, XrdCl style."""


class TestChecksumDavix(Davix, ChecksumSuite):
    """The checksum suite, davix style."""


class TestRedirect(Reference, RedirectSuite):
    """The redirect suite, XrdCl style."""


class TestRedirectDavix(Davix, RedirectSuite):
    """The redirect suite, davix style."""


class TestConnection(Reference, ConnectionSuite):
    """The connection suite, XrdCl style."""


class TestConnectionDavix(Davix, ConnectionSuite):
    """The connection suite, davix style."""


class TestCopy(Reference, CopySuite):
    """The copy suite, XrdCl style."""


class TestCopyDavix(Davix, CopySuite):
    """The copy suite, davix style."""


class TestTape(Reference, TapeSuite):
    """The tape suite, XrdCl style."""


class TestTapeDavix(Davix, TapeSuite):
    """The tape suite, davix style."""


class TestToken(Reference, TokenSuite):
    """The token suite, XrdCl style."""


class TestTokenDavix(Davix, TokenSuite):
    """The token suite, davix style."""


class S3(Conformance):
    """The reference client's S3 dialect."""

    def make_adapter(self, server: StorageServer) -> Adapter:
        """A signing reference client for ``server``."""
        return ReferenceS3(server)


class TestS3(S3, S3Suite):
    """The S3 suite, XrdCl style."""


class TestS3Davix(S3, S3Suite):
    """The S3 suite, davix style."""

    style = "davix"


# -- the machinery itself ----------------------------------------------------------------------


def test_a_call_that_succeeds_where_it_should_fail_fails_the_test():
    with pytest.raises(pytest.fail.Exception, match="succeeded where a failure was expected"):
        failure(Adapter(), lambda: None)


def test_the_default_reading_of_an_error():
    adapter = Adapter()
    assert adapter.kind(FileNotFoundError()) is Kind.NOT_FOUND
    assert adapter.kind(TimeoutError()) is Kind.TIMEOUT
    assert adapter.kind(OSError(errno.ENOTEMPTY, "x")) is Kind.NOT_EMPTY
    assert adapter.kind(ValueError()) is Kind.OTHER
    assert kind_of_errno(None) is Kind.OTHER
