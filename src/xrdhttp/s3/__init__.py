"""S3's additions to HTTP: the signature, and the XML answers.

* :mod:`.sigv4` - AWS Signature Version 4: an ``Authorization`` header for a
  request, or a pre-signed URL;
* :mod:`.codec` - S3's XML answers decoded with botocore's service model,
  after :mod:`xrdcore.safexml` has refused any declaration in them.

Both lean on ``botocore``, which is heavy and is the optional ``xrdhttp[s3]``
extra, so importing this package imports neither: each is loaded when first
named. Without botocore installed the package refuses to import at all, with
a message naming the extra, rather than failing later on a bare
``No module named 'botocore'`` from deep inside a signer. The filesystem
over a bucket - its listings, its multipart uploads - is each client's own.
"""

from __future__ import annotations

import importlib
import importlib.util
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import codec, sigv4

__all__ = ["codec", "sigv4"]

# ``find_spec`` locates botocore without importing it, so a present botocore
# still costs nothing until a submodule is named.
if importlib.util.find_spec("botocore") is None:
    raise ModuleNotFoundError(
        "xrdhttp.s3 needs botocore, which is not installed: pip install 'xrdhttp[s3]'",
        name="botocore",
    )


def __getattr__(name: str) -> ModuleType:
    """Import a submodule the first time it is named as an attribute."""
    if name in __all__:
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """The public names, including submodules not yet imported."""
    return sorted(__all__)
