"""Check the effective nixpkgs certifi bundle for PYSEC-2026-4320."""

import os
import ssl

# nixpkgs reads NIX_SSL_CERT_FILE at import time. Check the package's
# default bundle rather than a caller's environment override.
os.environ.pop("NIX_SSL_CERT_FILE", None)
os.environ.pop("SSL_CERT_FILE", None)

import certifi  # noqa: E402

roots = ssl.create_default_context(cafile=certifi.where()).get_ca_certs()
names = {value for root in roots for rdn in root["subject"] for key, value in rdn if key == "commonName"}
assert len(roots) > 100, "CA bundle is unexpectedly empty or incomplete"
assert "emSign ECC Root CA - G3" not in names, "PYSEC-2026-4320 root is trusted"
print(f"Verified {len(roots)} roots in {certifi.where()}")
