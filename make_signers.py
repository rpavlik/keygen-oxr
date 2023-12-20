#!/usr/bin/env python3
# Copyright 2023, Collabora, Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Original author: Rylie Pavlik <rylie.pavlik@collabora.com>
"""Generate subordinate keys and certs."""
from openxr_cert_utils import ROOT_STEM, CertAuth, generate_private_key, make_x509_name
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.serialization import pkcs12

_PW = b"asdf"


def _make_signer(ca, suffix: str):
    stem = suffix.lower().replace(" ", "_")
    cn = f"OpenXR Android Broker {suffix}"
    name = make_x509_name(cn)

    print("Generating private key")
    key = generate_private_key()

    print(f"Generating cert for {cn}")
    cert = ca.make_cert(name, key.public_key())

    # Write private key and cert to p12 file
    with open(f"{stem}_private.p12", "wb") as f:
        f.write(
            pkcs12.serialize_key_and_certificates(
                stem.encode("utf-8"),
                key,
                cert,
                None,
                serialization.BestAvailableEncryption(_PW),
            )
        )

    # Write cert to PEM file (.crt)
    with open(f"{stem}.crt", "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


def main():
    """Entry point to generate subordinate keys/certs."""
    ca = CertAuth.load(ROOT_STEM, _PW)

    _make_signer(ca, "Signer S1 TESTING")
    _make_signer(ca, "Signer S2 TESTING")
    _make_signer(ca, "Upload U1 TESTING")


if __name__ == "__main__":
    main()
