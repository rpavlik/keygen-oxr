#!/usr/bin/env python3
# Copyright 2023, Collabora, Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Original author: Rylie Pavlik <rylie.pavlik@collabora.com>
"""Generate subordinate keys and certs."""
import argparse

from ruamel.yaml import YAML
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization

from openxr_cert_utils import (
    CertAuth,
    generate_private_key,
    make_private_p12_path,
    make_public_pem_crt_path,
    make_x509_name,
)


def _generate_signer(ca: CertAuth, identity: dict):
    passphrase: bytes = identity["passphrase"].encode()
    suffix = identity["suffix"]
    stem = suffix.lower().replace(" ", "_")
    cn = f"OpenXR Android Broker {suffix}"

    print(f"\n{cn}")

    name = make_x509_name(cn)

    print("Generating private key")
    key = generate_private_key()

    print(f"Generating cert for {cn}")
    cert = ca.make_cert(
        name,
        key.public_key(),
        not_before=identity.get("not_before"),
        not_after=identity.get("not_after"),
    )

    # Write private key and cert to p12 file
    p12_path = make_private_p12_path(stem)
    print(f"Writing secrets to {p12_path}")
    with open(p12_path, "wb") as f:
        f.write(
            pkcs12.serialize_key_and_certificates(
                stem.encode("utf-8"),
                key,
                cert,
                None,
                serialization.BestAvailableEncryption(passphrase),
            )
        )

    # Write cert to PEM file (.crt)
    cert_path = make_public_pem_crt_path(stem)
    print(f"Writing cert to {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


def _generate_signers(fn):
    """Entry point to generate subordinate keys/certs."""
    print(f"Generating from {fn}")
    yaml = YAML(typ="safe")
    with open(fn, "r", encoding="utf-8") as fp:
        config = yaml.load(fp.read())

    root_stem = config["ca"]["fnstem"]
    root_pw = str(config["ca"]["passphrase"]).encode()
    ca = CertAuth.load(root_stem, root_pw)

    for identity in config["identities"]:
        _generate_signer(ca, identity)


def main():
    """Command line entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filename",
        default="root.yml",
        help="YAML file to configure the subordinate key generation",
    )
    args = parser.parse_args()
    _generate_signers(args.filename)


if __name__ == "__main__":
    main()
