#!/usr/bin/env python3
# Copyright 2023, Collabora, Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Original author: Rylie Pavlik <rylie.pavlik@collabora.com>
"""Generate a root CA."""
import argparse
from ruamel.yaml import YAML
from openxr_cert_utils import CertAuth


def generate_from_file(fn):
    """Entry point for CA generation routine."""
    print(f"Generating from {fn}")
    yaml = YAML(typ="safe")
    with open(fn, "r", encoding="utf-8") as fp:
        config = yaml.load(fp.read())

    fn_stem = config["fnstem"]
    cn = config["cn"]
    passphrase: str = config["passphrase"]
    not_before = config.get("not_before")
    not_after = config.get("not_after")
    ca = CertAuth.generate(cn, not_before=not_before, not_after=not_after)
    ca.save(fn_stem, passphrase.encode())
    ca.save_ca_cert(fn_stem)


def main():
    """Command line entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filename",
        default="root.yml",
        help="YAML file to configure the CA root certificate",
    )
    args = parser.parse_args()
    generate_from_file(args.filename)


if __name__ == "__main__":
    main()
