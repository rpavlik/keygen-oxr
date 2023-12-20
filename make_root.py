#!/usr/bin/env python3
# Copyright 2023, Collabora, Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Original author: Rylie Pavlik <rylie.pavlik@collabora.com>
"""Generate a root CA."""
from openxr_cert_utils import ROOT_STEM, CertAuth


_PW = b"asdf"


def main():
    """Entry point for CA generation routine."""
    ca = CertAuth.generate("OpenXR Android Root X1 TESTING")
    ca.save(ROOT_STEM, _PW)
    ca.save_ca_cert(ROOT_STEM)


if __name__ == "__main__":
    main()
