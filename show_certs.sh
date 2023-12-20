#!/bin/sh
# Copyright 2023, Collabora, Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Original author: Rylie Pavlik <rylie.pavlik@collabora.com>

for fn in xr_root_x1*.crt signer_s1*.crt signer_s2*.crt upload_u1*.crt; do

    echo "**************************"
    echo "$fn"
    openssl x509 -in "$fn" -text -noout -verify
done
