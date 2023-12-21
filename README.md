# keygen-oxr

<!--
Copyright 2023, Collabora, Ltd.

SPDX-License-Identifier: CC-BY-4.0
-->

Some Python tools to help set up a very small scall X.509 PKI system.

Maintained at <https://github.com/rpavlik/keygen-oxr>

## Introduction

This is mainly for internal use so documentation is limited.

## Dependencies

- Python modules:
  - `ruamel.yaml`
  - `cryptography` ([pyca/cryptography](https://cryptography.io/en/latest/))
- `openssl` command line tool for the shell script.

To get everything, as least on my machine:

```sh
sudo apt install python3-ruamel.yaml python3-cryptography
```

## File types

- Input:
  - [Root creation config](root.sample.yml) - YAML file for creating your trust
    root (aka "CA") - used with `make_root.py`
  - [Signers creation config](signers.sample.yml) - YAML file for creating your
    signers, some fields must match the root creation config so it can load the
    root - used with `make_signers.py`
- Output:
  - `.p12` - PKCS#12 format, typically protected with a passphrase. In the case
    of this set of scripts, any generated `.p12` files contain a private key and
    the associated certificate. They are secret and need to be protected. (The
    general `.p12` format can hold much more than what we use it for here.)
  - `.crt` - Certificates in PEM format (armored 7-bit text). These files, in
    this particular case, are public, not secret: they contain a digest of a
    public key, signed by an "issuer" private key, along with metadata.

## License

Dependencies have their own licenses, read and follow them!

The scripts themselves are `GPL-3.0-only`, config files and the like are
`CC0-1.0`, and this documentation is `CC-BY-4.0`. This repo follows the
[REUSE specification](https://reuse.software) so each file is clearly marked
with copyright and license in a machine and human readable way.

All license texts are in the `LICENSES` folder.

It's a part of all the licenses but it bears repeating here:

**Use at your own risk!**

I am publishing this not to necessarily build a community, but to record my
findings and procedures. I am not responsible for your security or privacy.

## Acknowledgments and thanks

This tool was initially developed and maintained by Rylie Pavlik in the course
of her work at the open-source software consultancy
[Collabora](https://collabora.com). Thanks to Collabora and their "Open First"
mantra for supporting the development of this tool.
