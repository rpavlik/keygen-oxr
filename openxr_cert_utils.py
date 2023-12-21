# Copyright 2023, Collabora, Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Original author: Rylie Pavlik <rylie.pavlik@collabora.com>
"""Shared utils for OpenXR signing."""
from dataclasses import dataclass, field
import datetime
from typing import Optional, cast
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

CA_DURATION = 50 * 365
"""The approximate number of days in 50 years"""

DEFAULT_DURATION = 10 * 365
"""The approximate number of days in 10 years"""

ROOT_STEM = "xr_root_x1"

PUBLIC_PATH = Path("id_public")
PRIVATE_PATH = Path("id_private")


_KEY_USAGE_SIGNING_ONLY = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)


def make_private_p12_path(fn_stem: str) -> Path:
    """Compute a path for a private PKCS12 file, and ensure the directory exists."""
    PRIVATE_PATH.mkdir(exist_ok=True)
    return PRIVATE_PATH / f"{fn_stem}_private.p12"


def make_public_pem_crt_path(fn_stem: str) -> Path:
    """
    Compute a path for a public certificate file, and ensure the directory exists.

    File is intended to be in PEM format, with a .crt extension.
    """
    PUBLIC_PATH.mkdir(exist_ok=True)
    return PUBLIC_PATH / f"{fn_stem}.crt"


def make_x509_name(common_name):
    """Make an OpenXR OID."""
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Oregon"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Beaverton"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "The Khronos Group Inc"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, "OpenXR Working Group"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "openxr-speceditor@khronos.org"),
        ]
    )


def generate_private_key() -> rsa.RSAPrivateKey:
    """Generate a 4096-bit RSA key."""
    # Recommended parameters per documentation
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def make_key_and_csr(name):
    """Return a key and associated CSR."""
    key = generate_private_key()

    subject = make_x509_name(name)

    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(ski, False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            _KEY_USAGE_SIGNING_ONLY,
            True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, csr


def _compute_dates(
    default_days=DEFAULT_DURATION,
    not_before: Optional[datetime.datetime] = None,
    not_after: Optional[datetime.datetime] = None,
) -> tuple[datetime.datetime, datetime.datetime]:
    if not_before is None:
        not_before = datetime.datetime.now(datetime.timezone.utc)
    if not_after is None:
        not_after = not_before + datetime.timedelta(days=default_days)
    return (not_before, not_after)


@dataclass
class CertAuth:
    """A little certification authority for limited uses."""

    subject: x509.Name
    key: rsa.RSAPrivateKey
    cert: Optional[x509.Certificate] = None

    extra_certs: list[x509.Certificate] = field(default_factory=list)

    def sign_csr(self, csr: x509.CertificateSigningRequest):
        """Generate a certificate for a CSR after checking it requests what we offer."""
        assert self.cert
        ski_ext = csr.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)

        basic_constraints = csr.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        if basic_constraints.value.ca is not False:
            raise RuntimeError("This CSR says it is for a CA!")

        key_usage = csr.extensions.get_extension_for_class(x509.KeyUsage)
        if key_usage.value != _KEY_USAGE_SIGNING_ONLY:
            raise RuntimeError("This CSR key usage does not match what we expect!")

        if ski_ext.value != x509.SubjectKeyIdentifier.from_public_key(csr.public_key()):
            raise RuntimeError(
                "This CSR SubjectKeyIdentifier does not match what we expect!"
            )

        return self.make_cert(csr.subject, csr.public_key())

    def make_cert(
        self,
        subject: x509.Name,
        public_key,
        not_after: Optional[datetime.datetime] = None,
        not_before: Optional[datetime.datetime] = None,
    ):
        """Generate a 'signer'-class certificate for the subject and public key."""
        assert self.cert

        print(f"Signing certificate for {subject.rfc4514_string()}")
        not_before, not_after = _compute_dates(
            DEFAULT_DURATION, not_before=not_before, not_after=not_after
        )
        print(f"Not valid before {not_before}, not valid after {not_after}")
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            # not a CA
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            # just signing
            .add_extension(
                _KEY_USAGE_SIGNING_ONLY,
                True,
            )
            # subject key
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
            # authority key
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self.cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier
                    ).value
                ),
                False,
            )
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )
        return builder.sign(self.key, algorithm=hashes.SHA256())

    @classmethod
    def generate(
        cls,
        name,
        not_after: Optional[datetime.datetime] = None,
        not_before: Optional[datetime.datetime] = None,
    ):
        """Generate a private key and self-signed cert for a new mini CA."""
        key = generate_private_key()

        subject = make_x509_name(name)

        # self signed
        # issuer = subject

        print(f"Making and signing certificate for {name}")

        basic_constraints = x509.BasicConstraints(ca=True, path_length=3)
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

        not_before, not_after = _compute_dates(
            CA_DURATION, not_before=not_before, not_after=not_after
        )

        print(f"Not valid before {not_before}, not valid after {not_after}")
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(ski, False)
            .add_extension(basic_constraints, True)
            .add_extension(
                key_usage,
                True,
            )
        ).sign(key, algorithm=hashes.SHA256())

        return cls(subject=subject, key=key, cert=cert)

    def save(self, fn_stem: str, password: bytes):
        """Save the keys and certificates making this CA to a PKCS#12 file."""
        assert self.cert

        path = make_private_p12_path(fn_stem)
        print(f"Writing CA key and certificate to {path}")
        with open(path, "wb") as f:
            f.write(
                pkcs12.serialize_key_and_certificates(
                    b"CA",
                    self.key,
                    self.cert,
                    None,
                    serialization.BestAvailableEncryption(password),
                )
            )

    def save_ca_cert(self, fn_stem):
        """Save the CA's self-signed certificate."""
        assert self.cert

        with open(f"{fn_stem}.crt", "wb") as f:
            f.write(self.cert.public_bytes(encoding=serialization.Encoding.PEM))

    @classmethod
    def load(cls, fn_stem: str, password: bytes):
        """Load a CA from a PKCS#12 file."""
        path = make_private_p12_path(fn_stem)
        print(f"Loading CA key and certificate from {path}")
        with open(path, "rb") as f:
            key, cert, _ = pkcs12.load_key_and_certificates(
                f.read(),
                password,
            )
        assert cert
        return cls(subject=cert.subject, key=cast(rsa.RSAPrivateKey, key), cert=cert)
