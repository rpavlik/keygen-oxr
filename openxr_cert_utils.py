# Copyright 2023, Collabora, Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Original author: Rylie Pavlik <rylie.pavlik@collabora.com>
"""Shared utils for OpenXR signing."""
from dataclasses import dataclass, field
import datetime
from typing import Optional, cast

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


def _make_and_save_private_key(fn_stem, encryption) -> rsa.RSAPrivateKey:
    """Generate and save a 4096-bit RSA key."""
    print("Making private key")
    key: rsa.RSAPrivateKey = generate_private_key()

    with open(f"{fn_stem}_private.pem", "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption,
            )
        )
    return key


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
    ):
        """Generate a 'signer'-class certificate for the subject and public key."""
        assert self.cert

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
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=DEFAULT_DURATION)
            )
        )
        return builder.sign(self.key, algorithm=hashes.SHA256())

    @classmethod
    def generate(cls, name):
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

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now() + datetime.timedelta(days=CA_DURATION)
            )
            .add_extension(ski, False)
            .add_extension(basic_constraints, True)
            .add_extension(
                key_usage,
                True,
            )
        ).sign(key, algorithm=hashes.SHA256())

        return cls(subject=subject, key=key, cert=cert)

    def save(self, fn_stem, password):
        """Save the keys and certificates making this CA to a PKCS#12 file."""
        assert self.cert

        fn = f"{fn_stem}_private.p12"
        print(f"Writing CA key and certificate to {fn}")
        with open(fn, "wb") as f:
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
    def load(cls, fn_stem, password):
        """Load a CA from a PKCS#12 file."""
        fn = f"{fn_stem}_private.p12"
        print(f"Loading CA key and certificate from {fn}")
        with open(f"{fn_stem}_private.p12", "rb") as f:
            key, cert, _ = pkcs12.load_key_and_certificates(
                f.read(),
                password,
            )
        assert cert
        return cls(subject=cert.subject, key=cast(rsa.RSAPrivateKey, key), cert=cert)
