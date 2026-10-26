#!/usr/bin/env python3
"""Gera certificado autoassinado sintético para 127.0.0.1 (h2 e h3 de laboratório).

Nenhum certificado é instalado no sistema. O Chrome recebe apenas
--ignore-certificate-errors-spki-list=<hash da chave pública>, o que dispensa
tocar no chaveiro do usuário.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).resolve().parent
CERT = HERE / "localhost.pem"
KEY = HERE / "localhost-key.pem"
SPKI = HERE / "spki.txt"


def main() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki = base64.b64encode(hashlib.sha256(der).digest()).decode()
    SPKI.write_text(spki + "\n")
    print(f"cert={CERT}")
    print(f"key={KEY}")
    print(f"spki-sha256={spki}")


if __name__ == "__main__":
    main()
