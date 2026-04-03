#!/usr/bin/env python3

"""Generate a self-signed CA and client certificate."""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CA_DIR = Path("CA")
CA_CERT_PATH = CA_DIR / "ca.crt"
CA_KEY_PATH = CA_DIR / "ca.key"
CA_VALIDITY_DAYS = 3650
CLIENT_VALIDITY_DAYS = 365
PASSPHRASE_ENV_VAR = "DIGITAL_CERT_PASSPHRASE"


def prompt_value(label: str, default: str = "") -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def prompt_required(label: str) -> str:
    while True:
        value = input(f"{label}: ").strip()
        if value:
            return value
        print("Please provide a non-empty value.")


def get_passphrase(confirm: bool = False) -> bytes:
    env_passphrase = os.environ.get(PASSPHRASE_ENV_VAR)
    if env_passphrase:
        return env_passphrase.encode("utf-8")

    while True:
        passphrase = getpass.getpass("Private key passphrase: ")
        if not passphrase:
            print("A passphrase is required to protect the private key.")
            continue
        if not confirm:
            return passphrase.encode("utf-8")

        confirmation = getpass.getpass("Confirm private key passphrase: ")
        if passphrase == confirmation:
            return passphrase.encode("utf-8")
        print("Passphrases do not match.")


def build_subject() -> x509.Name:
    values = [
        (NameOID.COUNTRY_NAME, prompt_value("Country Name (2 letter code)", "XX")),
        (NameOID.STATE_OR_PROVINCE_NAME, prompt_value("State or Province Name (full name)")),
        (NameOID.LOCALITY_NAME, prompt_value("Locality Name (eg, city)", "Default City")),
        (NameOID.ORGANIZATION_NAME, prompt_value("Organization Name (eg, company)", "Default Company Ltd")),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, prompt_value("Organizational Unit Name (eg, section)")),
        (NameOID.COMMON_NAME, prompt_required("Common Name (eg, your name or your server's hostname)")),
        (NameOID.EMAIL_ADDRESS, prompt_value("Email Address")),
    ]

    attributes = []
    for oid, value in values:
        value = value.strip()
        if value:
            if oid == NameOID.COUNTRY_NAME and len(value) != 2:
                raise ValueError("Country Name must be a 2 letter code.")
            attributes.append(x509.NameAttribute(oid, value))
    return x509.Name(attributes)


def create_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def write_bytes(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as file_obj:
        file_obj.write(data)


def build_output_stem(common_name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", common_name.strip()).strip("._-")
    if not sanitized:
        raise ValueError("Common Name must contain at least one safe filename character.")
    return sanitized


def build_subject_alternative_name(common_name: str) -> x509.SubjectAlternativeName | None:
    try:
        ip_value = ipaddress.ip_address(common_name)
        return x509.SubjectAlternativeName([x509.IPAddress(ip_value)])
    except ValueError:
        pass

    if "@" in common_name:
        return x509.SubjectAlternativeName([x509.RFC822Name(common_name)])

    if re.fullmatch(r"[A-Za-z0-9.-]+", common_name):
        return x509.SubjectAlternativeName([x509.DNSName(common_name)])

    return None


def certificate_expiry(certificate: x509.Certificate) -> datetime:
    if hasattr(certificate, "not_valid_after_utc"):
        return certificate.not_valid_after_utc
    return certificate.not_valid_after.replace(tzinfo=timezone.utc)


def create_ca(root_ca_path: Path, key_path: Path) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    ca_key = create_private_key()
    ca_subject = build_subject()
    now = datetime.now(timezone.utc)
    passphrase = get_passphrase(confirm=True)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    write_bytes(root_ca_path, ca_cert.public_bytes(serialization.Encoding.PEM))
    write_bytes(
        key_path,
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        ),
        mode=0o600,
    )
    return ca_cert, ca_key


def load_ca(root_ca_path: Path, key_path: Path) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    ca_cert = x509.load_pem_x509_certificate(root_ca_path.read_bytes())
    key_bytes = key_path.read_bytes()

    try:
        ca_key = serialization.load_pem_private_key(key_bytes, password=get_passphrase())
    except TypeError:
        ca_key = serialization.load_pem_private_key(key_bytes, password=None)

    return ca_cert, ca_key


def ca_verification(ca_cert: x509.Certificate) -> None:
    validity = (certificate_expiry(ca_cert) - datetime.now(timezone.utc)).days
    print(f"CA Certificate valid for {validity} days")


def create_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    client_cn: str,
) -> tuple[Path, Path]:
    client_key = create_private_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_cn)])
    output_stem = build_output_stem(client_cn)
    cert_path = Path(f"{output_stem}.crt")
    key_path = Path(f"{output_stem}.key")
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=CLIENT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    san_extension = build_subject_alternative_name(client_cn)
    if san_extension is not None:
        builder = builder.add_extension(san_extension, critical=False)

    client_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    passphrase = get_passphrase(confirm=True)

    write_bytes(cert_path, client_cert.public_bytes(serialization.Encoding.PEM))
    write_bytes(
        key_path,
        client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        ),
        mode=0o600,
    )
    return cert_path, key_path


def ensure_ca_material() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    CA_DIR.mkdir(mode=0o700, exist_ok=True)

    if CA_CERT_PATH.exists() and not CA_KEY_PATH.exists():
        raise FileNotFoundError(f"Missing CA private key: {CA_KEY_PATH}")

    if CA_KEY_PATH.exists() and not CA_CERT_PATH.exists():
        raise FileNotFoundError(f"Missing CA certificate: {CA_CERT_PATH}")

    if not CA_CERT_PATH.exists():
        print("Creating CA Certificate, please provide the values")
        ca_cert, ca_key = create_ca(CA_CERT_PATH, CA_KEY_PATH)
        print("Created CA Certificate")
    else:
        print(f"CA certificate has been found as {CA_CERT_PATH}")
        ca_cert, ca_key = load_ca(CA_CERT_PATH, CA_KEY_PATH)

    ca_verification(ca_cert)
    return ca_cert, ca_key


def main() -> None:
    """Create self-signed certificates."""

    ca_cert, ca_key = ensure_ca_material()
    client_cn = prompt_required("Client Certificate CN")
    cert_path, key_path = create_cert(ca_cert, ca_key, client_cn)
    print(f"Created client certificate: {cert_path}")
    print(f"Created private key: {key_path}")


if __name__ == "__main__":
    main()
