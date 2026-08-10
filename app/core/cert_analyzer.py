"""
X.509 Certificate Extractor and Deep Cryptographic Analyzer.
"""
import ssl
import socket
import datetime
import hashlib
import fnmatch
from typing import Dict, List, Optional, Any, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
from cryptography.x509.oid import (
    NameOID, ExtensionOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
)


class CertificateAnalyzer:
    """Extracts, decodes and analyzes remote and local X.509 certificates."""

    @staticmethod
    def normalize_target(target: str, default_port: int = 443) -> Tuple[str, int]:
        """Normalizes hostname/URL and extracts host and port."""
        target = target.strip()
        # Remove scheme if present
        if target.startswith("https://"):
            target = target[8:]
        elif target.startswith("http://"):
            target = target[7:]
        
        # Remove path or query
        if "/" in target:
            target = target.split("/")[0]
        
        # Extract port if specified
        if ":" in target and not target.endswith("]"): # not ipv6 without port
            parts = target.rsplit(":", 1)
            try:
                port = int(parts[1])
                return parts[0], port
            except ValueError:
                pass
        return target, default_port

    @classmethod
    def fetch_raw_certificates(cls, host: str, port: int = 443, timeout: float = 6.0) -> Tuple[bytes, List[bytes], Optional[str]]:
        """
        Connects via TLS socket to fetch the leaf DER certificate and intermediate DER certs.
        Uses unverified context for extraction so we can analyze expired/self-signed certs as well.
        """
        # Create unverified context to allow pulling cert regardless of trust state
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Enable all TLS versions supported
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except Exception:
            pass

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        raise ValueError("No certificate presented by server.")
                    
                    # Try to retrieve verified or unverified chain if supported by Python/OpenSSL
                    chain_ders = []
                    # ssock.get_verified_chain() is available in newer Python versions
                    if hasattr(ssock, "get_verified_chain"):
                        try:
                            verified_chain = ssock.get_verified_chain()
                            if verified_chain:
                                chain_ders = [c.public_bytes(serialization.Encoding.DER) if hasattr(c, 'public_bytes') else c for c in verified_chain]
                        except Exception:
                            pass

                    # Fallback to single cert if chain unavailable
                    if not chain_ders:
                        chain_ders = [der_cert]

                    cipher_info = ssock.cipher()
                    tls_version = ssock.version()
                    return der_cert, chain_ders, tls_version
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {host}:{port} - {str(e)}")

    @classmethod
    def parse_x509(cls, der_bytes: bytes, target_host: Optional[str] = None) -> Dict[str, Any]:
        """Deeply parses a DER X.509 certificate and returns a structured dictionary."""
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())

        # Subject extraction
        subject_data = cls._extract_name_dict(cert.subject)
        
        # Issuer extraction
        issuer_data = cls._extract_name_dict(cert.issuer)

        # Dates & Expiration
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            # Older cryptography versions
            not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        now = datetime.datetime.now(datetime.timezone.utc)
        
        days_remaining = (not_after - now).days
        total_validity_days = max(1, (not_after - not_before).days)
        days_elapsed = (now - not_before).days
        
        if total_validity_days > 0:
            validity_percentage = round(min(100.0, max(0.0, (days_elapsed / total_validity_days) * 100)), 1)
        else:
            validity_percentage = 100.0

        # Expiry Status
        if now > not_after:
            expiry_status = "EXPIRED"
            expiry_message = f"Certificate expired {abs(days_remaining)} day(s) ago on {not_after.strftime('%Y-%m-%d %H:%M UTC')}."
            expiry_severity = "CRITICAL"
        elif now < not_before:
            expiry_status = "NOT_YET_VALID"
            expiry_message = f"Certificate is not valid before {not_before.strftime('%Y-%m-%d %H:%M UTC')}."
            expiry_severity = "CRITICAL"
        elif days_remaining <= 7:
            expiry_status = "EXPIRING_CRITICAL"
            expiry_message = f"URGENT: Certificate expires in {days_remaining} day(s) ({not_after.strftime('%Y-%m-%d')})."
            expiry_severity = "CRITICAL"
        elif days_remaining <= 30:
            expiry_status = "EXPIRING_SOON"
            expiry_message = f"WARNING: Certificate expires in {days_remaining} day(s) ({not_after.strftime('%Y-%m-%d')})."
            expiry_severity = "WARNING"
        elif days_remaining <= 60:
            expiry_status = "EXPIRING_UPCOMING"
            expiry_message = f"Notice: Certificate expires in {days_remaining} day(s)."
            expiry_severity = "INFO"
        else:
            expiry_status = "VALID"
            expiry_message = f"Certificate is valid for another {days_remaining} day(s)."
            expiry_severity = "GOOD"

        # Subject Alternative Names (SANs)
        sans = cls._extract_sans(cert)
        
        # Hostname matching
        hostname_match = None
        if target_host:
            hostname_match = cls.check_hostname_match(target_host, subject_data.get("common_name"), sans)

        # Public Key Specs
        key_info = cls._extract_public_key_info(cert.public_key())

        # Signature Algorithm & Hash
        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert, 'signature_algorithm_oid') else "unknown"
        sig_hash_name = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "UNKNOWN"
        
        is_weak_sig = sig_hash_name in ["MD5", "MD2", "SHA1", "UNKNOWN"]

        # Fingerprints
        sha256_fp = cls._format_fingerprint(cert.fingerprint(hashes.SHA256()))
        sha1_fp = cls._format_fingerprint(cert.fingerprint(hashes.SHA1()))
        md5_fp = cls._format_fingerprint(cert.fingerprint(hashes.MD5()))

        # Extensions
        extensions_data = cls._extract_extensions(cert)

        # Self-Signed check (Leaf)
        is_self_signed = (cert.subject == cert.issuer)

        # Serial Number
        serial_decimal = str(cert.serial_number)
        serial_hex = f"{cert.serial_number:02X}"
        serial_formatted = ":".join([serial_hex[i:i+2] for i in range(0, len(serial_hex), 2)])

        # Raw PEM
        pem_str = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

        return {
            "subject": subject_data,
            "issuer": issuer_data,
            "serial_number": {
                "decimal": serial_decimal,
                "hex": serial_formatted
            },
            "version": f"v{cert.version.value + 1}" if hasattr(cert.version, 'value') else str(cert.version),
            "validity": {
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "not_before_formatted": not_before.strftime("%b %d, %Y %H:%M:%S UTC"),
                "not_after_formatted": not_after.strftime("%b %d, %Y %H:%M:%S UTC"),
                "days_remaining": days_remaining,
                "days_elapsed": days_elapsed,
                "total_validity_days": total_validity_days,
                "validity_percentage": validity_percentage,
                "expiry_status": expiry_status,
                "expiry_message": expiry_message,
                "expiry_severity": expiry_severity
            },
            "subject_alternative_names": sans,
            "hostname_match": hostname_match,
            "public_key": key_info,
            "signature": {
                "algorithm": sig_algo,
                "hash": sig_hash_name,
                "is_weak": is_weak_sig
            },
            "fingerprints": {
                "sha256": sha256_fp,
                "sha1": sha1_fp,
                "md5": md5_fp
            },
            "is_self_signed": is_self_signed,
            "extensions": extensions_data,
            "pem": pem_str
        }

    @staticmethod
    def _extract_name_dict(name: x509.Name) -> Dict[str, Any]:
        """Extracts standard attributes from an X.509 Name."""
        def get_val(oid):
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else None

        return {
            "common_name": get_val(NameOID.COMMON_NAME),
            "organization": get_val(NameOID.ORGANIZATION_NAME),
            "organizational_unit": get_val(NameOID.ORGANIZATIONAL_UNIT_NAME),
            "country": get_val(NameOID.COUNTRY_NAME),
            "state": get_val(NameOID.STATE_OR_PROVINCE_NAME),
            "locality": get_val(NameOID.LOCALITY_NAME),
            "email": get_val(NameOID.EMAIL_ADDRESS),
            "rfc4514_string": name.rfc4514_string()
        }

    @staticmethod
    def _extract_sans(cert: x509.Certificate) -> List[str]:
        """Extracts Subject Alternative Names (DNS names and IP addresses)."""
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    sans.append(str(name.value))
                elif isinstance(name, x509.UniformResourceIdentifier):
                    sans.append(name.value)
        except x509.ExtensionNotFound:
            pass
        return sans

    @classmethod
    def check_hostname_match(cls, target_host: str, common_name: Optional[str], sans: List[str]) -> Dict[str, Any]:
        """
        Validates if target hostname matches CN or SANs including wildcard evaluation.
        """
        target = target_host.lower().strip()
        matched_pattern = None
        is_matched = False
        all_candidates = list(sans)
        if common_name and common_name not in all_candidates:
            all_candidates.append(common_name)

        for candidate in all_candidates:
            cand = candidate.lower().strip()
            # Exact match
            if target == cand:
                is_matched = True
                matched_pattern = candidate
                break
            # Wildcard match (e.g. *.example.com)
            if cand.startswith("*."):
                suffix = cand[2:]
                # *.example.com matches sub.example.com but NOT sub.nested.example.com and NOT example.com
                if "." in target:
                    prefix, target_suffix = target.split(".", 1)
                    if target_suffix == suffix and "." not in prefix:
                        is_matched = True
                        matched_pattern = candidate
                        break

        return {
            "is_matched": is_matched,
            "target_host": target_host,
            "matched_pattern": matched_pattern,
            "checked_candidates_count": len(all_candidates),
            "candidates": all_candidates[:15] # first 15 for summary
        }

    @staticmethod
    def _extract_public_key_info(public_key) -> Dict[str, Any]:
        """Extracts public key algorithm, key length and security rating."""
        if isinstance(public_key, rsa.RSAPublicKey):
            size = public_key.key_size
            is_weak = size < 2048
            is_strong = size >= 4096
            return {
                "algorithm": "RSA",
                "key_size_bits": size,
                "is_weak": is_weak,
                "is_strong": is_strong,
                "description": f"RSA {size}-bit ({'Weak! <2048-bit' if is_weak else 'Standard' if size < 4096 else 'High Security'})"
            }
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name
            size = public_key.key_size
            is_weak = size < 256
            return {
                "algorithm": "ECDSA",
                "curve": curve_name,
                "key_size_bits": size,
                "is_weak": is_weak,
                "is_strong": size >= 384,
                "description": f"ECDSA {curve_name} ({size}-bit)"
            }
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return {
                "algorithm": "Ed25519",
                "key_size_bits": 256,
                "is_weak": False,
                "is_strong": True,
                "description": "Ed25519 (Modern High-Security Edwards Curve)"
            }
        elif isinstance(public_key, ed448.Ed448PublicKey):
            return {
                "algorithm": "Ed448",
                "key_size_bits": 448,
                "is_weak": False,
                "is_strong": True,
                "description": "Ed448 (Ultra High-Security Edwards Curve)"
            }
        elif isinstance(public_key, dsa.DSAPublicKey):
            size = public_key.key_size
            return {
                "algorithm": "DSA",
                "key_size_bits": size,
                "is_weak": True,
                "is_strong": False,
                "description": f"DSA {size}-bit (Deprecated)"
            }
        else:
            return {
                "algorithm": "Unknown",
                "key_size_bits": 0,
                "is_weak": True,
                "is_strong": False,
                "description": "Unknown Key Algorithm"
            }

    @staticmethod
    def _extract_extensions(cert: x509.Certificate) -> Dict[str, Any]:
        """Extracts X.509 extensions."""
        exts: Dict[str, Any] = {
            "basic_constraints": None,
            "key_usage": [],
            "extended_key_usage": [],
            "ocsp_urls": [],
            "ca_issuers_urls": [],
            "crl_distribution_points": [],
            "subject_key_identifier": None,
            "authority_key_identifier": None,
            "certificate_policies": []
        }

        for ext in cert.extensions:
            oid = ext.oid
            val = ext.value

            if oid == ExtensionOID.BASIC_CONSTRAINTS:
                exts["basic_constraints"] = {
                    "is_ca": val.ca,
                    "path_length": val.path_length
                }
            elif oid == ExtensionOID.KEY_USAGE:
                usages = []
                flags = [
                    ("digital_signature", "Digital Signature"),
                    ("content_commitment", "Content Commitment"),
                    ("key_encipherment", "Key Encipherment"),
                    ("data_encipherment", "Data Encipherment"),
                    ("key_agreement", "Key Agreement"),
                    ("key_cert_sign", "Certificate Sign"),
                    ("crl_sign", "CRL Sign"),
                    ("encipher_only", "Encipher Only"),
                    ("decipher_only", "Decipher Only")
                ]
                for attr, name in flags:
                    try:
                        if getattr(val, attr):
                            usages.append(name)
                    except ValueError:
                        pass
                exts["key_usage"] = usages

            elif oid == ExtensionOID.EXTENDED_KEY_USAGE:
                eku_list = []
                for u in val:
                    eku_list.append(u._name if hasattr(u, '_name') else str(u.dotted_string))
                exts["extended_key_usage"] = eku_list

            elif oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                for access_desc in val:
                    if access_desc.access_method == AuthorityInformationAccessOID.OCSP:
                        if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                            exts["ocsp_urls"].append(access_desc.access_location.value)
                    elif access_desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                        if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                            exts["ca_issuers_urls"].append(access_desc.access_location.value)

            elif oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                crls = []
                for dp in val:
                    if dp.full_name:
                        for fn in dp.full_name:
                            if isinstance(fn, x509.UniformResourceIdentifier):
                                crls.append(fn.value)
                exts["crl_distribution_points"] = crls

            elif oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                exts["subject_key_identifier"] = val.digest.hex().upper()

            elif oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                if val.key_identifier:
                    exts["authority_key_identifier"] = val.key_identifier.hex().upper()

            elif oid == ExtensionOID.CERTIFICATE_POLICIES:
                policies = []
                for p in val:
                    policies.append(p.policy_identifier.dotted_string)
                exts["certificate_policies"] = policies

        return exts

    @staticmethod
    def _format_fingerprint(raw_bytes: bytes) -> str:
        """Formats bytes into standard colon-separated hex format."""
        h = raw_bytes.hex().upper()
        return ":".join([h[i:i+2] for i in range(0, len(h), 2)])
