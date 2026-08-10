"""
SSL/TLS Certificate Chain Validator and Trust Path Inspector.
"""
import ssl
import socket
import datetime
import certifi
import requests
from typing import List, Dict, Any, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

from app.core.cert_analyzer import CertificateAnalyzer


class CertificateChainValidator:
    """Validates X.509 certificate chains, trust stores, and hierarchy."""

    @classmethod
    def analyze_chain(cls, host: str, port: int = 443, timeout: float = 6.0) -> Dict[str, Any]:
        """
        Retrieves the certificate chain presented by the server, attempts AIA fetching
        if intermediate is missing, and validates trust against the Mozilla Root CA store.
        """
        # Step 1: Fetch raw certificates presented in handshake
        chain_certs_parsed = []
        raw_leaf_der = None
        chain_ders = []
        handshake_error = None

        try:
            raw_leaf_der, chain_ders, _ = CertificateAnalyzer.fetch_raw_certificates(host, port, timeout)
        except Exception as e:
            handshake_error = str(e)

        if not raw_leaf_der:
            return {
                "is_trusted": False,
                "is_complete": False,
                "is_self_signed": False,
                "trust_error": handshake_error or "Could not establish TLS connection.",
                "chain_length": 0,
                "certificates": [],
                "issues": [{"severity": "CRITICAL", "message": handshake_error or "Connection failed"}]
            }

        # Load all certificates returned by server
        loaded_certs: List[x509.Certificate] = []
        for der in chain_ders:
            try:
                c = x509.load_der_x509_certificate(der, default_backend())
                loaded_certs.append(c)
            except Exception:
                pass

        leaf_cert = loaded_certs[0]
        is_leaf_self_signed = (leaf_cert.subject == leaf_cert.issuer)

        # If only 1 cert returned and it's not self-signed, try AIA retrieval to get intermediate cert
        if len(loaded_certs) == 1 and not is_leaf_self_signed:
            intermediate_cert = cls._try_fetch_aia_intermediate(leaf_cert)
            if intermediate_cert:
                loaded_certs.append(intermediate_cert)

        # Build parsed info for each certificate in the chain
        chain_nodes = []
        for idx, cert in enumerate(loaded_certs):
            der = cert.public_bytes(serialization.Encoding.DER)
            parsed = CertificateAnalyzer.parse_x509(der, target_host=host if idx == 0 else None)
            
            is_root = (cert.subject == cert.issuer)
            is_intermediate = (idx > 0 and not is_root)
            role = "Leaf (End-Entity)" if idx == 0 else ("Root CA" if is_root else f"Intermediate CA {idx}")
            
            chain_nodes.append({
                "index": idx,
                "role": role,
                "is_leaf": (idx == 0),
                "is_intermediate": is_intermediate,
                "is_root": is_root,
                "subject_cn": parsed["subject"]["common_name"] or parsed["subject"]["organization"] or "Unknown",
                "issuer_cn": parsed["issuer"]["common_name"] or parsed["issuer"]["organization"] or "Unknown",
                "parsed": parsed
            })

        # Step 2: Validate signatures and trust path against standard CA store
        trust_status, issues = cls._verify_trust_store(host, port)
        
        # Check chain completeness
        is_complete = True
        if len(loaded_certs) == 1 and not is_leaf_self_signed and not trust_status["is_trusted"]:
            is_complete = False
            issues.append({
                "severity": "HIGH",
                "message": "Incomplete Certificate Chain: Server did not provide intermediate CA certificate. Some clients may fail to connect."
            })

        if is_leaf_self_signed:
            issues.append({
                "severity": "CRITICAL",
                "message": "Self-Signed Certificate: The certificate is self-signed and not issued by a recognized Certificate Authority (CA)."
            })

        # Check for expired certs anywhere in chain
        now = datetime.datetime.now(datetime.timezone.utc)
        for idx, node in enumerate(chain_nodes):
            not_after = datetime.datetime.fromisoformat(node["parsed"]["validity"]["not_after"])
            if now > not_after:
                issues.append({
                    "severity": "CRITICAL",
                    "message": f"Expired certificate in chain: {node['role']} ({node['subject_cn']}) expired on {not_after.strftime('%Y-%m-%d')}."
                })

        return {
            "is_trusted": trust_status["is_trusted"],
            "is_complete": is_complete,
            "is_self_signed": is_leaf_self_signed,
            "trust_error": trust_status.get("error"),
            "chain_length": len(chain_nodes),
            "certificates": chain_nodes,
            "issues": issues,
            "root_store": "Mozilla Root CA Store (certifi)"
        }

    @classmethod
    def _verify_trust_store(cls, host: str, port: int) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
        """
        Uses Python's verified SSL context against certifi bundle to determine if the chain
        is trusted by standard operating systems and browsers.
        """
        issues = []
        ctx = ssl.create_default_context(cafile=certifi.where())
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return {"is_trusted": True, "error": None}, issues
        except ssl.SSLCertVerificationError as e:
            err_msg = str(e.verify_message) if hasattr(e, 'verify_message') else str(e)
            issues.append({
                "severity": "CRITICAL",
                "message": f"Certificate Verification Failed: {err_msg}"
            })
            return {"is_trusted": False, "error": err_msg}, issues
        except Exception as e:
            return {"is_trusted": False, "error": str(e)}, issues

    @classmethod
    def _try_fetch_aia_intermediate(cls, leaf_cert: x509.Certificate) -> Optional[x509.Certificate]:
        """
        Extracts the Authority Information Access (AIA) caIssuers URL and attempts
        to download the intermediate certificate.
        """
        try:
            aia_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_desc in aia_ext.value:
                if access_desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    url = access_desc.access_location.value
                    if url.startswith("http://") or url.startswith("https://"):
                        resp = requests.get(url, timeout=3.0)
                        if resp.status_code == 200:
                            # AIA certs can be DER or PKCS#7
                            try:
                                return x509.load_der_x509_certificate(resp.content, default_backend())
                            except Exception:
                                pass
        except Exception:
            pass
        return None
