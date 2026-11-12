"""Fail-closed X.509 path and revocation checks using the system OpenSSL CLI.

The trust bundle, CRLs and policy OID must be provisioned out-of-band by the
institution. No AIA URL is trusted as a new trust anchor.
"""
from __future__ import annotations
import subprocess
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import AuthorityInformationAccessOID


class X509PolicyError(ValueError):
    pass


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def validate_certificate_policy(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    trust_bundle: str | Path,
    *,
    crl_bundle: str | Path | None = None,
    policy_oid: str | None = None,
    revocation: str = "crl",
    openssl: str = "openssl",
    timeout: int = 15,
) -> dict:
    """Validate chain, validity, CA constraints, purpose and policy; fail closed.

    revocation='crl' checks the full chain against a provisioned CRL bundle.
    revocation='ocsp' queries the leaf certificate's signed AIA responder.
    revocation='both' requires both mechanisms to report good.
    """
    if revocation not in {"crl", "ocsp", "both"}:
        raise X509PolicyError("revocation must be crl, ocsp, or both")
    if not policy_oid:
        raise X509PolicyError("An institution-approved certificate policy OID is mandatory")
    roots = Path(trust_bundle)
    if not roots.is_file() or not roots.read_bytes().strip():
        raise X509PolicyError("Pinned trust bundle is missing or empty")
    with tempfile.TemporaryDirectory(prefix="huc-x509-") as tmp:
        tmpdir = Path(tmp)
        untrusted = tmpdir / "intermediates.pem"
        untrusted.write_bytes(b"".join(_pem(c) for c in intermediates))
        leaf_path = tmpdir / "leaf.pem"
        leaf_path.write_bytes(_pem(leaf))
        command = [openssl, "verify", "-CAfile", str(roots),
                   "-purpose", "any", "-auth_level", "2",
                   "-x509_strict", "-policy_check", "-explicit_policy"]
        if intermediates:
            command += ["-untrusted", str(untrusted)]
        if policy_oid:
            command += ["-policy", policy_oid]
        if revocation in {"crl", "both"}:
            if crl_bundle is None or not Path(crl_bundle).is_file():
                raise X509PolicyError("CRL bundle required; revocation status unavailable")
            command += ["-CRLfile", str(crl_bundle), "-crl_check_all"]
        command.append(str(leaf_path))
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise X509PolicyError("X.509 path/policy/CRL validation failed: " +
                                  (result.stderr.strip() or result.stdout.strip()))
        ocsp_status = "NOT_REQUESTED"
        if revocation in {"ocsp", "both"}:
            try:
                aia = leaf.extensions.get_extension_for_class(
                    x509.AuthorityInformationAccess).value
                urls = [item.access_location.value for item in aia
                        if item.access_method == AuthorityInformationAccessOID.OCSP
                        and isinstance(item.access_location, x509.UniformResourceIdentifier)]
            except x509.ExtensionNotFound:
                urls = []
            if not urls:
                raise X509PolicyError("No OCSP responder URI in certificate AIA")
            issuer_candidates = [c for c in intermediates if leaf.issuer == c.subject]
            if not issuer_candidates:
                # A root may directly issue the leaf; OpenSSL uses the trust bundle.
                issuer_path = roots
            else:
                issuer_path = tmpdir / "issuer.pem"
                issuer_path.write_bytes(_pem(issuer_candidates[0]))
            good = False
            errors = []
            for url in urls:
                ocsp = subprocess.run(
                    [openssl, "ocsp", "-issuer", str(issuer_path), "-cert", str(leaf_path),
                     "-url", url, "-CAfile", str(roots), "-no_nonce"],
                    capture_output=True, text=True, timeout=timeout)
                output = ocsp.stdout + ocsp.stderr
                if ocsp.returncode == 0 and "good" in output.lower() and "revoked" not in output.lower():
                    good = True
                    break
                errors.append(output.strip())
            if not good:
                raise X509PolicyError("OCSP did not confirm good status: " + "; ".join(errors))
            ocsp_status = "GOOD"
        return {"chain_valid": True, "policy_checked": True,
                "revocation_status": "GOOD" if revocation in {"crl", "both"} else ocsp_status,
                "ocsp_status": ocsp_status, "revocation_mode": revocation,
                "production_ready": False,
                "production_note": "Pilot verifier; OCSP currently checks the leaf certificate only. Complete chain-wide OCSP and institutional policy review are required before production."}
