from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

AGGREGATION_POLICIES = ("ALL_MUST_PASS", "ANY_DETECTION", "FIRST_DETECTION", "FIRST_SUCCESS")
ENCRYPTED_POLICIES = ("ALLOW", "DENY", "QUARANTINE", "MARK_FOR_REVIEW")

DEFAULT_AGGREGATION_POLICY = "ALL_MUST_PASS"
DEFAULT_ENCRYPTED_POLICY = "DENY"


@dataclass(frozen=True)
class ScannerOutcome:
    scanner_name: str
    status: str  # CLEAN | INFECTED | ERROR
    threat: Optional[str] = None


@dataclass(frozen=True)
class AggregationDecision:
    status: str  # CLEAN | INFECTED | ERROR
    allowed: bool
    threat: Optional[str]
    reason: str


def aggregate_scan_results(results: List[ScannerOutcome], policy: str) -> AggregationDecision:
    """
    Combines N per-scanner outcomes (one per row in `scan_results`) into
    a single verdict, per a scanner profile's `aggregation_policy`.

    Fail-closed invariant: the ONLY way this function returns
    allowed=True is an explicit CLEAN determination backed by at least
    one real scanner result. Zero results, or every scanner erroring,
    always returns ERROR/allowed=False - never CLEAN by default.
    """
    if not results:
        return AggregationDecision("ERROR", False, None, "No scanner results available")

    infected = [r for r in results if r.status == "INFECTED"]
    errors = [r for r in results if r.status == "ERROR"]
    clean = [r for r in results if r.status == "CLEAN"]

    if policy == "FIRST_DETECTION":
        # The first configured scanner (list/profile order) to report
        # INFECTED wins immediately. Absent any detection, still requires
        # every scanner to have actually succeeded - an ERROR blocks,
        # same as ALL_MUST_PASS, because "no detection" from a scanner
        # that never ran proves nothing.
        if infected:
            first = infected[0]
            return AggregationDecision(
                "INFECTED", False, first.threat, f"{first.scanner_name} detected {first.threat}"
            )
        if errors:
            names = ", ".join(r.scanner_name for r in errors)
            return AggregationDecision("ERROR", False, None, f"Scanner(s) failed before a detection could be ruled out: {names}")
        return AggregationDecision("CLEAN", True, None, f"No scanner (of {len(results)}) detected a threat")

    if policy == "FIRST_SUCCESS":
        # Trusts the FIRST scanner (in list/profile order) that actually
        # completed (CLEAN or INFECTED), skipping over any that errored -
        # useful for a "primary scanner with a fallback" profile where an
        # occasional primary-scanner outage shouldn't block every upload.
        for r in results:
            if r.status == "INFECTED":
                return AggregationDecision("INFECTED", False, r.threat, f"{r.scanner_name} detected {r.threat}")
            if r.status == "CLEAN":
                return AggregationDecision("CLEAN", True, None, f"{r.scanner_name} completed successfully (first of {len(results)})")
        return AggregationDecision("ERROR", False, None, f"All {len(results)} configured scanner(s) failed")

    if policy == "ANY_DETECTION":
        # Only an actual malware detection produces INFECTED. Unlike
        # ALL_MUST_PASS, a scanner ERROR does NOT by itself block the
        # file as long as at least one OTHER scanner produced a real
        # CLEAN verdict - this policy is specifically for tolerating a
        # flaky/unavailable secondary scanner. Use ALL_MUST_PASS if any
        # scanner outage should itself deny the file. Zero usable results
        # (every scanner errored) still fails closed - "ANY detection"
        # never means "assume clean when we have no evidence at all".
        if infected:
            names = ", ".join(r.scanner_name for r in infected)
            return AggregationDecision("INFECTED", False, infected[0].threat, f"Detected by: {names}")
        if clean:
            note = f"; {len(errors)} scanner(s) failed and were ignored" if errors else ""
            return AggregationDecision("CLEAN", True, None, f"{len(clean)} scanner(s) reported clean{note}")
        return AggregationDecision("ERROR", False, None, "All scanners failed - no results to evaluate")

    if policy == "ALL_MUST_PASS":
        if infected:
            names = ", ".join(r.scanner_name for r in infected)
            return AggregationDecision("INFECTED", False, infected[0].threat, f"Detected by: {names}")
        if errors:
            names = ", ".join(r.scanner_name for r in errors)
            return AggregationDecision("ERROR", False, None, f"{len(errors)} scanner(s) failed: {names}")
        return AggregationDecision("CLEAN", True, None, f"All {len(clean)} scanner(s) reported clean")

    return AggregationDecision("ERROR", False, None, f"Unknown aggregation_policy: {policy!r} - failing closed")


@dataclass(frozen=True)
class EncryptedPolicyDecision:
    status: str  # always "ENCRYPTED"
    allowed: bool
    needs_review: bool
    quarantine: bool
    reason: str


def resolve_encrypted_policy(category: str, policies: Dict[str, str]) -> str:
    """`policies` is the encrypted_file_policies table as a dict
    (category -> policy). Falls back to the 'default' row, then to
    DEFAULT_ENCRYPTED_POLICY if even that is somehow missing."""
    return policies.get(category) or policies.get("default") or DEFAULT_ENCRYPTED_POLICY


def apply_encrypted_policy(policy: str, category: str) -> EncryptedPolicyDecision:
    """
    Encrypted files skip scanner execution entirely (most scanners can't
    inspect content they can't decrypt) - this decision is the ENTIRE
    verdict for such a file, not an input to further scanning. `status`
    is always "ENCRYPTED" regardless of policy (callers always know a
    file was encrypted); `allowed` reflects the administrator's POLICY
    choice, decoupled from what happened - matches how the rest of this
    project separates "what was observed" from "what the policy decided".
    """
    if policy == "ALLOW":
        return EncryptedPolicyDecision("ENCRYPTED", True, False, False, f"Encrypted file ({category}) allowed by policy")
    if policy == "DENY":
        return EncryptedPolicyDecision("ENCRYPTED", False, False, False, f"Encrypted file ({category}) denied by policy")
    if policy == "QUARANTINE":
        return EncryptedPolicyDecision("ENCRYPTED", False, False, True, f"Encrypted file ({category}) quarantined by policy")
    if policy == "MARK_FOR_REVIEW":
        return EncryptedPolicyDecision("ENCRYPTED", False, True, True, f"Encrypted file ({category}) marked for manual review")
    return EncryptedPolicyDecision("ENCRYPTED", False, False, False, f"Unknown encrypted policy {policy!r} - failing closed")
