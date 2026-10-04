#!/usr/bin/env python3
"""
Bitcoin ECDSA Safe Audit

Purpose:
- defensive analysis of Bitcoin signatures and transaction patterns
- rate-limited, parallel API collection from public Bitcoin endpoints
- parsing/inspection of ECDSA DER signatures and scriptSig content
- detection of suspicious repeated-R / nonce-reuse signals

Safety:
- No private-key recovery logic
- No attack execution paths
- No secret extraction from wallet implementations

This project is designed for security research, wallet audits, and investigation workflows
under lawful and authorized conditions.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import aiohttp


BLOCKSTREAM_API = "https://blockstream.info/api/"
MEMPOOL_API = "https://mempool.space/api/"
RATE_LIMIT_PER_SEC = 5
MAX_CONCURRENT = 10


@dataclass
class SignatureAudit:
    address: str
    txid: str
    vin_index: int
    script_sig: Optional[str] = None
    validation: str = "unknown"
    signature_hex: Optional[str] = None
    r_hex: Optional[str] = None
    s_hex: Optional[str] = None
    der_length: Optional[int] = None
    repeated_r: bool = False
    warnings: List[str] = field(default_factory=list)


@dataclass
class AddressSummary:
    address: str
    tx_count: int
    suspicious_count: int
    signature_count: int
    repeated_r_count: int
    warnings: List[str] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safe Bitcoin ECDSA audit for repeated-R / nonce-risk signals")
    parser.add_argument("--addresses", nargs="+", required=True, help="Bitcoin addresses to audit")
    parser.add_argument("--limit", type=int, default=50, help="Max number of txs per address")
    parser.add_argument("--api", choices=["blockstream", "mempool"], default="blockstream", help="Public Bitcoin API source")
    parser.add_argument("--output", default="bitcoin_ecdsa_audit.json", help="Output JSON file")
    parser.add_argument("--csv", default=None, help="Optional CSV export file")
    parser.add_argument("--max-concurrent", type=int, default=MAX_CONCURRENT, help="Max concurrent API requests")
    parser.add_argument("--rate-limit", type=float, default=RATE_LIMIT_PER_SEC, help="Max requests per second")
    return parser.parse_args()


def get_api_base(api_name: str) -> str:
    if api_name == "mempool":
        return MEMPOOL_API
    return BLOCKSTREAM_API


async def rate_limited_get(session: aiohttp.ClientSession, url: str, rate_limit: float, last_request: Dict[str, float]) -> Any:
    """Simple throttle helper to prevent request bursts to public APIs."""
    now = time.monotonic()
    elapsed = now - last_request.get("time", 0.0)
    if elapsed < 1.0 / rate_limit:
        await asyncio.sleep((1.0 / rate_limit) - elapsed)
    last_request["time"] = time.monotonic()

    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
        if resp.status != 200:
            return None
        try:
            return await resp.json()
        except Exception:
            return None


def der_to_r_s(signature_hex: str) -> Optional[tuple[Optional[int], Optional[int]]]:
    """Parse a minimal DER-encoded ECDSA signature for audit-only risk analysis."""
    if not signature_hex:
        return None
    try:
        data = bytes.fromhex(signature_hex)
    except Exception:
        return None

    if len(data) < 8 or data[0] != 0x30:
        return None

    try:
        total_len = data[1]
    except Exception:
        return None

    if total_len + 2 != len(data):
        return None

    i = 2
    if i >= len(data) or data[i] != 0x02:
        return None
    r_len = data[i + 1]
    i += 2
    if i + r_len >= len(data):
        return None
    r_bytes = data[i:i + r_len]
    i += r_len

    if i >= len(data) or data[i] != 0x02:
        return None
    s_len = data[i + 1]
    i += 2
    if i + s_len > len(data):
        return None
    s_bytes = data[i:i + s_len]

    if len(r_bytes) == 0 or len(s_bytes) == 0:
        return None

    r_int = int.from_bytes(r_bytes, byteorder="big")
    s_int = int.from_bytes(s_bytes, byteorder="big")
    return r_int, s_int


def find_der_signature(script_sig_hex: str) -> tuple[Optional[str], Optional[str], Optional[int], List[str]]:
    """Scan a scriptSig for DER signatures. This is a safe audit helper only."""
    if not script_sig_hex:
        return None, None, None, ["No scriptSig present"]

    try:
        data = bytes.fromhex(script_sig_hex)
    except Exception:
        return None, None, None, ["scriptSig is not valid hex"]

    candidates: List[tuple[int, bytes, int, int]] = []
    for idx, byte in enumerate(data):
        if byte != 0x30:
            continue
        if idx + 2 >= len(data):
            continue
        length = data[idx + 1]
        if length == 0:
            continue
        segment = data[idx:idx + 2 + length]
        if len(segment) < 8:
            continue
        parsed = der_to_r_s(segment.hex())
        if parsed is None:
            continue
        r_val, s_val = parsed
        if r_val is None or s_val is None:
            continue
        candidates.append((idx, segment, r_val, s_val))

    if not candidates:
        return None, None, None, ["No valid DER signature found in scriptSig"]

    _, seg, r_val, s_val = candidates[0]
    r_hex = format(r_val, "x")
    s_hex = format(s_val, "x")
    return r_hex, s_hex, len(seg), []


async def fetch_json(session: aiohttp.ClientSession, url: str, rate_limit: float, last_request: Dict[str, float]) -> Optional[Dict[str, Any]]:
    data = await rate_limited_get(session, url, rate_limit, last_request)
    return data if isinstance(data, dict) else None


async def get_address_txs(session: aiohttp.ClientSession, address: str, limit: int, api_base: str, rate_limit: float, last_request: Dict[str, float]) -> List[str]:
    url = urljoin(api_base, f"address/{address}/txs")
    txs = await fetch_json(session, f"{url}?limit={limit}", rate_limit, last_request)
    if not isinstance(txs, list):
        return []
    result: List[str] = []
    for tx in txs:
        if isinstance(tx, dict) and "txid" in tx:
            result.append(str(tx["txid"]))
    return result


async def get_tx_detail(session: aiohttp.ClientSession, txid: str, api_base: str, rate_limit: float, last_request: Dict[str, float]) -> Optional[Dict[str, Any]]:
    url = urljoin(api_base, f"tx/{txid}")
    return await fetch_json(session, url, rate_limit, last_request)


async def audit_address(address: str, api_base: str, limit: int, rate_limit: float, max_concurrent: int) -> List[SignatureAudit]:
    async with aiohttp.ClientSession() as session:
        last_request = {"time": 0.0}
        txids = await get_address_txs(session, address, limit, api_base, rate_limit, last_request)
        sem = asyncio.Semaphore(max_concurrent)

        async def process_tx(txid: str) -> List[SignatureAudit]:
            async with sem:
                tx = await get_tx_detail(session, txid, api_base, rate_limit, last_request)
                if not isinstance(tx, dict):
                    return []

                audits: List[SignatureAudit] = []
                vin: Iterable[Dict[str, Any]] = tx.get("vin", [])
                for idx, input_obj in enumerate(vin):
                    script_sig = None
                    raw = input_obj.get("scriptSig") if isinstance(input_obj, dict) else None
                    if isinstance(raw, dict):
                        script_sig = raw.get("hex")

                    r_hex, s_hex, der_len, warnings = find_der_signature(script_sig or "")
                    validation = "ok"
                    if not script_sig:
                        validation = "missing_scriptSig"
                    elif not r_hex or not s_hex:
                        validation = "malformed_or_unparseable_sig"
                    elif der_len and der_len > 80:
                        validation = "suspicious_der_length"

                    audits.append(
                        SignatureAudit(
                            address=address,
                            txid=txid,
                            vin_index=idx,
                            script_sig=script_sig,
                            validation=validation,
                            signature_hex=(script_sig if script_sig else None),
                            r_hex=r_hex,
                            s_hex=s_hex,
                            der_length=der_len,
                            repeated_r=False,
                            warnings=warnings,
                        )
                    )
                return audits

        batch_results = await asyncio.gather(*(process_tx(txid) for txid in txids))
        flat = [item for sublist in batch_results for item in sublist]

        # Global repeated-R risk signal for safe audit only.
        r_groups: Dict[str, List[SignatureAudit]] = defaultdict(list)
        for entry in flat:
            if entry.r_hex:
                r_groups[entry.r_hex].append(entry)

        for r_hex, entries in r_groups.items():
            if len(entries) > 1:
                for entry in entries:
                    entry.repeated_r = True
                    entry.warnings.append("Repeated R value across multiple inputs/signatures; nonce reuse suspicion")

        return flat


async def audit_all(addresses: List[str], api_name: str, limit: int, rate_limit: float, max_concurrent: int) -> List[SignatureAudit]:
    api_base = get_api_base(api_name)
    tasks = [audit_address(address, api_base, limit, rate_limit, max_concurrent) for address in addresses]
    results = await asyncio.gather(*tasks)
    return [item for sublist in results for item in sublist]


def build_summary(addresses: List[str], audits: List[SignatureAudit]) -> List[AddressSummary]:
    address_to_audits: Dict[str, List[SignatureAudit]] = defaultdict(list)
    for audit in audits:
        address_to_audits[audit.address].append(audit)

    summaries: List[AddressSummary] = []
    for address in addresses:
        addr_audits = address_to_audits.get(address, [])
        suspicious = [a for a in addr_audits if a.repeated_r or a.validation != "ok" or a.warnings]
        warnings = []
        for item in suspicious:
            if item.warnings:
                warnings.extend(item.warnings)
        summaries.append(
            AddressSummary(
                address=address,
                tx_count=len({a.txid for a in addr_audits}),
                suspicious_count=len(suspicious),
                signature_count=len(addr_audits),
                repeated_r_count=sum(1 for a in addr_audits if a.repeated_r),
                warnings=sorted(set(warnings)),
            )
        )
    return summaries


def export_json(path: str, audits: List[SignatureAudit], summaries: List[AddressSummary]) -> None:
    payload = {
        "summary": [asdict(item) for item in summaries],
        "audits": [asdict(item) for item in audits],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def export_csv(path: str, audits: List[SignatureAudit]) -> None:
    if path is None:
        return
    fieldnames = [
        "address",
        "txid",
        "vin_index",
        "validation",
        "r_hex",
        "s_hex",
        "der_length",
        "repeated_r",
        "warnings",
    ]
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in audits:
            row = {
                "address": item.address,
                "txid": item.txid,
                "vin_index": item.vin_index,
                "validation": item.validation,
                "r_hex": item.r_hex,
                "s_hex": item.s_hex,
                "der_length": item.der_length,
                "repeated_r": item.repeated_r,
                "warnings": "; ".join(item.warnings),
            }
            writer.writerow(row)


async def main_async() -> None:
    args = parse_args()
    audits = await audit_all(args.addresses, args.api, args.limit, args.rate_limit, args.max_concurrent)
    summaries = build_summary(args.addresses, audits)
    export_json(args.output, audits, summaries)
    if args.csv:
        export_csv(args.csv, audits)

    print(f"Total audits: {len(audits)}")
    print(f"Addresses processed: {len(args.addresses)}")
    print(f"JSON output: {args.output}")
    if args.csv:
        print(f"CSV output: {args.csv}")

    for summary in summaries:
        print(f"{summary.address}: suspicious={summary.suspicious_count}, repeated_r={summary.repeated_r_count}, tx_count={summary.tx_count}")
        if summary.warnings:
            for warning in summary.warnings[:5]:
                print(f"  - {warning}")


if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        sys.exit(130)
