#!/usr/bin/env python3
"""tools_payout_tracker.py — on-chain USDC payout-graph tracker v1.

Read-only on-chain reconnaissance for crypto bounty work:

  1. verify            — is a wallet even ACTIVE on a chain? (balance / USDC / nonce / code)
                         Cheap falsification: settlement wallets claimed in bounties
                         that are empty + nonce 0 on every EVM chain were never used.
  2. scan              — walk USDC Transfer events to/from a wallet via eth_getLogs
                         (public RPC, no API keys). Survives rate limits by chunk
                         rotation + retries; every successful chunk carries a
                         coverage count so "no events" is never assumed.
  3. payers / payees   — aggregated pay flows: who pays the wallet (sponsors)
                         or who the wallet pays (e.g. other bounty winners).
  4. cluster           — re-run the payer flows for each *recipient* of a bounty
                         sponsor to reveal other paying projects (wallet graph).

Trust rule (hard lesson from field scans, 2026-10-27):
  Some "archive" public RPCs return HTTP 200 with an empty result for ranges
  they don't serve, i.e. they LIE about coverage. So a chunk only counts as
  covered when the node returns a *successful* getLogs — a chunk whose RPC
  errored is re-queued with a different endpoint or (configured) marked gaps.
  Never report "no events" over un-covered chunks.

Usage:
  python3 tools_payout_tracker.py verify base 0x3a5E08708dd1CF22AAe94f913Ab69b17b80a3dC5
  python3 tools_payout_tracker.py scan base 0xbbe6966949d7265a7f5f0b793f08293b9b7fe926 \
      --days 90 --direction in --out out6/payouts.json
  python3 tools_payout_tracker.py payers out6/payouts.json
  python3 tools_payout_tracker.py cluster base 0x26572ff23c6c52bfb1a69cb0c9114a8be443b422 --days 45

Read-only: no tx is ever signed or broadcast. Output: JSON + human table.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------- constants

TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)

# Tokens: the native USDC of each chain plus the bridged variant where it
# matters (Arbitrum USDC.e, historically the default bounty rail).
TOKENS = {
    "base": {
        "USDC": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    },
    "arbitrum": {
        "USDC": "0xaf88d066e678a3c014bcdb74fa282d4fbe9e39ae",
        "USDC.e": "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8",
    },
    "optimism": {
        "USDC": "0x0b2c639c533813f4aa9d78366caf39229184e0ac",
    },
    "ethereum": {
        "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    },
    "polygon": {
        "USDC": "0x3c499c542cef5288e1f3f4fbe8a3d29d1cdf3ba6",
    },
}
DECIMALS = {"USDC": 6, "USDC.e": 6}

# RPC pools. ARCHIVE_OK nodes served full history in field tests; the other
# entries are fallbacks (rate limits / reduced max range per call).
# Field-verified trust map (2026-10-27): for base, azul is the ONLY endpoint
# in the free tier that (a) served a 1000-block getLogs over a 90-day window
# and (b) returned the correct non-empty results. daybreak-rpc returned 200
# with empty results for ranges that DO contain events -> blacklisted there.
RPCS = {
    "base": [
        ("https://rpc.baseazul.dev", 1000, True),
        ("https://base.drpc.org", 100, False),
        ("https://mainnet.base.org", 1000, False),
    ],
    "arbitrum": [
        ("https://arb1.arbitrum.io/rpc", 1000, False),
        ("https://arbitrum-rpc.publicnode.com", 500, False),
    ],
    "optimism": [
        ("https://mainnet.optimism.io", 1000, False),
    ],
    "ethereum": [
        ("https://ethereum-rpc.publicnode.com", 500, False),
    ],
    "polygon": [
        ("https://polygon-rpc.com", 1000, False),
    ],
}

BLOCKTIME = {"base": 2, "arbitrum": 0.25, "optimism": 2,
             "ethereum": 12, "polygon": 2}
BLOCKS_PER_DAY = {"base": 43200, "arbitrum": int(86400 / 0.25),
                  "optimism": 43200, "ethereum": 7200, "polygon": 43200}


def rpc(url: str, method: str, params: list, timeout: int = 15):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                j = json.loads(r.read().decode())
            if "error" in j:
                return {"error": j["error"]}
            return {"result": j["result"]}
        except Exception as e:  # noqa: BLE001
            if attempt == 2:
                return {"error": {"message": str(e)[:120]}}
            time.sleep(0.4)
    return {"error": {"message": "unreachable"}}


def topic_of_addr(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").zfill(64)


def addr_of_topic(t: str) -> str:
    return "0x" + t[26:] if isinstance(t, str) and len(t) == 66 else t


def hexint(v) -> int | None:
    """Some RPCs answer 0x for zero balances; int('0x') would crash."""
    if not isinstance(v, str):
        return None
    v = v.strip()
    if not v or v == "0x":
        return 0
    try:
        return int(v, 16)
    except ValueError:
        return None


# ---------------------------------------------------------------- verify

def cmd_verify(chain: str, wallet: str) -> dict:
    usdc = TOKENS[chain]["USDC"]
    url = RPCS[chain][0][0]
    bal = rpc(url, "eth_call", [{"to": usdc, "data":
              "0x70a08231" + topic_of_addr(wallet)[2:]}, "latest"])
    eth = rpc(url, "eth_getBalance", [wallet, "latest"])
    nonce = rpc(url, "eth_getTransactionCount", [wallet, "latest"])
    code = rpc(url, "eth_getCode", [wallet, "latest"])
    out = {
        "chain": chain, "wallet": wallet,
        "usdc_balance": ((hexint(bal.get("result")) or 0) / 1e6
                         if bal.get("result") is not None else None),
        "native_balance_wei": hexint(eth.get("result")),
        "nonce": hexint(nonce.get("result")),
        "is_contract": bool(code.get("result") and code["result"] != "0x"),
    }
    active = bool(out["nonce"] or out["is_contract"] or out["native_balance_wei"]
                  or out["usdc_balance"])
    out["verdict"] = ("ACTIVE" if active else "FAKE/EMPTY — never transacted "
                      "on this chain (nonce 0, no code, no balances)")
    return out


# ---------------------------------------------------------------- scan

def cmd_scan(chain: str, wallet: str, days: int, direction: str,
             token: str, out_path: str | None, pace: float) -> dict:
    if direction == "in":
        topics = [TRANSFER_TOPIC, None, topic_of_addr(wallet)]
    else:
        topics = [TRANSFER_TOPIC, topic_of_addr(wallet), None]

    size_default = BLOCKS_PER_DAY[chain]
    pools = RPCS[chain]
    events: list[dict] = []
    covered = 0
    missing: list[list[int]] = []

    # Pacing: rotate endpoints, honour the tightest per-endpoint log cap.
    buf: list[bytes] = []
    print(f"scanning {chain} last {days}d of USDC {direction}:{wallet}",
          file=sys.stderr)

    # Determine window
    tip = rpc(pools[0][0], "eth_blockNumber", [])
    if "result" not in tip:
        print("cannot read tip", file=sys.stderr)
        return {"error": str(tip)}
    lat = int(tip["result"], 16)
    start = lat - int(days * BLOCKS_PER_DAY[chain])
    start = max(start, 1)

    # Choose chunk size by probing each (url, max_range) pair with its own url.
    chunk = 1000
    for url, sz, _ in pools:
        probe = rpc(url, "eth_getLogs",
                    [{"address": TOKENS[chain][token], "topics": topics,
                      "fromBlock": hex(lat - 5000),
                      "toBlock": hex(lat - 5000 + sz - 1)}])
        if "result" in probe:
            chunk = sz
            break

    token_addr = TOKENS[chain][token]
    chunks: list[list[int]] = []
    b = start
    while b < lat:
        chunks.append([b, min(b + chunk - 1, lat - 1)])
        b += chunk

    idx = 0
    t0 = time.time()
    while idx < len(chunks):
        url, _sz, arch = pools[idx % len(pools)]
        fb, tb = chunks[idx]
        res = rpc(url, "eth_getLogs",
                  [{"address": token_addr, "topics": topics,
                    "fromBlock": hex(fb), "toBlock": hex(tb)}], timeout=20)
        time.sleep(pace)          # stay under public-endpoint rate limits
        if "error" in res:
            # rate limit / blocked — rotate endpoint and slow down
            pools.append(pools.pop(0))
            pace = min(pace * 1.5, 1.5)
            continue
        pace = max(pace / 1.15, 0.05)  # gently recover when the node allows
        idx += 1
        covered += 1
        for l in res["result"]:
            if len(l.get("topics", [])) < 3:
                continue
            events.append({
                "block": int(l["blockNumber"], 16),
                "from": addr_of_topic(l["topics"][1]),
                "to": addr_of_topic(l["topics"][2]),
                "value": int(l["data"], 16) / 10 ** DECIMALS[token],
                "tx": l["transactionHash"],
            })
        if (idx % 200) == 0:
            print(f"  ...{idx}/{len(chunks)} ({len(events)} events)",
                  file=sys.stderr)
    events.sort(key=lambda e: e["block"])

    agg: dict[str, dict] = {}
    for e in events:
        peer = e["from"] if direction == "in" else e["to"]
        a = agg.setdefault(peer, {"amount": 0.0, "txs": []})
        a["amount"] += e["value"]
        a["txs"].append({"tx": e["tx"], "block": e["block"],
                         "value": e["value"]})
    for a in agg.values():
        a["txs"].sort(key=lambda t: t["block"])

    result = {
        "tool": "tools_payout_tracker.py v1",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "chain": chain, "wallet": wallet, "token": token,
        "direction": direction, "days": days,
        "window_blocks": [start, lat],
        "coverage": {"chunks_ok": covered, "chunks_total": len(chunks),
                     "note": "failed chunks retried/rotated until success"},
        "n_events": len(events),
        "sum_events": round(sum(e["value"] for e in events), 6),
        "peers": agg,
        "events": events,
    }
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(result, indent=1))
        print(f"saved {out_path}", file=sys.stderr)
    return result


# ---------------------------------------------------------------- presentation

def cmd_print(path: str) -> None:
    d = json.load(open(path))
    print(f"# {d['chain']} USDC {d['direction']}: {d['wallet']} "
          f"({d['days']}d, {d['coverage']['chunks_ok']}/"
          f"{d['coverage']['chunks_total']} chunks OK)")
    for peer, a in sorted(d["peers"].items(), key=lambda kv: -kv[1]["amount"]):
        print(f"  {peer}  {a['amount']:>12.6f} {d['token']}  "
              f"({len(a['txs'])} txs)")


# ---------------------------------------------------------------- cluster

def cmd_cluster(chain: str, sponsor: str, days: int, pace: float) -> dict:
    """Second-order graph: payees of the sponsor (bounty winners); then for
    each, who ELSE pays them (other bounty programmes / projects). This is
    the "hidden payers radar" for the hunter workflow."""
    out = cmd_scan(chain, sponsor, days, "out", "USDC", None, pace)
    winners = list(out["peers"].keys())
    print(f"\nsponsor {sponsor} paid {len(winners)} wallets "
          f"(first 10 promoted to secondary scan):", file=sys.stderr)
    graph = []
    for w in winners[:10]:
        sub = cmd_scan(chain, w, days, "in", "USDC", None, pace)
        others = {p: a["amount"] for p, a in sub["peers"].items()
                  if p.lower() != sponsor.lower()}
        graph.append({"winner": w, "paid_by_sponsor": out["peers"][w]["amount"],
                      "other_payers": others})
        print(f"  {w} <- also paid by {list(others)[:5]}", file=sys.stderr)
    return {"sponsor": sponsor, "days": days, "winners": graph}


# ---------------------------------------------------------------- cli

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="is this wallet alive on this chain?")
    v.add_argument("chain"); v.add_argument("wallet")

    s = sub.add_parser("scan", help="walk USDC Transfer logs for a wallet")
    s.add_argument("chain"); s.add_argument("wallet")
    s.add_argument("--days", type=int, default=45)
    s.add_argument("--direction", choices=["in", "out"], default="in")
    s.add_argument("--token", default="USDC")
    s.add_argument("--out", default=None)
    s.add_argument("--pace", type=float, default=0.05)

    p = sub.add_parser("payers", help="pretty-print a scan output json")
    p.add_argument("file")

    c = sub.add_parser("cluster", help="2nd-order graph of a sponsor")
    c.add_argument("chain"); c.add_argument("sponsor")
    c.add_argument("--days", type=int, default=45)
    args = ap.parse_args()

    if args.cmd == "verify":
        print(json.dumps(cmd_verify(args.chain, args.wallet), indent=1))
    elif args.cmd == "scan":
        r = cmd_scan(args.chain, args.wallet, args.days, args.direction,
                     args.token, args.out, args.pace)
        for peer, a in sorted(r["peers"].items(),
                              key=lambda kv: -kv[1]["amount"]):
            print(f"  {peer}  {a['amount']:>12.6f} {args.token}  "
                  f"({len(a['txs'])} txs)")
        if r["n_events"] == 0:
            print("  (no events in window — and 100% chunk coverage)")
    elif args.cmd == "payers":
        cmd_print(args.file)
    elif args.cmd == "cluster":
        print(json.dumps(cmd_cluster(args.chain, args.sponsor,
                                     args.days, 0.05), indent=1))


if __name__ == "__main__":
    main()
