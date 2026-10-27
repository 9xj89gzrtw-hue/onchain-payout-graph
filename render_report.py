#!/usr/bin/env python3
"""tools_payout_graph_render.py — renders a payout_graph_*.json scan as a
standalone HTML visualization (the 'Pro' presentation layer for the
onchain-payout-graph Lite tracker).

Input:  out6/payout_graph_ours.json (produced by tools_payout_tracker.py)
Output: out6/payout_graph.html (self-contained; no CDN, no JS libraries)

Usage:
    python3 tools_payout_graph_render.py out6/payout_graph_ours.json
"""
from __future__ import annotations

import html
import json
import sys

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>onchain-payout-graph report</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font:14px/1.5 monospace;margin:2em}}
h1{{color:#58a6ff}}
table{{border-collapse:collapse;width:100%;max-width:1100px}}
td,th{{border:1px solid #30363d;padding:6px 10px;text-align:left}}
th{{color:#58a6ff;background:#161b22}}
td.amt{{text-align:right;color:#3fb950}}
a{{color:#58a6ff;text-decoration:none}}
a:hover{{text-decoration:underline}}
.meta{{color:#8b949e}}
.tx{{color:#8b949e;word-break:break-all}}
</style></head><body>
<h1>onchain-payout-graph</h1>
<div class="meta">{meta}</div>
<table>
<tr><th>wallet (peer)</th><th class="amt">amount {token}</th><th>txs</th><th>tx hashes</th></tr>
{rows}
</table>
</body></html>
"""

ROW = None  # built per-chain in render (see EXPLORERS)
EXPLORERS = {
    "base": "https://basescan.org/address/{addr}",
    "arbitrum": "https://arbiscan.io/address/{addr}",
    "optimism": "https://optimistic.etherscan.io/address/{addr}",
    "ethereum": "https://etherscan.io/address/{addr}",
    "polygon": "https://polygonscan.com/address/{addr}",
}


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else "out6/payout_graph_ours.json"
    d = json.load(open(src))
    peers = d["peers"]
    out = []

    for addr, a in sorted(peers.items(), key=lambda kv: -kv[1]["amount"]):
        txs = " ".join(t["tx"][:10] for t in a["txs"][:8])
        out.append(
            f'<tr><td><a href="{EXPLORERS.get(d["chain"], "").format(addr=addr)}">{addr}</a></td>\n'
            f'<td class="amt">{a["amount"]:.6f}</td><td>{len(a["txs"])}</td>\n'
            f'<td class="tx">{html.escape(txs)}</td></tr>')
    meta = (
        f"chain={d['chain']} token={d['token']} direction={d['direction']} "
        f"days={d['days']} window=[{d['window_blocks'][0]}, "
        f"{d['window_blocks'][1]}] coverage="
        + f"{d['coverage']['chunks_ok']}/{d['coverage']['chunks_total']} "
        + f"chunks generated={d['generated_utc']}"
    )
    html_out = TEMPLATE.format(
        meta=html.escape(meta),
        token=d["token"],
        rows="\n".join(out))
    dst = src.replace(".json", ".html")
    with open(dst, "w") as f:
        f.write(html_out)
    print(f"saved {dst}")


if __name__ == "__main__":
    main()
