# onchain-payout-graph

Read-only CLI that maps **crypto bounty sponsors and payees from USDC Transfer
logs** on public EVM chains — with zero API keys, zero signers, zero KYC.
The three primitives:

`verify`   — is "settlement wallet X" even ALIVE on chain? (nonce/balance/code)
             Cheapest falsification step for any bounty that claims on-chain payouts.
`scan`     — full-history USDC Transfer walk via eth_getLogs (rate-limit-proof,
             coverage-checked; the tracker only counts a window when the node
             answered, so "no events" is never fabricated over gaps).
`cluster`  — second-order radar: who a program pays -> what ELSE pays those
             winners (uncovers hidden paying bounty programmes).

Field-verified behaviour included:
- public "archive" RPCs sometimes return HTTP 200 + EMPTY results for ranges
  that DO contain events (measured, 2026-10-27). The tracker retries failed
  chunks against other endpoints and never treats an unanswered window as empty.
- payout recipient clustering is the fastest route from one paying repo to
  the full set of repo-paying programmes in the same payment graph.

Usage:
  python3 payout_tracker.py verify base 0x<settlement_wallet_claimed>
  python3 payout_tracker.py scan base 0x<our_wallet> --days 90 --direction in --out out.json
  python3 payout_tracker.py payers out.json
  python3 payout_tracker.py cluster base 0x<sponsor_wallet> --days 45
