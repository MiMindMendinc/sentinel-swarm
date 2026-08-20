# Architecture

`Browser UI -> FastAPI -> mission runner -> isolated per-mission workspace -> JSONL evidence ledger`

v0.1 deliberately uses a deterministic local fixture so every displayed finding can be traced to bytes on disk. Future model/tool adapters should preserve this evidence-first contract.
