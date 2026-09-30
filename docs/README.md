# docs/

Place report diagrams here (architecture, data-flow, ER diagram of the SQLite schema,
encryption/key-derivation flow). Suggested files:

- `architecture.png`   - module diagram (main -> vault_manager -> crypto/database/analyzer/generator)
- `key-derivation.png` - master password -> scrypt -> AES-256 key -> AES-GCM
- `er-diagram.png`     - `meta` and `entries` tables
