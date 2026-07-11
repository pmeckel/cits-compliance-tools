# C-ITS Compliance Tools

Open-source Python tooling for **C-ITS (Cooperative Intelligent Transport Systems)** message
compliance checking and geographic visualization.

Tools check conformance against:
- **C-ROADS** harmonised C-ITS deployment specifications (Release 3.2.0)
- **C2C-CC** (Car-to-Car Communication Consortium) specifications

## Message Types

| Folder | Message | Use Cases | Spec |
|--------|---------|-----------|------|
| [`ivim/`](ivim/) | IVIM | [`ivs-ts/`](ivim/ivs-ts/), [`ng-tsa/`](ivim/ng-tsa/) (implemented), `ivs-ft/` (planned) | C-ROADS Release 3.2.0 |
| `denm/` | DENM | Future DENM based use cases (RWW, HLN) | *(planned)* |

A single message type can carry multiple C-ROADS use cases (e.g. IVIM carries
IVS-TS, NG-TSA and IVS-FT), each with its own compliance profile and checker
script. See the message-type README for the full use-case breakdown.

## Requirements

- Python 3.10+
- See [`requirements.txt`](requirements.txt)

```bash
pip install -r requirements.txt
```

## Contributing

Contributions are welcome regardless of which AI coding assistant or editor you use.
Fork the repository, create a feature branch, and open a Pull Request.

Please follow the existing code style (plain Python, no frameworks) and add or update
the relevant README when adding a new message type or tool.

## License

MIT
