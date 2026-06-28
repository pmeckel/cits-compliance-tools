# C-ITS Compliance Tools

Open-source Python tooling for **C-ITS (Cooperative Intelligent Transport Systems)** message
compliance checking and geographic visualization.

Tools check conformance against:
- **C-ROADS** harmonised C-ITS deployment specifications (Release 3.2.0)
- **C2C-CC** (Car-to-Car Communication Consortium) specifications

## Message Types

| Folder | Message | Use Case | Spec |
|--------|---------|----------|------|
| [`ivim/`](ivim/) | IVIM | IVS-TS (In-Vehicle Signage – Traffic Signs) | C-ROADS SUD02, MP 4.2.2.x |
| `denm/` | DENM | HLN-AZ (Hazardous Location Notification) | *(planned)* |

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
