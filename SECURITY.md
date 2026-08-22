# Security Policy

## Supported versions

Security fixes are applied to the latest release line. Please reproduce an
issue against the newest release before reporting it.

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability involving
authentication, cryptography, certificate issuance, privilege boundaries,
update signing, secret storage, or remote code execution.

Use GitHub's **Private vulnerability reporting** feature on this repository.
Include:

- affected component and version;
- prerequisites and impact;
- minimal reproduction steps;
- logs with tokens, certificates, IP addresses, and personal data removed;
- a proposed mitigation if available.

Never submit real pairing codes, enrollment hashes, admin tokens, device
tokens, private keys, TOTP seeds, API keys, or unredacted state files.

## Security boundaries

- The Windows management API binds to `127.0.0.1` only.
- Nebula device private keys are generated and retained on each endpoint.
- The control server stores sensitive state inside an AES-256-GCM envelope.
- Administrative actions require a short-lived session and may require TOTP.
- Update metadata is signed and artifacts are verified by SHA-256.

These controls do not replace host hardening, firewall policy, operating-system
updates, secure backups, or an independent security review.
