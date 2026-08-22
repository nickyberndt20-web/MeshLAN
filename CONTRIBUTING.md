# Contributing to MeshLAN

Thank you for helping improve MeshLAN.

## Development workflow

1. Fork the repository and create a focused branch.
2. Keep changes scoped to one behavior or bug.
3. Run formatting, tests, and static analysis:

   ```powershell
   gofmt -w .
   go test ./...
   go vet ./...
   ```

4. For UI changes, attach before/after screenshots with all identifiers,
   addresses, domains, and usage data redacted.
5. Explain compatibility and migration impact in the pull request.

## Coding guidelines

- Prefer the Go standard library and keep dependencies minimal.
- Preserve Windows and Linux build tags.
- Never weaken certificate, update, or authorization checks to simplify a
  feature.
- Do not log secrets or include production state in fixtures.
- Use RFC 5737 IPv4, RFC 3849 IPv6, and fictional device names in examples.
- Add regression tests for bug fixes.

## Commit and pull request scope

Small, reviewable commits are preferred. Generated binaries, runtime state,
private certificates, caches, and local screenshots must not be committed.
