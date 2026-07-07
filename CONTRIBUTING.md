# Contributing

Thanks for contributing to honeycomb-auth-extension.

## Development

The component lives in `honeycombauthextension/` (its own Go module).

```bash
make test        # unit tests (race + coverage)
make lint        # go vet + golangci-lint (if installed)
make generate    # regenerate internal/metadata from metadata.yaml (mdatagen)
make example     # build + run the example distro (see example/)
```

Requires Go 1.25+ (`GOTOOLCHAIN=auto` will fetch it if needed).

## Pull requests

- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
  `docs:`, ...); this is enforced by CI.
- Keep generated code (`internal/metadata/`) in sync with `metadata.yaml` by running `make generate`.
- Add or update tests for behavior changes.

## License

By contributing you agree that your contributions are licensed under the Apache-2.0 license.
