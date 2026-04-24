# Pull Request

## Summary

<!-- One or two sentences describing the change and why. -->

## Changes

<!-- Bullet list of the concrete changes in this PR. -->

-

## Test Plan

- [ ] `go build ./cmd/...` succeeds
- [ ] `go vet ./...` clean
- [ ] Relevant tests pass (`go test -parallel 4 ./tests/ ./pkg/beacon/`)
- [ ] Pre-commit hooks pass (`pre-commit run --all-files`)

## Checklist

- [ ] New code includes the SPDX license header
- [ ] No secrets or credentials committed
- [ ] `go.mod` / `go.sum` changes are intentional
- [ ] Documentation updated if behavior changed
- [ ] Linked issue or context: <!-- #issue-number -->
