# Reference adapter — NOT a supported Overturo integration

This directory contains a reference implementation of
`OverturoDecisionAdapter` showing how to plug a Cedar policy evaluator
into the `conductor.policy_gate` external-endpoint contract.

It is **NOT** a supported integration. Specifically:

- The in-memory policy evaluator shipped here is a fixture-driven stub
  that mirrors Cedar's `(principal, action, resource, context)` shape;
  it is NOT a Cedar parser/engine. Swap it for the real
  `cedar-policy` package (see [`README.md`](./README.md) "Cedar swap").
- The HTTP server uses stdlib `http.server` for portability. Production
  deployments should use a hardened web framework (FastAPI, Starlette,
  AWS Lambda runtime, etc.).
- Authentication, rate limiting, observability, and error handling are
  out of scope for this example. Production deployments must add them.
- No SLA, no semver, no security backporting — this code may be
  rewritten between releases.

Use this directory as a **starting point** for a customer-hosted
decision endpoint, not as a deployable artifact.
