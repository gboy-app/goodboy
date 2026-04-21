# FlowEngine.Protocol

The stable plugin contract between `FlowEngine` and every tool that
plugs into it — bundled (`EngineTools`, private `ProTools`) or
third-party. Three files:

- `Tool.swift` — the protocol itself.
- `ToolSpec.swift` — supporting types: params, results, errors,
  events, manifest.
- `DataSchema.swift` — what a tool produces / accepts, how the
  engine reports transfer vs. loss.

## Versioning

The engine ships a semver tag. Protocol changes set the bump:

- **Patch** — doc / comment / internal-behavior change with no
  signature impact. Third-party tools keep compiling.
- **Minor** — additions that are opt-in. New protocol requirement with
  a default implementation in an extension. Existing tools keep
  conforming without edits.
- **Major** — removals or signature changes. Requires explicit migration
  by every conformer.

## Deprecate before remove

A protocol requirement that's on its way out is marked `@available(*,
deprecated, message: "…")` for at least one minor release before the
major bump removes it. The deprecation message names the replacement.
Internal engine code migrates first; the public surface follows.

## What's *not* in this directory

Runtime types the protocol references but that aren't part of the
contract — `SecuredBox`, `BoxItem`, `FlowEngine`, `Device` — live in
`../Core/` and `../Services/`. They're reachable via
`import FlowEngine`, but changes to them follow engine-semver, not
protocol-semver. Tools should touch them narrowly.
