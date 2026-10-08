# Contributing

## The review bar

The question is not "is this a real vulnerability." It is **"is this advisory specific
enough to be useful."** An advisory that matches most deployments is worse than no
advisory: it trains people to ignore the tool.

A record merges when every answer is yes:

- [ ] **Sourced.** Every condition and version in the record is supported by a linked
      public write-up. If a detail could not be established, the summary says so.
- [ ] **Concrete.** It names checkable conditions — a version range, a grant, a setting,
      a capability combination. "Agents that process untrusted input" is not a condition.
- [ ] **Narrow.** `python -m unittest discover tests` passes with `hardened-support-agent`
      and `ci-coding-agent-patched` still clear. If your record lights up a lock it does
      not describe, tighten it.
- [ ] **Actionable.** `fixedBy` gives the operator something to do. For
      configuration-native records that is a mitigation with `set`, not an upgrade.
- [ ] **Safe.** Conditions and impact only. No working payload, no exploit steps beyond
      what the source already published.
- [ ] **Not a weakness class.** "Toolset has untrusted input, private data, and egress"
      is a pattern, not an advisory. File the instance.
- [ ] **Not a duplicate of a CVE with nothing added.** A pure one-package, one-range
      record is acceptable for matchability, but say so, put the CVE in `aliases`, and
      prefer spending effort on records a CVE cannot express.

## Adding a record

1. Take the next free id: `advisories/<year>/AVE-<year>-<NNNN>.json`.
2. Write it against `schema/advisory.schema.json`. `SCHEMA.md` defines what clauses mean.
3. If it should match one of the example locks, add the id to `EXPECTED` in
   `tests/test_audit.py`. If no example lock exercises it, add one.
4. Run `python tools/validate.py` and `python -m unittest discover tests`.

If your finding cannot be expressed without a new clause type, capability, or setting
key, open an issue first. The vocabularies grow only when a record requires it, and each
addition needs to be general rather than shaped around one finding.

## Adding a catalogue entry

A wrong capability claim is worse than a missing one: a false "present" lights up locks
it shouldn't, and a false "absent" clears locks it shouldn't. An entry merges when:

- [ ] **Every claim has evidence** — a public URL and a note saying what it shows. A
      capability you couldn't establish goes in `unknown` with the reason, not in a claim.
- [ ] **Identity is established.** The source names this package, or an advisory citing
      the source does. A write-up about "a Slack MCP server" is not evidence about a
      particular Slack package.
- [ ] **Configuration is explicit.** If the capability depends on a grant (read-only
      mode, credential role), the claim says so in `when`. Never claim a capability
      unconditionally that a documented setting removes.
- [ ] **Capabilities, not bugs.** What a vulnerable version can be tricked into belongs in
      an advisory.
- [ ] **`present: false` only with the strongest evidence,** since it is the one claim that
      can clear a match.

Put it at `catalogue/<purl type>/<namespace>/<name>.json`, write it against
`schema/capability-catalogue.schema.json`, and run `python tools/validate.py` and
`python -m unittest discover tests`.

## Identifiers

Permanent from the first tagged release: never reused, never renumbered. A withdrawn
advisory keeps its id and gains a `withdrawn` note. Until that first release, ids may
change.

## Before filing about a live deployment

Read [DISCLOSURE.md](DISCLOSURE.md).
