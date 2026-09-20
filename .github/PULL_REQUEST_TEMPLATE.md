<!-- SPDX-License-Identifier: MPL-2.0 -->
## Summary

<!-- What changes and why. One paragraph. -->

## Requirement IDs

<!-- Implements: / Fixes: — every behavioural change cites at least one. -->

- Implements:
- Scope / domain:

## Behaviour

- [ ] Behaviour changed (describe):
- [ ] Collector changes (id / version):
- [ ] Parser changes (version):
- [ ] Schema changes (entity / version):

## Comparability — required

> **Does this change alter normalized state for an unchanged host?**

- [ ] No
- [ ] Yes — describe the comparability and `baseline rebind` handling:

<!-- If yes and unhandled, this silently invalidates every existing baseline. -->

## Tests

- [ ] Negative tests added (malformed, missing data, permission failure)
- [ ] Regression test added before the fix, for a bug
- [ ] Corpus fixtures added or updated
- [ ] `make check` passes locally

## Impact

- [ ] Privilege or capability impact (describe, or "none"):
- [ ] Data sensitivity impact — new fields in reports or exports (describe, or "none"):
- [ ] New failure modes (describe, or "none"):
- [ ] Runtime dependency impact — must be "none"; runtime is Bash + Python stdlib only:

## Documentation

- [ ] `/docs` updated, or not required
- [ ] Generated docs regenerated (not hand-edited)
- [ ] No `FUTURE` feature described in the present tense
- [ ] No competitive framing about any project

## AI assistance — required

<!-- Which AI tools were used and how. Write "none" if none.
     Disclosure only; AI tools are not credited as authors. -->

- AI tools and use:
- [ ] Every commit carries `Assisted-by:` (or `Assisted-by: none`)
- [ ] No `Co-Authored-By:` trailer naming an AI tool or provider
- [ ] `Signed-off-by:` present (DCO)

## Checklist

- [ ] No frozen architecture or governance file edited without an owner amendment
- [ ] No requirement, test or gate weakened
- [ ] Blocked work recorded in `docs/IMPLEMENTATION_QUESTIONS.md`
