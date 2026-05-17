<!--
Thanks for contributing to neleus-db. Please fill in every section.
Delete inapplicable lines rather than leaving placeholders.
-->

## Summary

<!-- One or two sentences. What changed and why. -->

Closes #

## Changes

<!-- Bullet list of the substantive changes. File:line references encouraged. -->

-

## Invariants and compatibility

- [ ] No on-disk format change
- [ ] No hash domain or canonical encoding change
- [ ] No public API break
- [ ] Backward compatible with existing databases
- [ ] Schema migration included (if any of the above are false)

<!-- If any box above is unchecked, describe the migration / break explicitly. -->

## Tests

<!-- What was added or updated. If a bug is fixed, name the regression test. -->

- [ ] Unit tests
- [ ] Property tests (`proptest`)
- [ ] Integration / multiprocess tests
- [ ] Golden-byte tests updated (if canonical encoding touched)
- [ ] Benchmarks updated (if performance affected)

## Security and safety

- [ ] No new `unsafe` blocks (or justified inline)
- [ ] No new `unwrap` / `expect` on fallible runtime paths
- [ ] No new panics reachable from public API
- [ ] Cryptographic changes reviewed for nonce / salt / key handling

## Performance

<!-- If this touches a hot path, paste before/after benchmark numbers from `cargo bench`. -->

## Reviewer checklist

- [ ] Each changed line traces directly to the issue
- [ ] No drive-by refactors or unrelated cleanup
- [ ] No dead code introduced
- [ ] Errors carry actionable context

## Notes for reviewers

<!-- Anything reviewers should focus on. Tradeoffs, alternative approaches considered, follow-ups deferred. -->
