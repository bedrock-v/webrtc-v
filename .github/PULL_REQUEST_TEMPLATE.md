# Summary

<!-- What does this change, and why? One or two sentences. -->

Closes #

## What breaks if this is wrong

<!--
The field reviewers read first. Be concrete: "a peer behind a symmetric NAT
never connects", "a malformed packet reads past the end of the buffer", "nothing
user-visible, this is a docs change".
-->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change (the public API changes)
- [ ] Documentation
- [ ] Tests, tooling or CI

## Specification

<!--
If this implements or corrects a rule from an RFC, name it: "RFC 8445 section
7.3.1.1". If it does not, say "not applicable".
-->

## Testing

- [ ] `make check` passes locally
- [ ] New tests cover the change
- [ ] A bug fix includes a test that fails without it
- [ ] A new decoder handles malformed input without panicking, and is included in
      the adversarial test

<!-- Describe what you tested and how, especially anything CI cannot cover. -->

## Checklist

- [ ] Formatted with `v fmt -w .`
- [ ] No codec module gained a dependency on `net`
- [ ] Any new limit on attacker-controlled input is documented on the constant
- [ ] Public API has doc comments
- [ ] `CHANGELOG.md` updated under Unreleased, if the change is user-visible
- [ ] No unrelated reformatting in the diff
