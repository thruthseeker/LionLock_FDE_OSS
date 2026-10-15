# npm trusted-publisher identity review — research handoff

Status: INVESTIGATION ONLY. No LionLock exposure or mitigation is established by this document.

Related issue: #17.

## Claude implementation/prover handoff

Review repository workflows, dependency manifests, lockfiles and publication paths at a pinned commit. Record exact paths and observed evidence. Determine first whether npm trusted publishing is used, npm packages are published, or npm is only a dependency consumer. Mark nonapplicable checks explicitly.

Threat hypothesis: npm trusted publishing configured against mutable GitHub repository names may allow an unintended repository to establish publishing identity under certain unvalidated configuration conditions. Distinguish the external incident from local exposure; check current npm mitigations before asserting applicability.

If applicable, propose a minimal fail-closed control using immutable repository identity, expected workflow identity, attestation subject and provenance verification. Add deterministic fixtures for correct identity, reused slug with different identity, missing identity, unexpected workflow and mismatched attestation source. Assess dependency lockfile integrity and installation scripts separately; do not conflate consumption with publishing.

## Evidence gate

For each claim include commit SHA, file path, reproduction command, expected result, observed result and test receipt. Keep implementation changes in this draft PR. Do not merge or release without owner approval.

## Disclosure boundary

This is a PUBLIC repository and PR. Do not include credentials, unpublished exploit details, private infrastructure or proprietary controls. If a live actionable LionLock vulnerability is found, move technical disclosure to a private security advisory and keep this PR generic.

Sources:
- https://bloom.security/blog/slugfest-millions-of-ai-agents-download-exposed-npm-packages
- https://docs.npmjs.com/trusted-publishers/
