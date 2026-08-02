# Identity SDK 2.5 release plan

Date: 2026-08-01

## Release status

| Item | Status |
|---|---|
| `novvor/identity-contracts` v2.0.0 | Published baseline |
| `novvor/identity-sdk-php` v2.0.0 | Published baseline |
| SDK 2.5 core | Published as immutable `v2.5.0` |
| First-party Laravel adapter | `v2.0.1` published; 2.5 durable-intent upgrade pending |
| Platform and FilaSign runtime upgrade | Not yet validated against 2.5 |
| Console v1-to-v2 migration | Not started |

The published adapter is an SDK 2.0 integration boundary. Its missing 2.5
durable-intent capability is a consumer rollout blocker, not a reason to weaken
the core release gate or duplicate protocol logic in controllers.

## Core release gate

The `v2.5.0` candidate passed the following gate before its immutable tag:

1. `composer validate --strict`.
2. A clean `composer install` using only published dependency tags.
3. `composer verify` (PHPUnit, PHPStan, Composer audit and `git diff --check`).
4. Positive and negative tests for login-intent exact-once consumption, browser
   binding, expiry, state, nonce, PKCE, JARM, PAR, DPoP, RFC 9207 and token
   validation.
5. A changelog that names any non-compatible behavior.
6. An immutable annotated Git tag and a clean installation test from that tag.

The `verify` script is the canonical local and CI-equivalent preflight. The
quality workflow also runs for immutable version tags so the release evidence
remains attached to the exact tagged source. A tag is not a deployment or
consumer-rollout approval.

## Consumer order

1. Publish a Laravel integration package that uses durable login intents and
   makes the transaction lifecycle a single supported boundary.
2. Upgrade Enix Platform and FilaSign in independent branches; run their
   browser and negative callback flows against the new package.
3. Migrate Enix Console from `^1.1` to `^2.5` in a separate review because it
   is an authentication-boundary change, not a dependency bump.
4. Verify each deployment independently before the next consumer is changed.

## Rollback

Consumers retain their exact Composer lock until their independent runtime
validation passes. A failed consumer rollout is rolled back by restoring its
prior lockfile and deployment artifact; the immutable SDK tag is not rewritten.

## Truthful readiness

`identity-sdk-php` may become `PASS_PACKAGE_RELEASE` after its core gate. The
ecosystem becomes `PASS_RUNTIME` only after each consuming application proves
the configured OIDC flow, tenant binding, callbacks and negative cases at
runtime.
