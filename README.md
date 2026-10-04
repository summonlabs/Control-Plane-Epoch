# Control Plane Epoch

Control Plane Epoch is the facility-wide incarnation and epoch authority.
It is the component
that decides whether a mutation is allowed to happen at all, and it is the
component that fences everything issued before a change of epoch — stale
controllers, superseded observations, state recovered from an earlier
incarnation, and mutation rights that were valid a moment ago. Its core
invariant is that an epoch, a controller incarnation, and a scope, bound
together, are the only thing that authorizes a mutation; a grant that does not
carry all three authorizes nothing, and advancing the epoch permanently fences
every grant, token, and claim issued under the epoch that ended.

## 1. Systems boundary

This repository owns:

* authority domains: the declared scope vocabulary of one facility authority
  domain, its durable state, and the epoch value that is monotonic within it;
* the monotonic advancement of that epoch, one checked step at a time;
* controller identity and controller incarnations, including the rule that
  registration confers identity and never authority;
* epoch-scoped, incarnation-bound, scope-limited mutation and observation
  grants, and the fencing tokens derived from their claims;
* revocation, as a monotonic, durable, replay-safe operation that fences either
  exactly one grant or every incarnation of one controller up to a stated
  number;
* qualification of recovered state into exactly one verdict, so that persisted
  evidence never becomes current merely because a process restarted;
* idempotency of retryable mutations, so a retried command cannot be applied
  twice;
* provenance: who caused a state change, from which source kind, in which epoch,
  at which position in the mutation ledger;
* the durable store: a transactional commit path with recovery policies, a
  durable generation counter, and a durable epoch floor;
* the framed transport and the two runtimes built on it — the authority runtime
  and the controller runtime — plus the operator CLI.

This repository explicitly does **not** own, implement, or claim:

* distributed consensus, quorum, leader election, or replication;
* a facility metadata registry or any other system of record;
* ASI (accelerator) or DFI (fabric) semantics. An external reference is stored
  as an opaque `kind:value` pair and is never interpreted (`identity.hpp`);
* capacity planning, placement, scheduling, electrical or cooling control,
  maintenance orchestration, tenancy policy, incident response, dashboards, or
  multi-site federation;
* hardware integration of any kind. No accelerator, network device, switch,
  power distribution unit, UPS, cooling system, or building management system is
  contacted, modelled, or claimed.

The transport is a single authoritative store with multiple client processes,
not a protocol for agreeing on one. There is exactly one writer of one store
directory, enforced by an exclusive operating-system lock, and remote clients are
request/response consumers of that single authority (`protocol.hpp`,
`src/file_lock.cpp`).

## 2. Architecture and authoritative state model

The authoritative state of one domain is a single canonical image
(`src/image.hpp`). It holds:

* the domain identifier, the domain instance number, the current epoch, and the
  durable generation;
* the authority root controller identifier;
* the declared scopes, in ascending order;
* controller records, ascending by controller identifier, each with its current
  incarnation number, incarnation identity, incarnation state, registration
  count, first and latest registered epoch, the highest incarnation fenced by a
  controller revocation, and a bounded list of superseded incarnation
  identities;
* the grants of the current epoch, ascending by grant identifier. Grants never
  outlive their epoch, so advancement empties this collection;
* the revocation ledger, ascending by sequence, with a retained count, a trimmed
  count and an anchor digest;
* the epoch transition ledger, ascending by sequence, with the same retained,
  trimmed and anchor fields;
* the retained idempotency outcomes, ascending by (controller, incarnation,
  sequence), with a count and an evicted count;
* the next grant identifier and the next mutation sequence.

Encoding is canonical and deterministic: identical images produce identical
bytes and therefore identical digests, and decoding validates every field
against a bound and every collection against its canonical order before the data
is trusted (`src/image.cpp`).

**Chained ledgers.** Every committed epoch transition appends exactly one
immutable record carrying the digest of its predecessor, and the same is true of
the revocation ledger. The retained history therefore forms a verifiable chain:
truncation, reordering, or substitution inside the retained window is detected
rather than silently accepted. Retention is bounded — at most 4096 transition
records and at most 4096 revocation records are retained (`limits.hpp`). When a
record is retired, its digest becomes the ledger's durable *anchor*, and the
oldest retained record still chains to that anchor, so the trimming point itself
is verifiable.

**Store directory layout.** `StoreLayout` (`store.hpp`) declares the only names
this repository owns inside a store directory:

| Name | Role |
| --- | --- |
| `authority.lock` | the exclusive writer lock file; exists even when unlocked |
| `authority.state` | the live durable generation (envelope header + canonical image) |
| `authority.state.prev` | the superseded generation, retained as the fallback copy |
| `authority.floor` | the durable floor: the highest generation and epoch acknowledged as durable |
| `quarantine/` | damaged files moved aside by a reinitializing recovery |
| `<name>.cpesnap` | extension of a snapshot artifact written by `write_snapshot_artifact()` |

Interrupted commits leave `<base>.tmp.<pid>.<counter>` files, and those are the
only additional names this repository creates; they are retired at the next
writer open, and a file it does not own inside a store directory is ignored
rather than interpreted.

## 3. Identity, generation and authority semantics

Every identity and counter is a distinct C++ type (`identity.hpp`,
`incarnation.hpp`). Two identities of different kinds never convert into one
another, and no identity, counter, or external reference is represented by a
bare integer or an untyped string inside the library.

| Type | Meaning |
| --- | --- |
| `FacilityAuthorityDomainId` | stable identity of one authority domain; epochs are monotonic within exactly one domain |
| `ControllerId` | stable identity of a controller; stable across controller restarts |
| `ControllerIncarnationId` | identity of one controller boot, derived as a SHA-256 over a domain-separated encoding of (domain, controller, incarnation number) |
| `IncarnationNumber` | counter that strictly increases for each controller, so a restarted controller cannot present a previous boot's identity |
| `ScopeName` | name of an authority scope declared by the domain |
| `GrantId` | identifier of one durable grant; never reused within a domain |
| `DurableGeneration` | counts durable commits published by the store; every commit increments it, including commits that do not change the epoch |
| `DomainInstanceNumber` | counts initializations of the durable store, including recovery reinitializations |
| `OperationSequence` | client-chosen sequence of a retryable mutation within one controller boot |
| `TransitionSequence`, `RevocationSequence`, `RegistrationSequence` | positions in the respective ledgers |
| `ProvenanceSourceId` | identity of the human or automated source of a state change |
| `ExternalRef` | opaque `kind:value` reference owned by another DCCP layer; stored, never interpreted |

Identifier text is ASCII `[A-Za-z0-9._-]`, at most 96 bytes, with a first byte
that is alphanumeric (`limits.hpp`, `src/identity.cpp`). Comparison is byte-exact:
no case folding, no Unicode normalization, and no trimming is ever applied to an
identity. Free text — the provenance note — is validated as strict UTF-8 with no
control characters and is bounded separately.

**The authority root.** Initialization names one `authority_root`
(`commands.hpp`, `InitializeDomainRequest`). The root is registered as the
first controller incarnation and receives one grant covering every declared
scope. The root has a standing right to re-acquire the three reserved
administrative scopes — `authority.grant`, `authority.revoke`, `epoch.advance`
— without a sponsor, in any epoch, which is the documented bootstrap path
(`src/core.cpp`). That exemption applies only when the authority root asks for
nothing but reserved administrative scopes. Everything else requires a sponsor:
the acquisition must present a currently valid mutation authority covering
`authority.grant`, and without one it is refused with
`authority.sponsor_required`. A domain that does not declare all three reserved
administrative scopes is refused at initialization, and an image that does not
declare them is refused at decode time.

**Registration is identity, not authority.** `register_controller` allocates a
fresh, strictly higher incarnation number and returns a fresh incarnation
identity. It grants nothing. Registering a controller that is already registered
supersedes its previous incarnation, which permanently fences any authority
bound to that earlier incarnation. `IncarnationState` moves only
`Current -> Superseded`, `Current -> Revoked`, or `Superseded -> Revoked`; no
transition is reversible.

**Grants never outlive their epoch.** A grant records the epoch in which it was
issued. When the epoch advances, every grant of the base epoch is cleared; a
token presented afterwards is refused with `epoch.fenced`, not with
"unknown grant", because the fenced case is decided before grant existence is
examined.

**A fencing token is evidence, not a bearer secret.** `FencingToken` is a digest
derived from the authority class and the full claim set — domain, epoch,
controller, incarnation, grant, scopes — so two different (epoch, incarnation)
pairs never produce the same token, which is what makes "authority from epoch N
is fenced by epoch N+1" observable and machine-checkable. The token detects
corruption and accidental confusion *inside* one epoch. It is not a credential
and it authenticates nothing: the authoritative store decides validity, and
every validation reads the authoritative state and re-runs the ladder below.
Constructing a token grants nothing (`authority.hpp`).

### The validation ladder

`validate_mutation` and `validate_observation` run the same fixed ladder against
durable state, in this exact order, and the first failing rung determines the
rejection (`src/core.cpp`). The order is part of the documented behaviour, not an
implementation detail: a fenced token is reported as fenced even when the grant
it names no longer exists, and a revoked grant is reported as revoked even when
the scope would also have failed.

| # | Check | Stable token on failure |
| --- | --- | --- |
| 1 | token domain is the authoritative domain | `authority.domain_mismatch` |
| 2 | token integrity (the fencing token matches its own claims) | `authority.token_tampered` |
| 3 | token epoch is not above the authoritative epoch | `epoch.unknown` |
| 4 | token epoch is not below the authoritative epoch | `epoch.fenced` |
| 5 | the named grant exists in the current epoch | `authority.unknown_grant` |
| 6 | the grant's authority class matches the token's class | `authority.class_mismatch` |
| 7 | the token claims match the stored grant exactly | `authority.claims_mismatch` |
| 8 | the grant is not revoked | `authority.revoked` |
| 9 | the grant's controller is still registered | `controller.unknown` |
| 10 | the grant has not been superseded | `incarnation.superseded` |
| 11 | the token's incarnation is the controller's current incarnation | `incarnation.superseded`, or `incarnation.unknown` |
| 12 | the token covers the requested scope | `authority.scope_not_granted` |
| — | otherwise | accepted |

Mutation authority and observation authority are distinct C++ types
(`MutationAuthority`, `ObservationAuthority`) with distinct authority classes, so
they cannot be interchanged by accident; presenting one where the other is meant
fails rung 6.

## 4. Persistence, durability and recovery semantics

**The commit protocol.** Every accepted state change goes through the same
transactional path before it is reported as accepted
(`src/authority_store.cpp::commit`):

1. build the canonical image and encode the envelope;
2. write it to an exclusively created temporary file and flush it to the device
   (`FlushFileBuffers` on Windows, `fsync` elsewhere);
3. read the temporary file back and re-decode it; a file that does not verify
   byte for byte is never published;
4. retain the superseded generation as the fallback copy;
5. publish the new generation by atomic replace, so a crash can never leave the
   store without a readable generation. Nothing is deleted before the
   replacement is in place, and on Windows the replace is retried a bounded
   number of times while a reader or a filter driver transiently holds the
   target open; every other failure is reported immediately;
6. publish the durable floor, naming the new generation, epoch, and snapshot
   digest;
7. flush the directory (a no-op on Windows, where the replace is already
   write-through).

Only after the floor has been published and the directory flushed does the store
report success and move its in-memory authoritative state forward. A commit is
therefore reported successful only after **both** the new generation and the
floor are durable, which is what makes rollback below the floor impossible.

**The floor rule.** A generation is usable only if it satisfies the durable
floor: its generation must be at or above the floor's generation *and* its epoch
at or above the floor's epoch. A store that holds a readable generation but no
readable floor is refused with `persistence.floor_missing` — rollback cannot be
excluded, so the store is not assumed to be authoritative. A generation below
the floor is refused with `integrity.generation_below_floor`.

**Recovery policies** (`store.hpp`, `RecoveryPolicy`; passed through
`StoreOpenOptions`):

* `refuse-on-damage` (default) — refuse to open on any unusable current
  generation. Nothing is written and nothing is repaired implicitly.
* `adopt-previous-generation` — adopt the retained previous generation, but only
  when it satisfies the durable floor. The unusable live file is quarantined,
  the fallback is republished byte-identically with its floor, and the outcome is
  reported as `adopted-previous-generation`. If the retained generation is below
  the floor the open is refused with `integrity.generation_below_floor`.
* `reinitialize-domain` — quarantine the damaged durable files and initialize a
  fresh durable instance of the domain at an epoch strictly above every
  recoverable floor value. This requires an explicit operator epoch assertion
  (`StoreOpenOptions::asserted_epoch_floor`) whenever no floor value can be read
  at all (`persistence.asserted_epoch_floor_required`); an assertion below a
  floor that *is* readable is rejected rather than clamped
  (`persistence.asserted_epoch_floor_too_low`). The new instance's domain
  instance number and first epoch are both derived to be strictly above the
  recoverable values.

Opening a store reports a `RecoveryReport`: the outcome
(`opened-clean`, `adopted-previous-generation`, `reinitialized-damaged-store`,
`read-only-inspection`), the domain, instance, epoch and generation when a
domain exists, the snapshot digest, the floor digest, the damaged files, the
quarantined files, and a deterministic detail line. A directory that holds no
authority domain reports those fields as absent rather than as zero, so "no
authority exists here yet" can never be mistaken for authority at epoch 0.

**Read-only mode.** `StoreOpenMode::ReadOnly` reads and verifies one consistent
generation, never writes, never takes the writer lock, and never quarantines
anything. It is therefore safe to run against a live authority runtime.
`inspect_store()` takes no writer lock either: it verifies the current
generation, the retained previous generation when present, the durable floor and
the transition chain, and reports a deterministic problem list instead of
repairing anything.

**Retirement of interrupted work.** A writer takes the exclusive lock once at
open and then retires any `<base>.tmp.<pid>.<counter>` file matching a name this
repository owns. Because the lock is held, no other writer's in-flight temporary
can be removed.

## 5. Deterministic rejection and error semantics

Two channels are used, and the split is deliberate (`error.hpp`):

* `Result<T>` and `ValidationOutcome` carry every **domain** outcome a caller is
  expected to handle: stale epochs, revoked authority, conflicting advancement,
  exhausted limits, idempotency conflicts, recovery verdicts, integrity refusals
  in a store being opened.
* `EpochError` is thrown only for **infrastructure** failures: I/O errors,
  integrity failures in durable or framed data, configuration mistakes, and
  internal invariant violations. It is never thrown for an expected domain
  rejection.

Every outcome has a stable machine token (`authority.revoked`), a fixed category,
a fixed retryability flag, and a fixed human summary. An `Explanation` renders as
`<token>: <summary> [<detail>]`, where the detail is derived only from the
request and the authoritative state involved. For identical inputs and identical
state the produced `Explanation` is byte-identical, which is what makes rejection
outcomes testable and log-comparable. `ValidationOutcome` either accepts (with
no explanation) or rejects with exactly one explanation.

Operation codes that matter most in practice:

| Token | Reported when | Retryable |
| --- | --- | --- |
| `authority.domain_mismatch` | the token belongs to a different authority domain | no |
| `authority.token_tampered` | the token does not match its own claims | no |
| `authority.token_malformed` | the token text is malformed | no |
| `authority.unknown_grant` | no grant with that identifier exists in the current epoch | no |
| `authority.class_mismatch` | the grant authorizes a different class of authority | no |
| `authority.claims_mismatch` | the token claims do not match the stored grant | no |
| `authority.revoked` | the authority has been revoked and is permanently fenced | no |
| `authority.scope_not_granted` | the authority does not cover the required scope | no |
| `authority.scope_unknown` | the scope is not declared by this domain | no |
| `authority.sponsor_required` | the requested authority needs a sponsoring authority | no |
| `epoch.unknown` | the token names an epoch this domain never committed | no |
| `epoch.fenced` | the token belongs to an epoch that has been permanently fenced | no |
| `epoch.conflict` | the authoritative epoch is not the expected epoch | yes |
| `epoch.zero` | an epoch value of 0 was supplied; 0 is not a committed epoch | no |
| `controller.unknown` | the controller is not registered in this domain | no |
| `incarnation.superseded` | a newer incarnation of the controller is registered | no |
| `incarnation.unknown` | the incarnation is not the controller's current one | no |
| `idempotency.conflict` | the idempotency key was already used for a different command | no |
| `recovery.current` / `recovery.stale` / `recovery.superseded` / `recovery.needs_reconciliation` | recovered-state qualification verdict | no |
| `recovery.rejected_future_epoch`, `recovery.rejected_unknown_incarnation`, `recovery.rejected_no_authority`, `recovery.rejected_domain_mismatch` | the recovered-state claim cannot be trusted | no |
| `persistence.store_locked` | another process holds the exclusive writer lock | yes |
| `persistence.floor_missing` | a durable generation exists but its epoch floor is missing | no |
| `persistence.asserted_epoch_floor_required` | reinitializing with no readable floor needs an epoch assertion | no |
| `persistence.asserted_epoch_floor_too_low` | the asserted floor is below a readable one | no |
| `integrity.generation_below_floor` | the generation is below the durable floor | no |
| `integrity.digest_mismatch` | stored content does not match its stored digest | no |
| `integrity.truncated` | encoded data ends before its declared length | no |
| `integrity.chain_broken` | a ledger record does not link to its predecessor | no |
| `protocol.frame_too_large` | the frame exceeds the negotiated size bound | no |
| `protocol.frame_digest_mismatch` | the frame payload digest does not match | no |
| `server.stopping` | the authority runtime is shutting down | yes |
| `internal.unsupported_operation` | the operation is not available in this mode (for example a mutation against a read-only store) | no |

The catalogue reserves stable numbers and tokens that no current code path
produces — for example `controller.root_immutable`, `integrity.epoch_below_floor`,
`server.busy`, `server.not_running`, and `server.already_running`. They are never
renumbered and never reused, and callers should not depend on observing them.

## 6. Public API

`control_plane_epoch/control_plane_epoch.hpp` is the umbrella header; a consumer
that needs one thing includes the one header.

| Header | Contents |
| --- | --- |
| `version.hpp` | version integers, durable format and schema version, protocol version |
| `limits.hpp` | every hard resource bound |
| `digest.hpp` | `Sha256Digest`, streaming `Sha256`, `sha256()` |
| `identity.hpp` | validated identifiers, counters, `ExternalRef`, text validation |
| `epoch.hpp` | `Epoch`, `EpochTransitionReason` |
| `incarnation.hpp` | `ControllerIncarnationId`, `IncarnationState`, `ControllerRecord`, `ControllerRegistration` |
| `authority.hpp` | `AuthorityClass`, `AuthorityScopeSet`, `AuthorityClaims`, `FencingToken`, `MutationAuthority`, `ObservationAuthority`, grants, revocation, `IdempotencyKey` |
| `provenance.hpp` | `ProvenanceSourceKind`, `ProvenanceInput`, `ProvenanceRecord` |
| `transition.hpp` | `EpochTransitionRecord`, `EpochHistoryPage` |
| `recovery.hpp` | `RecoveredStateVerdict`, `RecoveredStateClaim`, `RecoveryQualification` |
| `commands.hpp` | the mutation command values and the paged query values |
| `store.hpp` | `StoreOpenMode`, `RecoveryPolicy`, `StoreOpenOptions`, `RecoveryReport`, `DurableCommitReport`, `StoreInspection`, `inspect_store()`, `StoreLayout` |
| `service.hpp` | `ControlPlaneEpochAuthority`, the single authoritative service of one domain |
| `inspection.hpp` | `AuthorityStatus`, `AuthorityAccounting`, and the paged ledger views |
| `server.hpp` | `ServerOptions`, `EpochAuthorityServer` |
| `client.hpp` | `ClientOptions`, `EpochAuthorityClient`, `AuthorityEndpointInfo` |
| `protocol.hpp` | frame layout, `MessageType`, `encode_frame`, `decode_frame` |
| `error.hpp` | `ErrorCode`, `ErrorCategory`, `Explanation`, `EpochError`, `Result`, `Status`, `ValidationOutcome` |

The program below compiles against this API and runs to completion: it
initializes a domain, registers a controller, acquires sponsored authority,
validates, advances, re-acquires, revokes, qualifies recovered state, and
reopens the store.

```cpp
#include <filesystem>
#include <iostream>
#include <string_view>
#include <utility>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

using namespace dccp::epoch;

int main() {
  const std::filesystem::path directory = std::filesystem::temp_directory_path() / "control-plane-epoch-readme";
  std::error_code ignored;
  std::filesystem::remove_all(directory, ignored);

  // 1. Open the durable store. ReadWrite takes the exclusive writer lock; a
  //    damaged store is refused, never repaired implicitly.
  StoreOpenOptions options;
  options.directory = directory;
  options.mode = StoreOpenMode::ReadWrite;
  options.recovery_policy = RecoveryPolicy::RefuseOnDamage;

  ControlPlaneEpochAuthority authority(options);

  // 2. Initialize the domain: the three reserved administrative scopes are
  //    mandatory, and the root gets a grant covering every declared scope.
  InitializeDomainRequest domain_request;
  domain_request.domain = FacilityAuthorityDomainId::parse("facility-alpha", "authority domain").value();
  domain_request.authority_root = ControllerId::parse("authority-root", "authority root").value();
  for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                      epoch_advance_scope().view(), std::string_view("facility.state")}) {
    domain_request.scopes.push_back(ScopeName::parse(name, "declared scope").value());
  }
  domain_request.provenance = ProvenanceInput::from_source(ProvenanceSourceKind::Initialization, "operator").value();
  if (!authority.initialize(std::move(domain_request)).has_value()) {
    std::cerr << "initialization was rejected\n";
    return 1;
  }

  // 3. Register a controller. Registration confers identity, never authority.
  RegisterControllerRequest registration_request;
  registration_request.controller = ControllerId::parse("controller-7", "controller").value();
  registration_request.provenance = ProvenanceInput::from_source(ProvenanceSourceKind::Controller, "controller-7").value();
  const ControllerRegistration registration = authority.register_controller(std::move(registration_request)).value();

  // 4. The authority root acquires the reserved administrative scopes through
  //    the documented standing-root path, which needs no sponsor.
  std::vector<ScopeName> reserved{authority_grant_scope(), authority_revoke_scope(), epoch_advance_scope()};
  AcquireAuthorityRequest root_request;
  root_request.controller = ControllerId::parse("authority-root", "authority root").value();
  root_request.incarnation = authority.controller_record(root_request.controller).value().incarnation_id();
  root_request.scopes = AuthorityScopeSet::create(std::move(reserved)).value();
  root_request.provenance = ProvenanceInput::from_source(ProvenanceSourceKind::Operator, "operator").value();
  const AuthorityGrantView root_view = authority.acquire_authority(std::move(root_request)).value();
  const MutationAuthority root_authority = *root_view.mutation_authority();

  // 5. Everything else needs a sponsor: the root issues the worker a grant for
  //    one scope, bound to the worker's incarnation and to the current epoch.
  AcquireAuthorityRequest worker_request;
  worker_request.controller = registration.controller();
  worker_request.incarnation = registration.incarnation_id();
  worker_request.scopes = AuthorityScopeSet::create({ScopeName::parse("facility.state", "scope").value()}).value();
  worker_request.sponsor = root_authority;
  worker_request.provenance = ProvenanceInput::from_source(ProvenanceSourceKind::Controller, "controller-7").value();
  const AuthorityGrantView worker_view = authority.acquire_authority(std::move(worker_request)).value();
  const MutationAuthority worker_authority = *worker_view.mutation_authority();

  // 6. Validate: accepted for a covered scope, and rejected with a stable code
  //    for a scope the grant does not cover.
  const ScopeName state_scope = ScopeName::parse("facility.state", "scope").value();
  const ValidationOutcome covered = authority.validate_mutation(worker_authority, state_scope);
  const ValidationOutcome uncovered =
      authority.validate_mutation(worker_authority, ScopeName::parse("facility.cooling", "scope").value());
  std::cout << "validate covered=" << covered.to_string() << '\n';
  std::cout << "validate uncovered=" << uncovered.to_string() << '\n';

  // 7. Advance the epoch. The expected value is a precondition, and the
  //    transition permanently fences every grant issued in the base epoch.
  AdvanceEpochRequest advance_request;
  advance_request.expected_current = authority.current_epoch();
  advance_request.authority = root_authority;
  advance_request.reason = EpochTransitionReason::OperatorRequest;
  advance_request.provenance = ProvenanceInput::from_source(ProvenanceSourceKind::Operator, "operator").value();
  const EpochTransitionRecord transition = authority.advance_epoch(std::move(advance_request)).value();
  std::cout << "advance " << transition.to_string() << '\n';
  std::cout << "fenced " << authority.validate_mutation(worker_authority, state_scope).to_string() << '\n';

  // 8. Re-acquire: the advancement fenced the root's own epoch-1 grant too, so
  //    administrative authority has to be issued again in the new epoch.
  std::vector<ScopeName> renewed_scopes{authority_grant_scope(), authority_revoke_scope(),
                                        epoch_advance_scope()};
  AcquireAuthorityRequest renewed_request;
  renewed_request.controller = ControllerId::parse("authority-root", "authority root").value();
  renewed_request.incarnation = authority.controller_record(renewed_request.controller).value().incarnation_id();
  renewed_request.scopes = AuthorityScopeSet::create(std::move(renewed_scopes)).value();
  renewed_request.provenance = ProvenanceInput::from_source(ProvenanceSourceKind::Operator, "operator").value();
  const MutationAuthority renewed_root =
      *authority.acquire_authority(std::move(renewed_request)).value().mutation_authority();

  // 9. Revoke. Fencing the controller's incarnations through the current one is
  //    monotonic: no later command can un-fence it, and repeating the request is
  //    an accepted replay rather than new fencing.
  RevokeAuthorityRequest revoke_request;
  revoke_request.target = RevocationTarget::controller_all(registration.controller());
  revoke_request.authority = renewed_root;
  revoke_request.reason = RevocationReason::SuspectedStaleAuthority;
  revoke_request.provenance = ProvenanceInput::from_source(ProvenanceSourceKind::Operator, "operator").value();
  const RevocationRecord revocation = authority.revoke_authority(std::move(revoke_request)).value();
  std::cout << "revoke " << revocation.to_string() << '\n';

  // 10. Qualify recovered state: "current" is qualified, never assumed.
  const RecoveredStateClaim claim =
      RecoveredStateClaim::create(FacilityAuthorityDomainId::parse("facility-alpha", "authority domain").value(),
                                  Epoch::from_value(1).value(), registration.controller(),
                                  registration.incarnation_id(), state_scope,
                                  sha256(std::string_view("recovered-state-bytes")))
          .value();
  const RecoveryQualification qualification = authority.qualify_recovered_state(claim).value();
  std::cout << "qualify " << qualification.to_string() << '\n';

  // 11. Close and reopen the same directory: the epoch, the durable generation
  //     and the ledgers continue exactly where they stopped.
  authority.close();
  ControlPlaneEpochAuthority reopened(options);
  std::cout << "reopened " << reopened.recovery().to_string()
            << " epoch=" << reopened.current_epoch().to_string() << '\n';
  return 0;
}
```

Runnable examples covering the same ground one topic at a time live in
`examples/` and build as `control_plane_epoch_example_<name>`: `initialize_domain`,
`controller_registration`, `scoped_authority`, `epoch_advancement`,
`stale_token_rejection`, `revocation`, `recovered_state_qualification`,
`persistence_recovery`, and `remote_controller`.

## 7. Command-line tooling

Three executables are built (and installed into the install prefix's `bin`):

* `control-plane-epoch-authority` — the authoritative runtime of one domain. It
  owns the store's exclusive writer lock for its lifetime and serves remote
  controllers over the framed transport. Every request is handled by the same
  library call a local consumer would make; the runtime adds transport, not
  authority.
* `control-plane-epoch-controller` — an independent controller process: a real
  client of the authority runtime that registers, acquires, validates, attempts
  mutations, and can persist tokens locally to demonstrate that reloaded local
  state is not authority.
* `control-plane-epoch-cli` — read-only inspection plus narrowly scoped operator
  commands.

Options, as accepted by the programs (`--help` prints the same list):

```
control-plane-epoch-authority --store DIR [options]
  --store DIR                      durable store directory (required)
  --bind ADDRESS                   listen address (default 127.0.0.1)
  --port N                         listen port, 0 for ephemeral (default 0)
  --port-file FILE                 write the effective endpoint to FILE
  --init                           create the authority domain if absent
  --domain ID                      domain identifier (with --init)
  --root CONTROLLER                authority root controller (with --init)
  --scopes a,b,c                   declared scopes (with --init)
  --source ID                      provenance source (default operator)
  --recovery-policy POLICY         refuse-on-damage | adopt-previous-generation |
                                   reinitialize-domain (default refuse-on-damage)
  --asserted-epoch-floor N         operator assertion for reinitialize-domain
  --read-only                      serve inspection only; never writes
  --workers N                      worker threads (default 4)
  --queue-depth N                  accepted-session bound (default 256)
  --max-connections N              concurrent session bound (default 128)
  --max-requests N                 stop after N served requests (default 0: unbounded)
  --max-requests-per-connection N  bound per session (default 1000000)

control-plane-epoch-controller --endpoint HOST:PORT --controller ID --action ACTION [options]
  --endpoint HOST:PORT             authority runtime to contact (required)
  --controller ID                  stable controller identity (required)
  --action ACTION                  register | acquire | validate | mutate | status |
                                   advance | revoke | qualify
  --token-file FILE                read the authority token from FILE
  --sponsor-file FILE              read the sponsoring token from FILE
  --save-token FILE                persist the acquired token to FILE
  --scopes a,b                     scopes to acquire or validate against
  --scope NAME                     single scope for validate/mutate
  --target controller|grant        revocation target kind (revoke)
  --target-controller ID           controller being revoked (revoke)
  --through N                      highest incarnation fenced (revoke)
  --grant N                        grant being revoked (revoke)
  --class CLASS                    mutation | observation (default mutation)
  --epoch N                        expected epoch (advance) or producing epoch (qualify)
  --incarnation HEX                incarnation identity (qualify)
  --digest HEX                     content digest (qualify)
  --persist-local FILE             write the acquired token to FILE (restart replay test)
  --await-stdin                    wait for one line on stdin before acting
  --source ID                      provenance source (default controller)

control-plane-epoch-cli COMMAND [options]
  read-only (no writer lock):
    status | verify | controllers | grants | history | revocations   --store DIR [--from X] [--limit N]
    recovery     --store DIR [--recovery-policy P] [--asserted-epoch-floor N]
    inspect-token --token TEXT
    snapshot     --store DIR --out FILE
  mutating (exclusive writer lock required):
    init       --store DIR --domain ID --root CONTROLLER --scopes a,b,c [--source ID]
    root-authority --store DIR [--source ID]
    register   --store DIR --controller ID [--source ID]
    grant      --store DIR --controller ID --incarnation HEX --scopes a,b --sponsor TOKEN
               [--class mutation|observation] [--source ID]
    advance    --store DIR --expected-epoch N --sponsor TOKEN [--reason R] [--source ID]
    revoke     --store DIR --target controller|grant --controller ID [--through N] [--grant N]
               --sponsor TOKEN [--reason R] [--source ID]
    validate   --store DIR --token TEXT --scope NAME [--class mutation|observation]
```

`--sponsor-file FILE` is accepted wherever `--sponsor` is, `--token-file FILE`
wherever `--token` is, and `--note TEXT` attaches a provenance note; none of the
three appears in the printed usage.

**Exit codes are stable** (`apps/tool_support.hpp`):

| Code | Meaning |
| --- | --- |
| 0 | the command completed, including a domain rejection that is reported on stdout with its stable code |
| 1 | infrastructure failure (I/O, integrity, protocol, configuration) |
| 2 | command-line usage error |
| 3 | the authority rejected the command |

**Output is deterministic `key=value`.** One line per record, or one line of
space-separated `key=value` fields, for example
`rejected code=authority.revoked retryable=false detail=...`,
`validation accepted=false code=epoch.fenced detail=...`,
`failure code=persistence.store_locked detail=...`, and
`authority-ready endpoint=127.0.0.1:52344 domain=facility-alpha epoch=1 protocol=1`.
A `detail=` field carries the human-readable rejection detail and can therefore
contain spaces and punctuation, so parse on the key rather than by splitting a
line on whitespace. Nothing is localized and nothing is timed.

**Locking.** Read-only inspection — `verify`, `status`, `controllers`, `grants`,
`history`, `revocations`, `inspect-token`, and `snapshot` — opens the store
without the writer lock, so it is safe to run against a live authority runtime.
Mutation takes the exclusive writer lock and is therefore refused with
`persistence.store_locked` while a runtime holds the store; a CLI mutation cannot
run concurrently with a runtime. The CLI's `recovery` command is read-only under
`refuse-on-damage` and takes the writer lock only for a repairing policy, because
adopting or quarantining writes.

**No bypass.** The tools never bypass authority checks. Every mutation they
perform is sponsored by a token the authority issued, and each one faces exactly
the same validation ladder as any other consumer. `root-authority` is the
documented standing-root path for the reserved administrative scopes, not an
exemption: it goes through the same `acquire_authority` call, and it fails like
any other acquisition if the caller is not the domain's authority root.

## 8. Concurrency model

**One mutex per authority instance.** `ControlPlaneEpochAuthority` owns one
durable store directory and is protected by one non-recursive mutex. Every public
method takes that mutex once, performs its work, and returns. No callback,
listener, or user-supplied function is ever invoked while the mutex is held, so
re-entrancy is impossible by construction. `AuthorityStatus`,
`AuthorityAccounting`, and the paged views are produced under that lock, so no
field can change while a caller reads a snapshot.

**One exclusive process writer lock, taken once.** The store's exclusive writer
lock is acquired once in the constructor and released once in `close()` or
destruction. Individual commits never re-acquire it, so there is no lock
inversion between the in-process mutex and the operating-system lock. The lock is
non-blocking: a second writer in the same process or in another process fails
immediately with `persistence.store_locked` rather than waiting.

**Bounded runtime.** `EpochAuthorityServer` runs a fixed worker pool
(`ServerOptions::workers`, default 4, maximum 32) over a bounded queue of
accepted-but-unstarted sessions (default 256), with a bounded number of
concurrent connections (default 128) and a bounded number of requests per
connection (default 1,000,000, after which the client must reconnect). Frames are
rejected before allocation when the declared payload length exceeds the
negotiated bound, when the magic or version is wrong, or when the payload digest
does not match the bytes that arrived. Every request is served by calling exactly
the same `ControlPlaneEpochAuthority` method a local consumer would call; the
runtime never bypasses authority or generation checks.

**Deterministic shutdown.** `stop()` closes the listener, shuts down the active
sessions so that no worker is left blocked on a socket, then joins every worker.
Work that completed before shutdown is committed and answered; work that had not
started when shutdown was requested is answered with `server.stopping`. `stop()`
is idempotent and is never called while holding authority state, because workers
may be waiting on the authority mutex.

The client is deliberately simpler: one client owns one connection and issues one
request at a time, using operating-system blocking throughout. It never times a
request out, and a peer that dies mid-frame produces an explicit
`io.socket_closed` or `protocol.frame_truncated` rather than a half-applied
result.

## 9. Validation performed

The suites are built and registered by `tests/CMakeLists.txt` as one CTest test
that runs the whole harness, which prints one `[pass] suite.name` or
`[fail] suite.name: ...` line per case and a final `executed=<N> failed=<M>`
summary. There is no timeout property, no watchdog, and no timer anywhere in the
harness: a case that waits for a child process blocks until the child produces
the expected line, and a child that exits first becomes an explicit assertion
failure. A hanging test is treated as a defect and surfaces as a hang. The
multiprocess suite is only compiled when both
`CONTROL_PLANE_EPOCH_BUILD_PROCESS_TESTS` and `CONTROL_PLANE_EPOCH_BUILD_APPS`
are on, which is the default; the remaining suites are always available.

**REAL — independent operating-system processes and real sockets.** The
multiprocess suite starts the built `control-plane-epoch-authority`,
`control-plane-epoch-controller`, and `control-plane-epoch-cli` executables as
child processes. The authority runtime binds a real loopback socket on an
ephemeral port and reports its endpoint on stdout; the test reads that line and
points controller processes at it; token exchange between processes happens over
the framed transport, with tokens persisted to files on disk. It establishes:

* a runtime starts, initializes a domain, serves two requests, exits cleanly
  (`authority-stopped served=2`, `active_connections=0`), and releases the writer
  lock so the store verifies;
* a worker's token authorizes a real mutation at epoch N; another authorized
  controller process advances the epoch; the same token, re-presented by a new
  process, is then refused with `epoch.fenced` for both mutation and validation,
  while an observer process sees `epoch=2` and `live_grants=0`;
* a controller that persists its token locally, "restarts" as a new process, and
  re-registers is fenced with `incarnation.superseded` even though no revocation
  happened and no epoch advanced, and can re-acquire above the fence;
* four controller processes, each held on a blocking read of its standard input
  and released deliberately rather than by a timer, race to advance the same base
  epoch: exactly one is accepted and the other three receive the retryable
  `epoch.conflict`;
* the runtime is terminated unconditionally at an arbitrary point in its life — a
  real process kill with no cooperative shutdown, not a simulated one. The store
  still verifies afterwards, the transition chain still verifies, the epoch is
  not below the last acknowledged value, no temporary file is left behind, and a
  fresh runtime process opens the same directory clean and serves the recovered
  epoch. The kill does not land inside a commit; that window is probed
  synthetically, below;
* a mutating CLI command from another process is refused with
  `persistence.store_locked` while the runtime holds the store, while read-only
  `status` and `verify` from other processes succeed;
* a revocation performed over the wire by one process is visible to every other
  process, including the revoked controller, and re-registration above the fence
  restores authority while the old token stays fenced;
* a read-only runtime takes no writer lock, serves inspection, and refuses a
  mutating request with `internal.unsupported_operation`.

**SYNTHETIC — in-process fault injection at exact durability boundaries.** The
store consults an internal, test-only durability seam (`src/fault.hpp`) at five
points inside a commit: after the temporary write, after the read-back
verification, after retaining the superseded generation, after the atomic
publish, and after the floor write. The seam is thread-local, unarmed by default,
not installed, and not reachable from the public API or the wire protocol. When a
case arms it, the commit raises `CommitFailed` at that exact boundary — a
deterministic stand-in for the process dying there — and the case then closes and
reopens the store exactly as a restart would, asserting that the previous
generation is still authoritative, that no commit was acknowledged, and that no
temporary file survives. This is how the publish/floor window is probed: no real
power loss is simulated, and no case claims to have survived one.

**In-process suites over the public API.** The remaining suites drive
`ControlPlaneEpochAuthority` and the value types directly:

* identity, text, and UTF-8 validation, including identifiers that differ only by
  case or by a trailing byte;
* the epoch value, its refusal of zero, and advancement by exactly one;
* scope sets: canonical order, duplicate rejection, and the per-grant bound;
* registration: incarnation one on the first registration, supersession on
  re-registration, registration conferring identity without authority, and
  identity-keyed accounting;
* the validation ladder, including the ordering rules that make it
  deterministic: a fenced epoch outranks grant existence, and revocation and
  supersession outrank scope coverage;
* revocation: grant revocation fencing exactly one grant, controller revocation
  fencing through an incarnation, monotonicity, replay without new fencing, and
  re-registration above the fence;
* fencing: advancement frees every grant of the base epoch, a fenced token
  cannot sponsor a real command, a superseded incarnation cannot be revived by
  re-registration, advancement requires the `epoch.advance` scope and can be
  performed by a non-root controller that holds it, and a stale expectation
  conflicts while exactly one successor exists;
* recovered-state qualification: every verdict, including all four rejection
  shapes and the rule that an earlier epoch by a still-current incarnation is
  never silently current;
* idempotency: replay returns the recorded outcome and applies nothing, the same
  key with different content conflicts, keys are scoped to one controller
  incarnation, and the retained window is bounded with eviction counted;
* persistence: reopen preserves every durable fact, every commit advances the
  generation by exactly one, identical operation sequences produce byte-identical
  snapshots *and* floors, the superseded generation is retained and decodable,
  read-only opens take no writer lock, a second writer is refused, and every
  stateful operation after `close()` is rejected with `persistence.store_not_found`;
* corruption: truncation below the header and inside the payload, a flipped
  payload byte, a wrong magic, an unsupported format version, an unsupported
  schema version, and appended bytes are each refused with their exact integrity
  code, for a store whose directory digest is unchanged by the refusal; a
  generation below the durable floor is refused under both the conservative and
  the adopting policy; a missing or unreadable floor is refused; adoption is
  refused when the fallback is below the floor and allowed only inside the
  floor; reinitialization quarantines the damaged files and starts strictly above
  the recoverable epoch and instance; and reinitialization without a readable
  floor requires the operator assertion, while an assertion below a readable
  floor is refused rather than clamped. Damaged images are crafted with
  white-box access to the canonical codec (the internal headers are on the test
  include path and are never installed);
* protocol: the frame codec rejects a wrong magic, an unsupported version,
  non-zero reserved flags, an unknown message type, an oversized declared length
  (before materializing a payload), truncation at several lengths, and a payload
  digest mismatch, each with its exact code and protocol category; randomized
  frames round-trip exactly; the message-type vocabulary round-trips through its
  tokens; and request/response payload codecs round-trip against a live
  in-process authority;
* concurrency: an in-process advance race commits exactly one successor per base
  epoch while every loser receives an identical retryable explanation; accepted
  validations never straddle an epoch boundary; concurrent registrations never
  reuse an incarnation; concurrent controller revocations stay monotonic;
  accounting closes exactly over accepted commands; and a read-only observer
  running `inspect_store()` and a second read-only authority never sees a damaged
  or half-published generation and never causes a lost or half-applied command,
  even though on Windows a concurrent reader can transiently make a publish fail
  and the store then has to retry it;
* property: a seeded generator drives fixed, documented seeds through 96
  operations each, comparing after every operation against a model of grants,
  incarnations and ledgers, re-validating every token ever issued against a code
  predicted from the documented ladder, and re-executing every predicted
  rejection to require the identical code and explanation with status unchanged.
  Every failure message carries `seed=<seed> step=<n>`. A separate case replays
  one seed against two stores and requires identical snapshot digests, chain
  heads, record digests, and final status;
* adversarial: hand-built hostile inputs with no random generator — hostile
  frames, hostile payloads, hostile token texts, consistent claims that match
  nothing, hostile store paths, unexpected files inside a store directory,
  oversized durable inputs, durability fault injection, arm/clear cycles of the
  fault seam, and the rule that a refused command never changes status. Every
  rejection is asserted by exact code and asserted twice for an identical
  explanation.

**Coverage that does not exist.** The `limits` suite is a single regression case
about `recovery()` after `close()`; it does not exercise the bounds in
`limits.hpp`. Those bounds are exercised across the persistence, corruption,
idempotency, protocol, adversarial, identity, and authority_scope suites. The
retention bounds for the transition and revocation ledgers are implemented but no
case crosses them (the idempotency window is crossed). No case provokes a
request-id mismatch, `server.busy`, `server.not_running`, or
`server.already_running`. No case runs concurrent *processes* mutating the same
store — the only multi-process mutation claim is that a second writer is refused.

**Sanitizer and static-analysis configuration.** The repository ships four CMake
presets, all Ninja, all single-configuration. All four configure presets set
`CONTROL_PLANE_EPOCH_BUILD_TESTS=ON`, so a preset build builds the suites and a
preset test run runs them:

| Preset | Configuration |
| --- | --- |
| `release` | `CMAKE_BUILD_TYPE=Release` |
| `debug` | `CMAKE_BUILD_TYPE=Debug` |
| `asan` | `CMAKE_BUILD_TYPE=Debug`, `CMAKE_CXX_FLAGS="/fsanitize=address /Zi"`, `CMAKE_EXE_LINKER_FLAGS="/INCREMENTAL:NO"` |
| `analyze` | `CMAKE_BUILD_TYPE=Debug`, `CONTROL_PLANE_EPOCH_ENABLE_ANALYZE=ON`, which adds `/analyze` with platform and standard-library headers declared external so that only first-party findings are reported |

Both the `asan` flags and the `analyze` option are MSVC-only: on GCC and Clang
`CONTROL_PLANE_EPOCH_ENABLE_ANALYZE` is ignored, so the `analyze` preset
configures and builds without running an analyzer. There is no UBSan, TSan, or
MSan preset. **There is no CI in this repository at all** — no workflow of any
kind exists, so AddressSanitizer, MSVC static analysis, CTest, the examples, the
benchmark, and the downstream consumer are all things a developer runs locally.
To reproduce any of them, configure with the toolchain in the environment and
build the suites explicitly. For the sanitizer configuration on Windows (a
single command line, quoted for `cmd.exe`):

```
cmake -S . -B build/asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="/fsanitize=address /Zi" -DCMAKE_EXE_LINKER_FLAGS="/INCREMENTAL:NO"
cmake --build build/asan
ctest --test-dir build/asan --output-on-failure
```

For static analysis, configure with `-DCONTROL_PLANE_EPOCH_ENABLE_ANALYZE=ON`
using the MSVC toolset and build; the analyzer reports first-party findings
during compilation.

**UNSUPPORTED.** No accelerator, fabric, or facility hardware was exercised. The
only sockets anywhere in this repository are loopback TCP sockets between
processes on one host. There is no multi-GPU, RDMA, NVLink, MIG, switch, PDU,
UPS, cooling, or BMS integration here, so nothing about such hardware is
validated or claimed.

## 10. Benchmarks

`benchmarks/benchmarks.cpp` builds as `control_plane_epoch_benchmarks` and takes
no arguments: it prepares a real store in the operating system's temporary
directory, initializes a domain, and prints one `key=value` line per metric,
followed by the store state, the recovery outcome of a reopen, and an integrity
check that must pass or the run fails. Only operations the authority accepted are
counted; a rejected operation aborts the benchmark rather than being reported as
a rate.

Five metrics are measured, and the distinction between them is the point:

| Metric | Durability | What the measured interval contains |
| --- | --- | --- |
| `validate_mutation_in_memory` | `in-memory` | the authority mutex and in-memory authoritative state only — no commit, no flush, no atomic publish, no file I/O |
| `register_controller_durable` | `durable` | a full commit: exclusive temporary write, device flush, read-back verify, atomic publish, retained previous generation, floor publish |
| `revoke_authority_durable` | `durable` | the same full commit for one revocation that fences one live grant |
| `advance_epoch_durable` | `durable` | the same full commit for one epoch transition; re-acquiring the `epoch.advance` grant needed by the next transition is excluded |
| `store_reopen_recovery` | `durable` | opening the store directory: writer lock, retirement of interrupted temporaries, verification of the current generation, the retained previous generation and the floor, then recovery policy |

In-memory token validation and durable epoch advancement are therefore measured
separately and never conflated: validation is its own metric, printed with
`durability=in-memory` and an `includes=` field stating that it excludes all
durability cost, and no aggregate, average, or composite number across metrics is
produced anywhere. Each metric line reports `operations`, `warmup_operations`,
`samples`, `ops_per_second_total`, nearest-rank `ops_per_second_min/median/p99`
over the per-sample rates, and nearest-rank `latency_min/median/p99/max_us` over
the per-sample mean latencies; with few samples a high percentile is close to the
worst sample, and the sample count is always printed next to it.

The workload is fixed and small — 100,000 measured validations over 25 samples
plus 200 warm-up operations; 140 durable registrations over 7 samples; 105
durable revocations in 105 single-operation samples; 105 durable advancements in
105 single-operation samples; 20 store reopens. The harness states its own scope
on every run: single host, single process, an in-process durable store in the
temporary directory, no network, no loopback client, no multi-process
concurrency, no distributed consensus, `std::chrono::steady_clock` timings only.
These are not a hardware characterization and must not be read as production
capacity.

Reproduce:

```
cmake --build build/release --target control_plane_epoch_benchmarks
build/release/control_plane_epoch_benchmarks
```

The benchmark is not installed; it exists in the build tree only.

## 11. Building, installing and consuming

Requirements: CMake 3.21 or newer, a C++20 compiler, and Ninja if the presets are
used. The only platform library linked is `ws2_32` on Windows; elsewhere the
library links `Threads::Threads` publicly.

CMake options (all first-party targets are configured with `/W4 /permissive- /utf-8 /EHsc` on MSVC or `-Wall -Wextra -Wpedantic -Wconversion -Wshadow` elsewhere, plus warnings-as-errors unless disabled):

| Option | Default | Effect |
| --- | --- | --- |
| `CONTROL_PLANE_EPOCH_BUILD_TESTS` | ON | build the test suites and register the CTest test |
| `CONTROL_PLANE_EPOCH_BUILD_EXAMPLES` | ON | build the `control_plane_epoch_example_*` programs |
| `CONTROL_PLANE_EPOCH_BUILD_BENCHMARKS` | ON | build `control_plane_epoch_benchmarks` |
| `CONTROL_PLANE_EPOCH_BUILD_APPS` | ON | build the authority runtime, controller runtime, and CLI |
| `CONTROL_PLANE_EPOCH_BUILD_PROCESS_TESTS` | ON | include the multiprocess suite (requires the apps) |
| `CONTROL_PLANE_EPOCH_WARNINGS_AS_ERRORS` | ON | treat first-party warnings as errors |
| `CONTROL_PLANE_EPOCH_ENABLE_ANALYZE` | OFF | run the MSVC static analyzer on first-party code |

The project version in `CMakeLists.txt` is checked against
`include/control_plane_epoch/version.hpp` at configure time, and configuration
fails fast if the two disagree. `add_library` is called without an explicit
library type, so the target follows `BUILD_SHARED_LIBS` (static by default), and
`WINDOWS_EXPORT_ALL_SYMBOLS` is enabled for Windows builds.

Configure, build, and test both configurations:

```
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
ctest --test-dir build/release --output-on-failure

cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

On Windows, run these from an environment that provides the toolchain
(`vcvars64.bat` for the MSVC toolset). The equivalent preset names are `release`,
`debug`, `asan`, and `analyze`, each with a matching build and test preset
(`cmake --build --preset debug`, `ctest --preset debug`). All four configure
presets set `CONTROL_PLANE_EPOCH_BUILD_TESTS=ON`, so a preset build builds the
suites and `ctest --preset <name>` runs them; the explicit commands above are
equivalent and are what the recorded validation used.

Install:

```
cmake --install build/release --prefix install
```

This installs the library, the public headers, the three tools, and the CMake
package files `ControlPlaneEpochConfig.cmake` and
`ControlPlaneEpochConfigVersion.cmake` under
`<libdir>/cmake/ControlPlaneEpoch`, exporting the target
`SummonSoftwareLabs::ControlPlaneEpoch`. Examples and the benchmark are not
installed. On non-Windows platforms the installed package config resolves the
`Threads` dependency it needs.

Consume the installed package from an independent downstream project:

```
cmake -S consumer -B build/consumer -G Ninja -DCMAKE_PREFIX_PATH=<prefix>
cmake --build build/consumer
```

`consumer/` is a standalone CMake project that is deliberately not part of the
main build. It calls `find_package(ControlPlaneEpoch REQUIRED)` and links
`SummonSoftwareLabs::ControlPlaneEpoch`; the only input it needs from the caller
is a `CMAKE_PREFIX_PATH` pointing at a real install prefix. Its `main.cpp` walks
the public API end to end against a store in a temporary directory and exits
non-zero if any step behaves differently from the documented behaviour:
initialize, register, acquire (standing-root then sponsored), validate a covered
and an uncovered scope, advance, observe the fenced token, report the durable
commit, and verify the store with `inspect_store()`.

## 12. Genuine limitations

* **One authoritative writer per store directory.** The store is protected by an
  exclusive operating-system lock; a second writer — in the same process or in
  another — is refused with `persistence.store_locked`. There is no standby
  writer, no handover protocol, and no replication.
* **No consensus and no multi-site.** This is not a distributed protocol. There
  is exactly one authority; remote clients request and receive. Nothing here
  spans sites, and no quorum is formed anywhere.
* **No wall-clock leases.** Authority is generation-based, not time-based: a
  grant is valid exactly while its epoch is current, its record is not revoked,
  its controller incarnation is current, and the requested scope is covered.
  Every one of those conditions is durable state, so validity cannot drift with a
  clock — and, symmetrically, **an unreachable authority cannot be worked around
  by waiting**. Nothing expires on its own; a caller that cannot reach the
  authority cannot validate, advance, or revoke, and stale authority stays
  formally valid for exactly as long as the epoch does not move.
* **Bounded windows.** At most 4096 transition records and 4096 revocation
  records are retained; older records are trimmed and represented by a durable
  anchor digest rather than by the record itself. At most 4096 idempotency
  outcomes are retained, oldest first out, so idempotency is guaranteed only
  within that window: a retry that arrives after its outcome has been evicted is
  treated as a fresh command. Each controller retains at most 8 superseded
  incarnation identities, which is enough to attribute a rejected token but not
  an unbounded audit trail.
* **The authority root cannot be replaced by an API call.** It is fixed when the
  domain is initialized, and no command changes it. Changing the authority root
  means reinitializing the domain under a recovery policy that quarantines the
  previous durable instance and starts a new one at a strictly higher epoch and
  domain instance number.
* **The transport carries no authentication and no encryption.** Frames have a
  magic, a version, a type, a request identifier, and a payload digest — no
  credential, no MAC, no session token, and no confidentiality. The defaults bind
  the authority runtime to `127.0.0.1`, and the service is a single-facility
  service; who may reach the socket is the operator's responsibility, not a
  property of this repository. Any peer that can reach the socket can attempt any
  request, and is then subject to the same authority checks as everyone else.
* **Durability depends on the operating system's flush semantics.** The commit
  path calls `FlushFileBuffers`/`fsync` and an atomic replace, and on Windows the
  directory flush is a no-op because the replace is already write-through.
  Nothing here can do better than what the platform and the storage device
  actually honour.
* **Failure granularity is per store, not per domain.** A store directory holds
  one authority domain. Multiple independent authority domains in one facility
  means multiple store directories, each with its own writer lock, its own epoch
  sequence, and its own durable floor.
* **The durable format is versioned and refused, not migrated.** An image written
  by a different format or schema version is refused rather than reinterpreted
  (`integrity.format_version_unsupported`, `integrity.schema_unsupported`).
  There is no in-place migration path.
* **Recovered state is qualified, never repaired.** The authority returns a
  verdict. Reconciling, rewriting, or re-attesting the state itself is the
  caller's work.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
