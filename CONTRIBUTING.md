# Contributing to Control Plane Epoch

Control Plane Epoch is a Data Center Control Plane (DCCP) Tranche 1 repository
maintained by Summon Software Labs. Contributions are welcome under the terms of
the Apache License 2.0.

## Licensing of contributions

By submitting a contribution you agree that it is licensed under the Apache
License 2.0, as described in section 5 of the [LICENSE](LICENSE). There is **no**
Contributor License Agreement to sign and no copyright assignment. You keep the
copyright to your contribution.

Do not add `Co-authored-by` trailers, generated-by notices, or attribution lines
that you cannot justify; commit authorship is recorded by Git itself.

## Before you open a pull request

1. Build both configurations. Warnings-as-errors is on by default
   (`CONTROL_PLANE_EPOCH_WARNINGS_AS_ERRORS=ON`), so these commands are the
   warning gate as well as the build:

   ```
   cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
   cmake --build build/release
   cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
   cmake --build build/debug
   ```

   On Windows, run them from an environment that provides the toolchain
   (`vcvars64.bat` for the MSVC toolset). The `CMakePresets.json` presets
   (`release`, `debug`, `asan`, `analyze`) all configure with
   `CONTROL_PLANE_EPOCH_BUILD_TESTS=ON`, so a preset build builds the suites and
   `ctest --preset <name>` runs them; the explicit commands above are equivalent.

2. Run the complete test suite in both configurations:

   ```
   ctest --test-dir build/release --output-on-failure
   ctest --test-dir build/debug --output-on-failure
   ```

   Tests are expected to terminate on their own. Do not add timeouts, watchdogs,
   or "kill the process and call it a pass" logic; a hanging test is a defect and
   must be diagnosed. The harness has no timeout mechanism by design, and a child
   process that exits before producing the line a case waits for is an explicit
   assertion failure, not a skip.

3. If your change can affect durability, run a sanitizer build as well:

   ```
   cmake -S . -B build/asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="/fsanitize=address /Zi" -DCMAKE_EXE_LINKER_FLAGS="/INCREMENTAL:NO"
   cmake --build build/asan
   ctest --test-dir build/asan --output-on-failure
   ```

   The `asan` flags are MSVC flags. Static analysis is available through
   `-DCONTROL_PLANE_EPOCH_ENABLE_ANALYZE=ON`, which adds `/analyze` on MSVC with
   platform and standard-library headers declared external so that only
   first-party findings are reported.

## Code quality expectations

* C++20, standard library only for the shipped library. The SHA-256
  implementation this repository needs is in-tree; new third-party dependencies
  must be justified in the pull request and are normally rejected when the
  standard library suffices.
* Zero first-party warnings under `/W4 /WX` (MSVC) or `-Wall -Wextra -Wpedantic
  -Wconversion -Wshadow -Werror` (GCC and Clang).
* No TODO placeholders, dead code, debug prints, machine-specific absolute paths,
  or generated junk in the tree.
* Deterministic behaviour must stay reproducible: seeded generators with fixed
  documented seeds, stable iteration order, canonical serialization. An
  operation that produces durable bytes must produce the same bytes for the same
  inputs and the same state.

## Strongly typed public API

Every identity, counter, generation, epoch, and external reference in this
repository is a distinct C++ type. Keep it that way:

* no untyped strings or raw integers at an internal trust boundary. If a value
  crosses the public API, a command, the wire, or the durable image, it needs a
  type that validates it on construction and cannot be confused with the value
  next to it;
* no implicit conversions between unrelated identities. `ControllerId`,
  `ScopeName`, `GrantId`, `IncarnationNumber`, `DurableGeneration`, and
  `DomainInstanceNumber` are not interchangeable, and neither are
  `MutationAuthority` and `ObservationAuthority`;
* no sentinel values. Absence is expressed with `std::optional` or with a sum
  type; a zero epoch, a zero incarnation, and a zero digest are not "unset", they
  are values that get rejected. Do not overload a real value to mean
  "not supplied".

Boundary types validate on construction and are never re-checked or normalized
downstream. In particular, identity text is compared byte-exact: do not add case
folding, Unicode normalization, or trimming anywhere.

## Durable state

Every durable state change goes through the transactional commit path in the
store: exclusive temporary file, device flush, read-back verification, retention
of the superseded generation, atomic publish, durable floor, directory flush. A
commit is reported successful only after both the new generation and the floor
are durable.

* Do not write durable artifacts directly from a command path, a test helper, or
  a tool. The only writer is the commit path.
* Do not reorder the protocol steps or move the point at which a commit is
  acknowledged. The in-memory authoritative state moves forward last, so an
  interrupted commit leaves the previous generation authoritative.
* Do not weaken the floor rule. A generation below the floor must be refused —
  accepting it would roll the epoch backwards, which is the one outcome this
  repository exists to prevent.
* A change to the durable image layout or its semantics requires a format or
  schema version decision, and an explicit compatibility statement in the pull
  request. A store written by a different version is refused, never
  reinterpreted.
* Retained structures stay bounded. If you add a collection to the image, state
  its bound in `limits.hpp` and enforce it at decode time as well as at write
  time.

## Evidence for new behaviour

New behaviour needs evidence. Every new invariant, rejection, fence, or recovery
outcome needs a test that fails when the invariant is violated — not merely a
test that passes when it holds.

* Tests assert observable behaviour, not implementation details. Assert the
  stable error token and the durable effect, not a private field.
* A rejection outcome is deterministic: for identical inputs and identical state
  the produced `Explanation` must be byte-identical. Assert that where it
  matters.
* If your change adds a new failure mode for malformed input, add the hostile
  input to the adversarial suite, which asserts each rejection by exact code and
  asserts it twice for an identical explanation.
* If your change is on a concurrency path, add or extend a gated concurrency case
  that joins every thread it starts. In a test, do not sleep, poll on a timer, or
  retry until something happens; use a barrier, a condition variable, or a real
  process boundary.
* Limits are hard and non-negotiable. A new externally influenced size, count, or
  length must be checked against a bound in `limits.hpp` before allocation or
  mutation, and the check needs a test.

## Reporting defects and security issues

Open an issue with the exact command, the observed result, and the expected
result. Durability, integrity, ordering, and fencing defects are treated as
release blockers; include the store directory (or a minimised reproduction) when
the defect is in recovery.

For a security issue, **do not open a public issue that contains a working
exploit.** Report it privately to the maintainers, describing the invariant you
believe is broken rather than only the symptom: which of domain, token integrity,
epoch, grant existence, authority class, claims, revocation, controller
existence, supersession, incarnation currency, or scope coverage you believe can
be violated, and what durable state you believe is required to violate it. A
precise statement of the broken invariant is what makes the report actionable,
and it lets the fix be verified against the ladder rather than against one input.
Note that the framed transport carries no authentication or encryption by design,
so "an unauthenticated peer can send a request" is documented behaviour and not a
vulnerability; "an unauthenticated peer can obtain authority it was not granted"
is.

