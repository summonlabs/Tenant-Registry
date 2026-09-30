# Tenant Registry

Tenant Registry is the canonical facility-level tenancy registry of the Data
Center Control Plane (DCCP), Tranche 6: Facility Policy, Tenancy, and
Entitlement. It answers one question and refuses to answer any other:

> Which facility tenancy identities exist, in which isolation domains, under
> which ownership and service relationships, in which lifecycle state and
> revision -- and which of those declarations may a higher control layer trust?

It is a vendor-neutral C++20 library with one operator tool. It has no
third-party dependencies: it builds with a C++20 compiler, CMake and the
operating system alone.

Version 1.0.0. Container format version 1. Canonical encoding version 1. Export
format version 1.

---

## 1. The core question, precisely

A tenancy registry is easy to get wrong in one specific way: it becomes a
directory that agrees with whatever it was last told, and whose answers cannot
be tied to the state they were derived from. Everything in this repository
exists to prevent that.

It answers, deterministically and boundedly:

* Does the identity `tenant:acme` exist, what is its lifecycle state, and what
  revision is it at?
* What does it own, who owns it, and what is the chain of accountability above
  it?
* Which services belong to it, and how?
* Which isolation domains is it in force in right now, as of which generation of
  that domain's membership set?
* Which generation of the whole registry is this answer true of, and which
  control epoch and incarnation of the store produced it?
* If a request is refused, exactly which input caused the refusal, and what else
  was observed but was not the reason?

It does not answer, and must not be asked: whether a principal is who it claims
to be, what anything costs, where a workload should run, whether a tenant is
entitled to a resource, or what the network does with a packet.

---

## 2. Systems boundary

### 2.1 What this repository owns

* **Canonical identities.** `TenantId`, `ServiceId`, `IsolationDomainId`,
  `PrincipalId`, `SourceId` and `MetadataKey` are distinct C++ types with one
  canonical textual form and one canonical ordering. An identity is an opaque,
  case-sensitive, bounded token; it is never normalized, never trimmed, and
  never interpreted as a path or a name.
* **The tenancy records themselves.** Tenant, service and isolation-domain
  records, ownership edges, service bindings and isolation memberships. Each
  record carries its lifecycle state, its own revision, the generation that
  created and last updated it, its provenance, and the digest of the exact
  declaration that established it.
* **The lifecycle and the legal transitions between states**, defined in exactly
  one place and enforced on every path.
* **Referential integrity.** A relationship whose endpoint does not exist cannot
  be created, cannot be stored, and cannot survive a reload.
* **Isolation-domain membership as an explicit, declared, queryable fact**, with
  a per-domain generation that fences a consumer that cached it.
* **Ownership as an explicit declared relationship**, acyclic by construction,
  with exactly one accountable administrative owner per tenant at a time.
* **Authority and fencing.** Registry generation, per-record revision, per-domain
  membership generation, durable control epoch, writer incarnation, request
  digests and idempotency keys.
* **Tombstones and rebind policy.** Retired identities are never reusable;
  a tombstoned identity is reusable exactly once, and only when an explicit
  permit named that exact successor before the tombstone was written.
* **Durable state.** A versioned, bounded, integrity-checked, hash-chained
  container with one atomic commit point, single-writer exclusion, conservative
  recovery that never guesses, and compaction that cannot produce a state the
  ordinary reader would refuse.
* **Deterministic rendering.** A canonical text form, a canonical JSON form and
  a canonical binary form, all stable across platforms and container iteration
  orders, so a digest means the same thing on two machines.

### 2.2 What this repository explicitly does not own

| Adjacent concern | Who owns it, and what this repository therefore does not do |
| --- | --- |
| Authentication, SSO, IAM | Whether a principal is who it says it is. This registry records *who declared* something as provenance. It authenticates nobody and decides nothing about what a principal may do. |
| Billing and metering | Cost, rating, invoicing, usage accounting. |
| Accelerator scheduling and quotas (ASI) | How much of an accelerator a tenant may use, and when. |
| Network segmentation and routing (DFI) | VLANs, VRFs, overlays, ACLs, paths. An isolation domain here is a *declared tenancy boundary*, not a network construct, and this repository neither creates nor reads one. |
| Resource entitlement and admission | Whether a tenant is entitled to anything, whether capacity exists, and whether a request is admitted. |
| Physical placement and maintenance | Where a workload runs, when hardware is serviced, and how an incident is handled. |
| Service-class policy | What a service class means and which one applies. |
| External directories | Any directory, CMDB or inventory is a *feed*, never a source of truth. A record imported from one is evidence about what that system said, recorded as such; it is not evidence that the system was right, and it never silently overwrites canonical state. |

The rule that keeps the boundary honest: where an effect belongs to an adjacent
authority, this repository models a declaration and consumes evidence. It never
performs or simulates the external effect.

---

## 3. Principal invariants

These hold of every state this registry can reach, and every one of them is
re-derived from scratch when durable state is loaded. A store that violates any
of them is refused rather than repaired.

1. **An identity is unique and canonical.** Two records can never share an
   identity, and a record's stored key always equals the canonical form of its
   own contents.
2. **Nothing dangles.** Every ownership edge, service binding and isolation
   membership names endpoints that exist. A relationship whose endpoint is
   missing is not representable in a loadable state.
3. **The ownership graph is acyclic** and bounded in depth.
4. **At most one accountable owner.** A tenant has at most one *in-force*
   administrative owner at any moment.
5. **At most one in-force binding per (service, kind).** Two in-force bindings of
   one kind would be two answers to one question.
6. **At most one in-force primary isolation domain per subject.**
7. **Only an in-force identity can be related to.** `Declared` reserves an
   identity and confers nothing; `Suspended`, `Retiring`, `Retired` and
   `Tombstoned` confer nothing.
8. **Retirement is clean.** An identity can only begin retirement when nothing
   refers to it.
9. **Identity reuse is impossible without a permit.** A retired identity is never
   reusable. A tombstoned identity is reusable exactly once, by the exact
   successor an explicit permit named at tombstone time, and the tombstone
   survives the reuse as a permanent record.
10. **Every record exposes provenance and position.** Lifecycle state, revision,
    creating and updating generation, provenance and the digest of the
    declaration that created it.
11. **Absence stays absent.** A display name, an owner principal, a metadata key,
    a provenance time and a tombstone permit that were never set are reported as
    unset. They never materialize as an empty string, zero, false, or a
    synthesized default.
12. **Isolation is declared, never inferred.** No code path derives a domain
    membership from a name, a label, a rack, a path or any other naming
    convention.
13. **Canonical rendering is order-independent.** Every collection is held and
    emitted in canonical order, so the same state produces the same bytes
    whatever order it was built in and whatever the container implementation
    did.
14. **Counters never wrap.** Every generation, revision, epoch, incarnation and
    sequence either advances or refuses. A saturated counter can never silently
    become a small one.

---

## 4. Authority, generations and fencing

This is the part of the design that decides whether an answer can be trusted.

### 4.1 The fields

| Field | Scope | Advances when |
| --- | --- | --- |
| `RegistryGeneration` | the whole registry | any accepted mutation, by exactly one |
| `RecordRevision` | one record | any accepted mutation that changes that record, by exactly one |
| `DomainGeneration` | one isolation domain's membership set | any membership change in that domain, by exactly one |
| `ControlEpoch` | the durable store | a writer takes control of the store |
| `Incarnation` | the writer | never reused; a new one per read-write session |
| `JournalSequence` | the durable journal | one committed frame |

### 4.2 What a mutation must bind to

Every mutating request carries a `MutationContext` with:

* `expected_generation` -- the generation the caller composed its decision
  against. There is deliberately **no** way to say "whatever is current".
* `actor` -- a `ProvenanceRecord` naming the source system, the principal and,
  optionally, the time. `MutationContext` is not default constructible, so the
  compiler forces a caller to state both.
* `idempotency_key` -- optional, and the only thing that makes a lost response
  recoverable.

Each operation additionally binds to the exact record revision, the exact domain
membership generation, or both, as the operation requires. Relationship
operations bind to an explicit assertion about whether the relationship exists
and at which revision.

### 4.3 What invalidates what

* A **new generation** invalidates every decision composed against an older one.
  A caller that did not see the current generation is refused with
  `stale_generation`, and the refusal names both generations.
* A **new record revision** invalidates any decision that named the old one
  (`stale_record_revision`).
* A **new domain membership generation** fences a consumer that cached domain
  membership, without that consumer having to re-read the whole registry
  (`stale_domain_generation`).
* **Taking control of a durable store** publishes a new control epoch and a new
  incarnation. Every live authority issued by a previous writer is fenced by
  that publication, atomically with it. Recovered state is not automatically
  fresh authority: a process that reopens a store holds authority over it only
  because taking control said so, and the act of taking control is what fenced
  the previous holder.
* **A restart never preserves live authority by accident.** A read-only session
  takes no authority at all; a read-write session's authority exists only for as
  long as it holds the writer lock, which the operating system releases when the
  process ends, however it ends.

### 4.4 Idempotent replay, and why it comes first

If a caller sends a mutation and never sees the answer, the honest retry is the
identical request. That retry may arrive after the registry has moved on, so the
idempotency question is answered **before** the staleness question:

1. If the request carries a key that is in the ledger **and the canonical request
   digest matches**, the original answer is returned, marked `replayed`, with
   the original generation, sequence and revision, and **the record as it was at
   the original commit**. The registry does not advance and does not recompute.
2. If the key is present with a **different** digest, the request is refused with
   `idempotency_key_reused`. A key identifies one request and only one.
3. Only if neither applies is the request treated as new, and only then can
   staleness refuse it.

The ledger is rebuilt from the journal on every open, so it cannot disagree with
the log. It is never silently pruned: when it is full, a new keyed request is
refused with `idempotency_ledger_full` rather than accepted without the ability
to replay it.

---

## 5. Lifecycle model

One lifecycle enum serves tenants, services and isolation domains, because their
lifecycles *are* the same lifecycle and three copies would drift. The kinds are
kept apart where confusion would actually be dangerous: in the identity types,
which are distinct classes and cannot be interchanged.

| State | Meaning |
| --- | --- |
| `unspecified` | Never a legal state of a live record. It exists so that a zero byte, a truncated field or a missing value can never decode as a legal state. |
| `declared` | Registered and reserved. The identity exists and is unique. It confers nothing: it may not own, may not be owned, may not be bound, and may not hold isolation membership. |
| `active` | Admitted and in force. Only an active identity may be the source of a relationship. |
| `suspended` | Previously in force, deliberately not in force now, recoverable. Keeps its relationships; may not gain new ones. |
| `retiring` | Being withdrawn. No new relationships; existing ones must be gone before it started. |
| `retired` | Withdrawn. Permanently readable; the identity may never be reused. |
| `tombstoned` | Fenced forever, with an explicit statement about whether any successor may ever take the identity's place. |

Legal transitions, defined in exactly one place:

```
declared   -> active, retired
active     -> suspended, retiring
suspended  -> active, retiring
retiring   -> active, retired
retired    -> tombstoned        (only through the tombstone operation)
tombstoned -> (none)
```

`retiring -> active` is legal and deliberate: an operator who starts a
withdrawal may stop it before it completes, and the registry records that
honestly rather than forcing the identity into retirement.

Membership has a different lifecycle, because a subject can be active while a
particular membership is only proposed, and a membership can be withdrawn while
the subject stays active:

```
proposed  -> bound, withdrawn
bound     -> suspended, withdrawn
suspended -> bound, withdrawn
withdrawn -> (none)            -- the record leaves the state
```

### 5.1 Retirement and the tombstone policy

Retirement is refused (`has_live_dependents`) while anything still refers to the
identity, and the refusal names what is in the way rather than only that
something is.

An identity that has been retired **cannot be recreated** (`identity_retired`).
Taking an identity over is an explicit, irreversible act:

1. The identity must already be `retired`. Tombstoning anything else is refused.
2. The request must carry an explicit acknowledgement. Recorded acknowledgement is
   not the effect: the tombstone exists only once its commit is durable.
3. The request may name a `rebind` successor. The permit is fixed at that
   moment and cannot be widened afterwards.
4. After tombstoning, recreating the identity is refused with
   `identity_tombstoned` -- unless an outstanding permit names **that exact
   identity**.
5. When such a permit is consumed, the identity is recreated **and** the
   tombstone moves to a permanent `tombstone:` record inside the same commit.
   The proof that the identity was once fenced is never destroyed.
6. Any further attempt is refused with `rebind_permit_consumed`.

---

## 6. Persistence and recovery

### 6.1 Layout

Three files inside one directory:

```
tenant-registry.manifest        the authority. Fixed 256 bytes, checksummed,
                                replaced atomically.
tenant-registry-<n>.journal     append-only frames; n increases on compaction.
tenant-registry.lock            the writer lock.
```

A frame is a fixed 88-byte header, a payload, and a 4-byte trailer:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `TRFR` |
| 4 | 2 | frame format version |
| 6 | 2 | kind (1 commit, 2 baseline) |
| 8 | 8 | sequence |
| 16 | 8 | generation after this frame |
| 24 | 8 | control epoch |
| 32 | 8 | incarnation |
| 40 | 4 | reserved, zero |
| 44 | 4 | payload length |
| 48 | 4 | header CRC-32 over bytes [0,48) |
| 52 | 4 | payload CRC-32 |
| 56 | 32 | payload SHA-256 |
| 88 | N | payload (canonical encoding) |
| 88+N | 4 | trailer `TREN` |

The manifest records the store identity, the control epoch and incarnation of
the writer that took control, the committed sequence, the generation those
frames reach, the chain head over them, the journal file name, the chain base
sequence and the chain seed.

### 6.2 The hash chain

The chain head after frame *i* is
`SHA-256(head(i-1) || complete frame bytes of frame i)`, starting from the chain
seed. Every commit therefore advances the chain by one hash, and recovery
verifies the whole committed prefix in one pass. Any reordering, truncation,
substitution or rollback of a committed frame changes the head.

### 6.3 The commit point

The commit point is **the atomic replacement of the manifest**. Everything before
it is staging; nothing after it is ever observed. One mutation proceeds:

1. Validate, then compute the new state. Nothing is written yet.
2. Build the complete frame in one buffer.
3. Append it to the journal.
4. Flush the journal to the device.
5. **Read the frame back from the file** and verify its length, header CRC,
   payload CRC, payload SHA-256 and trailer.
6. Advance the hash chain.
7. Stage the new 256-byte manifest image and flush it.
8. Atomically replace the live manifest.
9. Only now apply the change to in-memory state and acknowledge.

Because step 9 comes last, a failure at any earlier step leaves the in-memory
state untouched and the caller is told nothing happened. Because step 8 is the
commit point, a process that dies after it leaves a mutation that *did* happen
even though no caller ever heard an answer -- which is one of exactly two
states a reopen may produce.

### 6.4 Recovery

Recovery chooses exactly one authoritative state or refuses. It never guesses,
never merges, and never starts empty when durable state exists but cannot be
verified.

1. If the root does not exist: create it (read-write) or refuse with
   `store_not_found` (read-only).
2. If the manifest is absent **and** a journal is present, refuse with
   `store_corrupt`. Durable state exists and cannot be verified.
3. Verify the manifest: exactly 256 bytes, magic, version, reserved fields zero,
   CRC. A version this build does not know is `store_format_unsupported`.
4. Take the writer lock **before** reading the journal, so recovery and the first
   commit are ordered against any other writer.
5. Scan frames, verifying each completely and advancing the chain.
6. If fewer frames verify than the manifest commits, refuse with
   `store_corrupt`. **A shorter state is never substituted for the committed
   one.**
7. The chain head over the committed prefix must equal the head the manifest
   records, otherwise `store_corrupt`.
8. Bytes past the committed point are **not state**. They were flushed by a
   commit that never published, so they were never acknowledged to anyone. They
   are dropped and reported. This includes the very first commit: a store whose
   first commit died before publication reopens empty and valid rather than
   becoming unopenable.
9. Rollback floor: if the caller supplied a minimum committed generation and the
   store is below it, refuse with `store_rolled_back`.
10. Store pinning: if the caller supplied an expected store identity and it does
    not match, refuse with `store_identity_mismatch`.
11. Read-write only: publish a manifest whose control epoch is one past the one
    found, with a fresh incarnation. **This is the act that fences the previous
    writer**, and it happens atomically with the publication that makes the new
    epoch authoritative.

Read-only inspection obeys every one of these rules except taking the lock and
publishing. A store a writer would refuse is refused by an inspector too.

### 6.5 Compaction

Compaction writes a **new** journal file containing one baseline frame that
carries the whole canonical state, flushes it, reads it back and verifies it, and
only then publishes a manifest naming it. The old journal stays intact until that
publication succeeds. A crash before the publication leaves the previous journal
authoritative; a crash after it leaves the new one. Either way the ordinary
reader accepts the result, because the new journal is verified with exactly the
same code path as any other.

---

## 7. Concurrency model

**One mutex, one acquisition per operation, no nesting.** Every public operation
-- read or write -- takes the same `std::mutex` for its whole duration. There is
therefore:

* no shared lock and therefore no read-to-write upgrade;
* no second lock, and therefore no lock ordering to get wrong;
* no re-entrant acquisition anywhere;
* no callback, log sink or user code invoked while the mutex is held, with one
  documented exception (below).

Durable I/O happens while the mutex is held, deliberately: the commit point must
be ordered with the publication of the in-memory state it protects. Blocking
under a lock is normally a defect; here it is the property being implemented, and
the alternative -- releasing the lock across the commit -- is what would let two
writers interleave.

The one callback invoked under the lock is the publish fault hook
(`PublishFaultHooks`). It exists only so that crash consistency can be proved
against real processes, it is documented as not re-entering the registry, and
every production caller leaves it unset, in which case it costs one empty
`std::function` check per commit stage.

**Cross-process exclusion is provided by the operating system, not by this
mutex.** A read-write session holds an exclusive lock on
`tenant-registry.lock` for its whole lifetime. On Windows the handle withholds
`FILE_SHARE_WRITE`, so a second writer's open fails with a sharing violation; on
POSIX it is a `fcntl` write lock. The lock is released by the kernel when the
process dies, however it dies, so a crashed writer can neither block nor
authorize a later one. A read-only session takes no lock and is never blocked by
a writer.

The library is not a thread pool and does not need one. Many threads may call
one registry concurrently; they are serialised by the mutex, and a caller that
composed a request against a generation another thread has since moved past is
refused with `stale_generation` rather than losing an update.

---

## 8. Error and refusal semantics

### 8.1 Shape

A refusal is not a string. It carries an `ErrorCode`, an optional canonical
subject token, a human-readable detail, and any secondary observations that were
made before the refusal was decided but that are not the reason for it. "Why was
this refused" and "what else was wrong" are different questions, and the second
one is preserved.

Codes are appended, never inserted, and never reused for a different meaning.
`to_token` renders the stable lower-case token used by the CLI, the tests and
the logs; `parse_error_code` refuses an unknown token rather than falling back
to a default, because a default would turn an unrecognized refusal into a
recognized one.

### 8.2 Precedence

When several failures coexist, the first one below is the one reported:

1. **Request shape.** Missing fields, malformed identities, invalid UTF-8,
   control bytes in text, out-of-range enums, oversized payloads, exceeded
   counts. Nothing is touched.
2. **Idempotency.** A replay of an accepted request is answered here, before
   anything can refuse it as stale. A key reused for a different request is
   refused.
3. **Authority.** A closed session, a read-only session, a superseded epoch.
4. **Staleness.** Expected generation, then per-record revision, then domain
   membership generation.
5. **Existence.** The subject or the relationship does not exist.
6. **Lifecycle legality.** Including "already in this state", which is a distinct
   refusal from "cannot move to this state".
7. **Relationship integrity.** Self reference, cycles, depth, duplicate
   relationship, conflicting in-force owner or binding, live dependents.
8. **Limits on the resulting state.**

Every step is enforced before any state changes, and the whole mutation is
decided before a byte is written.

---

## 9. Library integration

```cpp
#include <tenant_registry/tenant_registry.hpp>

using namespace tenant_registry;

EphemeralOptions options;                 // or RegistryOpenRequest for durability
auto registry = TenantRegistry::open_ephemeral(options);
if (!registry) {
  // registry.error().code(), .token(), .detail(), .suppressed()
}

const auto tenant = TenantId::create("acme").value();
const auto actor = ProvenanceRecord::create(
    ProvenanceSource::OperatorDeclaration,
    SourceId::create("deploy-tool").value(),
    PrincipalId::create("operator-7").value(),
    std::optional<Timestamp>{Timestamp{1'700'000'000'000}},
    std::string{"initial declaration"}, 512).value();

// Every mutating request is one aggregate: the compiler will not let a caller
// forget the generation it composed against or who is asking.
const CreateTenantRequest create{ MutationContext{registry->generation(), std::nullopt, actor},
                                  tenant, std::string{"Acme"}, std::nullopt, TenancyMetadata{} };
auto declared = registry->create_tenant(create);
if (!declared) { /* declared.error() */ }

auto admitted = registry->transition_subject(
    TransitionSubjectRequest{ MutationContext{registry->generation(), std::nullopt, actor},
                              TenancySubject::of_tenant(tenant),
                              declared.value().record.revision,
                              LifecycleState::Active });
```

Three things about the interface are deliberate and worth knowing before writing
against it:

* **Request structs are aggregates with no default constructor.** If you build
  one in pieces, the compiler refuses. That is the point: a generation and an
  actor are not optional decoration.
* **Unset is a value, not an absence.** `MetadataValue::find` on a key that was
  never set returns an explicitly unknown value, not an empty string. A display
  name is a `std::optional`. Rendered output says `unset` and emits `null`.
* **Digests identify states, not sessions.** `RegistrySnapshot::digest()` covers
  the generation and the records. The control epoch, the incarnation, the store
  identity and the journal position are reported by the snapshot but are not part
  of its digest, so two registries holding the same tenancy facts share a digest
  whatever process wrote them.

---

## 10. The command line tool

```
treg [--root <dir>] [--read-only] [--json] <command> [arguments]
```

Without `--root` the session is ephemeral and the tool says so.

```
treg tenant create acme --display-name "Acme Corporation" --metadata tier=gold
treg tenant transition acme --to active --revision 1
treg tenant show acme
treg tenant list --state active --limit 20
treg tenant tombstone acme --revision 4 --acknowledge --rebind-to acme --note "reissued to the new operator"
treg tenant tombstone-show acme

treg service create renderer
treg domain create zone-a --class fault_containment
treg domain members zone-a

treg ownership put acme globex --kind administrative --state active
treg binding put renderer acme --kind operated_by
treg membership put tenant:acme --domain zone-a --role primary --domain-generation 0

treg isolate tenant:acme
treg traverse acme --direction ancestors
treg explain isolation_domain:zone-a
treg stats
treg export --json
treg compact
treg verify
treg --self-check
treg --scenario
```

Exit codes: `0` success, `1` refusal, `2` usage error, `3` store error. A
refusal prints `error: <token>: <detail>` on standard error, followed by one
`note:` line per suppressed observation.

`treg verify` re-opens the same root read-only in a second session and reports
what recovery did: the committed generation, the control epoch, the incarnation,
and whether any uncommitted tail was discarded. It is the first thing to run
when a durable store is in doubt.

---

## 11. Build, install and consume

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix /some/prefix
```

CMake options: `TREG_BUILD_TESTS`, `TREG_BUILD_TOOLS`, `TREG_BUILD_EXAMPLES`,
`TREG_BUILD_BENCHMARKS`, `TREG_WARNINGS_AS_ERRORS` (default ON),
`TREG_SANITIZERS`, `TREG_ANALYZE`, and the standard `BUILD_SHARED_LIBS`.

A downstream project consumes it with:

```cmake
find_package(TenantRegistry CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE TenantRegistry::tenant_registry)
```

The package exports one namespaced imported target. Nothing this project uses
for its own build leaks into it: all the strictness flags are `PRIVATE`.

---

## 12. Validation performed

Everything below was run on the machine described in section 15. Nothing in this
section is inferred from reading code.

### 12.1 Builds

| Configuration | Compiler | Result |
| --- | --- | --- |
| Release | MSVC 19.44 (Visual Studio 2022 17.14), `/W4 /WX /permissive-` | clean, zero warnings |
| Debug | MSVC 19.44, `/W4 /WX /permissive-`, `_ITERATOR_DEBUG_LEVEL=2`, `/RTC1` | clean, zero warnings |

### 12.2 Test suite

The suite is described in section 13 and run with `ctest`; see section 12.8 for
the exact result.

### 12.3 Sanitizers

See section 12.7. This is reported honestly rather than assumed.

### 12.4 Crash consistency

A real child process performs one mutation and ends itself abruptly at each of
the six commit stages. For every stage the parent then reopens the store and
asserts the state is exactly one of the two allowed outcomes:

| Stage | Reopened state |
| --- | --- |
| before the journal append | the mutation is absent |
| after the append, before the flush | the mutation is absent |
| after the flush | the mutation is absent |
| after the read-back verification | the mutation is absent |
| before the manifest publish | the mutation is absent |
| after the manifest publish | the mutation is **present** |

The store reopens successfully in every case, and a further mutation succeeds
afterwards, which is what proves the crash left no half-written frame and no
held lock behind it.

### 12.5 Multiprocess

Real, independent operating system processes, started from the test binary
itself:

* a second writer is refused with `store_locked` while the first holds the lock;
* the lock is released by the kernel when the holder is killed without running
  any cleanup, and the next writer then succeeds;
* a read-only session opens and reports the committed state while a writer holds
  the lock;
* competing writers are serialised: every write from both processes is present
  exactly once and none is lost.

### 12.6 Corruption

Every corruption is applied to a real store file, the store is then opened, and
the exact refusal code is asserted. Among them: flipped magic, truncated and
zeroed manifests, an unsupported format version, a non-zero reserved field, a
manifest sequence above the truth, a modified chain head, an unparseable journal
name, a traversing journal name, a flipped payload byte, a payload byte flipped
**with its checksums repaired** so that only the hash chain can catch it, a
flipped frame header, a removed trailer, a truncated final frame, prepended
bytes, an empty journal, and a deleted manifest with the journal left in place.
For every case the corrupted bytes are still there afterwards, so nothing was
silently repaired into a different state.

### 12.7 Sanitizers and Debug

Debug is built and tested with the MSVC debug iterator level at 2 and run-time
checks on, which turns container misuse into a failure rather than silent
corruption.

**AddressSanitizer was probed and is not available, and no sanitizer result is
claimed.** The exact probe: `cmake -S . -B build-asan -DTREG_SANITIZERS=ON`
runs `check_cxx_compiler_flag("/fsanitize=address")` against the x64 toolset,
which fails, and the configure stops with

```
-- Performing Test TREG_COMPILER_HAS_ASAN
-- Performing Test TREG_COMPILER_HAS_ASAN - Failed
CMake Error: TREG_SANITIZERS=ON cannot be used with MSVC 19.44.35209.0: a program
built with /fsanitize=address does not compile and link here. Either the toolset
predates AddressSanitizer support (Visual Studio 2019 16.9) or the optional C++
AddressSanitizer component is not installed.
```

The toolset is newer than 16.9, so the cause is the second one: this Visual
Studio installation has the AddressSanitizer runtime for 32-bit targets only
(`clang_rt.asan_dynamic-i386.dll` is present, no x64 equivalent), so an x64
instrumented binary cannot be linked. The build system refuses rather than
silently producing a binary that was never instrumented -- a configure that
"passes" while quietly dropping the sanitizer is the failure mode this is
written to avoid.

The strongest alternative that is actually available was used instead: Debug with
`_ITERATOR_DEBUG_LEVEL=2` and `/RTC1`. Its limit is stated plainly -- it catches
container misuse, iterator invalidation and uninitialized stack use, and it does
**not** catch use-after-free of freed heap blocks or out-of-bounds reads the way
AddressSanitizer does. No ASan, UBSan or TSan result exists for this repository.

### 12.8 Results

The exact commands and their output, on the machine described in section 15:

```
cmake -S . -B build       -G Ninja -DCMAKE_BUILD_TYPE=Release   -> clean, 84 targets
cmake --build build --parallel                                  -> clean, zero warnings
ctest --test-dir build --output-on-failure                      -> 100% tests passed, 0 failed out of 12
build/treg_tests.exe                                            -> 229 passed, 0 failed

cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug     -> clean, 84 targets
cmake --build build-debug --parallel                            -> clean, zero warnings
ctest --test-dir build-debug --output-on-failure                -> 100% tests passed, 0 failed out of 12
build-debug/treg_tests.exe                                      -> 229 passed, 0 failed
```

The twelve ctest targets are the library test binary, the eight examples, the
CLI self-check, the CLI scenario, and the benchmark smoke test. The test binary
runs 229 tests across 33 files.

Debug is not a formality here. It found a defect Release did not: the state
validator's per-kind tally was still sized for six record kinds after the
tombstone record kind was added, so a store containing a permanent tombstone
aborted on reopen under `_ITERATOR_DEBUG_LEVEL=2` and reopened silently in
Release. That is recorded as defect 12 in section 17.

### 12.9 Packaging and downstream

* A staged install into a clean prefix.
* An independent out-of-tree consumer configured against **that prefix only**
  with `find_package(TenantRegistry CONFIG REQUIRED)`, which exercises the public
  API: it declares tenancy, admits it, relates it, refuses a stale request,
  explains a tenant, closes, reopens, and checks that the state digest survives
  the restart.
* A fresh `git clone` of the release commit, configured, built, tested,
  installed, and consumed from that clean clone.

---

## 13. Test suite

Every test file is a proof obligation, not a smoke test.

| Area | What it proves |
| --- | --- |
| identities, counters, keys | the token grammar, saturation, distinct types, digest domain separation |
| lifecycle | every legal and illegal transition, the transition tables, terminality |
| metadata, provenance | duplicate refusal, canonical order, unset staying unset, digest binding |
| canonical codec | byte-for-byte round trips, truncation and trailing-byte refusal, invalid enum refusal |
| registry mutations | creation, admission, ownership, bindings, membership, metadata, retirement |
| dangling references | no relationship can outlive its endpoint; retirement names what is in the way |
| authority and idempotency | staleness, replays before staleness, ledger bounds, restart survival |
| tombstones | retirement, permits, exactly-once reuse, the permanent record |
| queries and traversal | filters, cursors, deterministic order, bounded walks that never claim completeness |
| property tests | randomized state machines with invariants checked after **every** action, printing their seed |
| crash consistency | real abrupt death at each commit stage (section 12.4) |
| multiprocess | real second processes, lock exclusion, kernel lock release (section 12.5) |
| corruption | a sweep over real files (section 12.6) |
| adversarial | hostile identities, text, enums and counts through the public API |

A property test prints the seed it used, so a failure is reproducible from the
output alone. Randomized sequences assert, after every single action, that an
accepted action advanced the generation by exactly one, that a refused action
changed nothing, and that every invariant in section 3 still holds.

There are no test timeouts anywhere. A hang is a defect to diagnose.

---

## 14. Benchmarks

The benchmark tool measures **completed** operations only. Submission or enqueue
latency is never reported as completed work, and a durable figure always includes
the whole real durable path -- the journal append, the flush, the read-back
verification and the atomic manifest replacement.

Every figure is labelled `SYNTHETIC` (measured against generated data in this
process on this machine) or `REAL` (it went through the real durable path). All
figures are single-host wall-clock measurements taken with
`std::chrono::steady_clock`, with percentiles by nearest rank over sorted
samples. No figure in this repository claims physical hardware behaviour.

See section 16 for the measured numbers and the exact methodology that produced
them.

---

## 15. Platform support, and what has not been validated

* **Validated:** Windows x64, MSVC 19.44 (Visual Studio 2022 17.14), Release and
  Debug, on an AMD Ryzen 7 9800X3D with local NTFS storage. Every result in
  section 16 was produced there.
* **Implemented but not validated here:** the POSIX code paths. The writer lock
  (`fcntl`), file replacement (`rename` plus directory `fsync`) and file
  flushing have real POSIX implementations and are not stubs, but no POSIX
  machine was available during this work and **no POSIX result is claimed**.
* **Not claimed:** behaviour on network filesystems, on filesystems that do not
  honour flush semantics, across machines, on 32-bit targets, on big-endian
  targets, or under any sanitizer other than the ones section 12.7 states were
  actually run.
* Times are wall-clock readings of one process on one host with local storage;
  they are not a throughput claim about any hardware.

---

## 16. Measured results

Command: `treg_benchmark`, the full run, on the machine in section 15 with no
other work running. `treg_benchmark --quick` runs the same phases with smaller
counts and is what ctest executes as a smoke test. The tool prints its whole
methodology on every run, including the iteration counts, the warm-up counts,
the tree shape, the limits in force and the percentile rule; the numbers below
are what one run printed, quoted rather than recomputed.

Percentiles are nearest rank over sorted samples. Every figure is a single-host
wall-clock reading taken with `std::chrono::steady_clock` in this process.
`phases_failed=0 refused=0 result=PASS exit_code=0`.

### 16.1 SYNTHETIC -- ephemeral mutation throughput

Completed operations per second, warm-up excluded, against an in-memory registry
with no durable path.

| Operation | Iterations | Completed | Refused | Ops/s |
| --- | --- | --- | --- | --- |
| `create_tenant` | 50 000 | 50 000 | 0 | 203 082 |
| `transition_subject` | 50 000 | 50 000 | 0 | 257 154 |
| `put_ownership` | 50 000 | 50 000 | 0 | 214 812 |
| `put_isolation_membership` | 10 000 | 10 000 | 0 | 10 309 |

`put_isolation_membership` is slower by design: the operation carries a
per-domain capacity check over that domain's membership set, and the benchmark
says so in its own output rather than hiding it.

### 16.2 REAL -- durable commit latency

The whole of `create_tenant` on a durable store: the journal append, the flush
to the device, the read-back verification, the hash chain step and the atomic
manifest replacement. 500 committed mutations after 25 warm-up commits.

| Statistic | Latency |
| --- | --- |
| median | 3 158 us |
| p95 | 3 878 us |
| p99 | 4 053 us |
| min | 2 650 us |
| max | 8 683 us |

That is roughly 300 durable commits per second on local NTFS storage on this
host, each one already on the device and already published before the call
returns. It is not a throughput claim about any hardware.

### 16.3 REAL -- durable compaction

| Measure | Value |
| --- | --- |
| records at compaction | 525 |
| `compact()` wall time | 5.642 ms |
| journal before | `tenant-registry-1.journal`, 349 125 bytes |
| journal after | `tenant-registry-2.journal`, 110 911 bytes |
| records after | 525 (unchanged) |
| committed sequence after | 526 |

### 16.4 SYNTHETIC -- read and query latency

One in-memory registry holding 1 365 tenants, 1 364 ownership edges in a tree of
depth 5 and fan-out 4, one service, one binding, one domain and five
memberships. 200 iterations each.

| Operation | median | p95 | p99 |
| --- | --- | --- | --- |
| `find_tenant` | 0.4 us | 0.4 us | 0.5 us |
| `list_tenants` (whole registry, 2 pages, 1 365 items) | 66.1 us | 117.3 us | 125.6 us |
| `traverse_ownership` descendants (1 364 reached, 1 364 steps, not truncated) | 1 412.0 us | 1 632.9 us | 2 067.4 us |
| `explain` a tenant | 13.3 us | 28.9 us | 31.9 us |

The traversal is given a depth bound one level deeper than the tree, so it
terminates by exhausting the frontier rather than by the bound; the report says
`traverse_truncated=false`, which is what makes it a complete answer rather than
a cut-off one.

### 16.5 SYNTHETIC -- snapshot cost

2 737 records, 483 114 canonical bytes.

| Operation | Iterations | median | p95 | p99 |
| --- | --- | --- | --- | --- |
| `snapshot()` | 30 | 962.2 us | 1 158.3 us | 1 166.3 us |
| `snapshot().digest()` | 100 | 1 784.2 us | 2 251.6 us | 2 444.1 us |

### 16.6 What these numbers do not say

They are not a comparison against any other system, and there is no before/after
or speedup claim anywhere in this repository: no controlled comparable run was
performed that would isolate a change. They say how long one build of this
library took to do these operations on one host, once.

---

---

## 17. Hardening defects found and fixed

Every one of these was found by adversarial testing during this work rather than
by reading the code, every one is fixed, and every one now has a passing test
that pins it. They are listed because the pattern matters more than the
individual bugs: almost all of them are the same mistake in different clothes --
the library accepted and durably stored something it then refused to read, or
enforced a rule on one path and not on another path that reaches the same state.

1. **A legal transition could produce a state the validator refuses.**
   `transition_ownership` into the in-force state did not re-check the
   one-in-force-administrative-owner rule that creation enforces, so a caller
   could reach a state with two accountable owners -- and the next open refused
   the store as corrupt. The rule is now checked on every path that can bring an
   edge into force.
2. **Withdrawing an isolation membership stored a state the validator refuses.**
   Withdrawal is terminal and the record must leave the state; storing it as
   withdrawn made a durable store unopenable. Withdrawal is now a delete in the
   same commit that advances the domain generation.
3. **An empty provenance note could not be read back.** A record the registry
   accepted became unreadable after a restart, because the decoder applied the
   non-empty text rule to a field the encoder legitimately leaves empty. Text
   fields that may be empty are now decoded as such.
4. **Ownership edges never counted as live dependents.** The dependent walk used
   a key prefix that selects edges by child and then compared the parent field,
   so it could never match: a tenant could retire while an in-force edge still
   named it, and every refusal reported `children=0`. Both ends of an edge are
   now counted.
5. **Compaction published a manifest that described a chain the journal did not
   contain.** The manifest was published before the chain seed and base sequence
   the baseline frame was chained from were updated, so a compacted store
   reopened with zero verifiable frames and refused as corrupt. The manifest is
   now built from the values the frame was actually chained with, and they are
   restored if the publication fails.
6. **Compaction left the session's journal position behind.** The baseline frame
   consumes a journal position of its own, so the next commit wrote one sequence
   into its payload and another into its frame header, and the following open
   refused the store. The session's committed position now follows a successful
   compaction.
7. **Replay assumed a journal began at sequence zero**, so any compacted store
   was refused as corrupt on reopen even though its frames were intact. The walk
   is now anchored on the frame that is present while still requiring exactly one
   step per frame.
8. **A crash during the very first commit made a store permanently unopenable.**
   The first commit's flushed-but-unpublished frame was treated as a
   contradiction rather than as an uncommitted tail, so the store had to be
   cleared by hand. Bytes past the committed point are now uniformly treated as
   something that was never published: they are dropped and reported.
9. **`explain()` assumed its subject was a tenant** and threw
   `std::bad_variant_access` for a service or an isolation domain. It now selects
   the record alternative explicitly.
10. **The snapshot digest mixed session authority into the state identity**, so
    two registries holding identical tenancy facts never shared a digest and the
    digest changed across every restart. The digest now covers the tenancy state
    only; the control epoch, incarnation, store identity and journal position
    remain reported fields and remain bound into every mutating decision.
11. **A closed session still answered reads**, presenting state whose owner had
    released the store. Every read on a closed session is now refused with
    `store_closed`.
12. **A store containing a permanent tombstone aborted on reopen in Debug and
    reopened silently in Release.** The state validator's per-kind tally array
    was still sized for six record kinds after the tombstone kind was added, so
    it indexed past its end. `_ITERATOR_DEBUG_LEVEL=2` turned that into an
    assertion failure; in Release it was an out-of-bounds read that happened to
    land inside the object. This is the clearest argument in the repository for
    building and testing both configurations, and it is why section 12.8 reports
    the Debug result as its own result.
13. **A consumed rebind permit was decoded as unconsumed.** The decoder read the
    consumed generation and then discarded it, so a tombstone written with a
    consumed permit came back with an outstanding one, the validator refused the
    coexistence it was supposed to allow, and the store could not be reopened.
14. **The validator forbade the state the rebind design requires.** A live
    successor record and the permanent tombstone that proves the identity was
    fenced must coexist after a handover -- that coexistence *is* the handover.
    The rule now permits it exactly when the permit records it, and still refuses
    every other coexistence.
15. **`max_children_per_tenant` was declared, validated and enforced nowhere.** A
    limit that does nothing is a supported claim that is not true: it is now
    enforced when an ownership edge is created.
16. **The first attempt at that enforcement made declaring an edge cost the whole
    registry.** The canonical key of an ownership edge begins with the child, so
    the children of a tenant are not a key range, and a scan per creation turned a
    50 000-edge benchmark from roughly 215 000 operations per second into 2 081 --
    a hundredfold regression that no correctness test would have caught. The
    count is now maintained with the record map and re-derived and compared by
    the validator, so a drifted index cannot silently be believed. It is recorded
    here because a performance defect introduced while fixing a correctness defect
    is exactly the kind of change that ships unnoticed.
17. **Three tombstone-related keys and two identity keys were built in two places**
    and disagreed, so a permanent tombstone was written under one key and looked
    for under another: `find_tombstone` reported that an identity had never been
    fenced while the snapshot held the record proving it had. There is one builder
    per key now, and a test compares them.
18. **Out-of-range enumerators were accepted by three request validators.** A
    value cast from an integer outside the enum was stored, and the next read
    refused the store as corrupt -- one request, one poisoned store. Every enum
    arriving from a caller is now range-checked at the boundary. The lesson is in
    section 8: a value that cannot be read back must not be accepted, and that
    check belongs where the value enters, not where it leaves.

Three places where the implementation deliberately does **not** do what a
first reading of the design might suggest, each pinned by a test and stated here
so it is not mistaken for an omission:

* Fencing is reachable only from `retired`, and retirement is exactly what a live
  child blocks, so there is no path to a tombstone while a child exists. The
  tombstone operation does re-check dependents; the check is simply unreachable
  by construction.
* A read-only session holds no writer lock, so it is never refused and never
  blocks a writer. That is the design, and it is why an operator can inspect a
  store while it is being written.
* The rebind-permit-consumed refusal is not reachable through the public API:
  after a handover the successor record holds the identity, so a further
  declaration is refused as already existing, with the consumed permit named as
  suppressed evidence. That is the accurate answer -- the identity does exist --
  and the more specific code would suggest the permit failed when it succeeded.

---

## 18. License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
