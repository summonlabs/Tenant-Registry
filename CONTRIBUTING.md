# Contributing to Tenant Registry

Thank you for your interest in contributing to Tenant Registry. This document
describes the contribution terms and the engineering expectations for this
repository.

## License

By contributing to this project, you agree that your contributions are licensed
under the **Apache License, Version 2.0**. See the `LICENSE` file for the full
license text and the `NOTICE` file for attribution and license notices. There
is **no separate Contributor License Agreement (CLA)** requirement: you retain
ownership of your contributions and grant the project a license to use them
under the terms of the Apache License 2.0.

## License headers

New source files should carry the following header:

```
// Copyright 2026 Summon Software Labs
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
```

## Building

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The build requires a C++20 compiler and CMake 3.20 or newer. There are no
third-party dependencies to fetch, and the build works with no network access.

## Code quality expectations

* **C++20, and only the standard library.** A new third-party dependency is a
  decision about every downstream consumer and needs to be justified in the
  change, not smuggled in.
* **Strict warnings.** Every target is built with `/W4 /WX /permissive-` on
  MSVC and `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror`
  elsewhere. Nothing in this repository suppresses a warning; a warning is
  either fixed or the cause of it is removed.
* **Types carry meaning.** Identities, generations, revisions, epochs,
  incarnations, digests and states are distinct types. Do not add an implicit
  conversion, a default constructor, or an accessor that returns a bare integer
  where a strong type exists.
* **Absence stays absent.** A missing, unknown or unset value must never become
  zero, false, an empty string or a default. If a field can be unset, model it
  as unset.
* **Nothing is inferred.** Isolation, ownership, service relationships and
  metadata are declared explicitly. A change that derives one of them from a
  name, a label, a path or a convention will not be accepted.
* **Determinism is a contract.** For equivalent inputs, every produced byte,
  ordering and digest must be identical across runs, processes, machines and
  container iteration orders.
* **Untrusted input is bounded.** Every length, count, identifier and payload
  that arrives from outside is validated against a configured limit before it
  is used.
* **Durability claims come with proof.** A change to the commit protocol, the
  recovery path or the writer lock needs a test that exercises the real failure
  it is about -- a real second process, a real abrupt death, or a real corrupted
  file -- not a mock.

## Tests

Every behavioural change needs a test. The suite is organised by proof
obligation rather than by file:

* `tests/test_*.cpp` unit and integration tests for one area each.
* Property and randomized state machine tests print the seed they used, so a
  failure is reproducible from the output alone.
* Multiprocess, crash consistency, corruption and lock release tests re-execute
  the test binary as a real child process; they are not simulations.

Run the whole suite with `ctest --test-dir build --output-on-failure`. Do not
add a timeout to a test: a hang is a defect to diagnose, not something to hide
behind a watchdog.

## Documentation

`README.md` is the operating manual for this subsystem. If a change alters the
owned boundary, an invariant, the authority or fencing model, the persistence
or recovery model, the concurrency model, the error precedence, the CLI or the
library interface, the README changes in the same commit.

## Commits

Commit messages are public facing and describe the change to the software.
Describe what changed and why it is correct; do not include internal process
notes. Do not add Co-authored-by trailers.

## Reporting a defect

A useful report contains the exact command or API call, the exact refusal token
and detail text if there was one, the generation and revisions involved, and
whether the store was durable. If a durable store is involved, include the
output of `treg --root <dir> verify`.
