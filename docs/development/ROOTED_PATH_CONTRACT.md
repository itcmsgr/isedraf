<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Rooted-path contract

Status: IMPLEMENTED
Implements: SCOPE-022, GOV-001, GOV-002

`lib/isedraf/hostpath.py`

The bounded architecture decision taken before the authorized_keys lane opened, so that
lane would not create a third private copy of an operation two lanes already had.

## The invariant

    HOST PATH
        !=
    COLLECTION-ROOT PATH

    normalise in HOST space first
    then map EXACTLY ONCE into collection space

Project-wide, beside the two invariants already frozen:

    NOT PRESENT  !=  PRESENT BUT NOT OBSERVABLE  !=  PRESENT BUT PARTIALLY OBSERVED
    OBSERVATION CAPABILITY  !=  HOST STATE

It belongs with them for the same reason: confusing host space with collection space is
another way evidence from the collector's own machine masquerades as evidence from the
machine under test. Three defects have now come from it — the sudo include, the sshd
Include, and `%h` in authorized_keys, where an already-rooted home was rooted a second
time and produced a path that exists nowhere.

"Exactly once" is the operative half. Mapping zero times reads the live host; mapping
twice reads nothing; and both failures look like ordinary path bugs rather than evidence
defects, which is why the rule is written down rather than remembered.

## The operation

A configuration file names absolute paths. `#include /etc/extra`, `Include
/etc/ssh/*.conf` and an account home of `/home/alice` are statements about the **host's**
filesystem. A collection given a root that is not `/` must read the corresponding object
beneath that root.

    host-absolute lexical path  +  collection root   ->   collection-local lexical path

    root == "/"                 ->   identity
    never realpath as identity
    never a fall-through to the live host

## Disposition: extracted, consumer_count = 3

| Consumer | Operation required | Same? |
|---|---|---|
| sudo — `#include` / `#includedir` target | absolute path + root | yes |
| ssh — `Include` target | absolute path + root | yes |
| authorized_keys — account home, and an absolute `AuthorizedKeysFile` | absolute path + root | yes |
| pam — `include <service>` | service NAME joined to an already-rooted directory | **no** |

PAM was checked and is **not** a consumer. `include password-auth` names a service, and a
name joined to a directory that is already rooted is a different operation that happens to
look alike. The PAM lane contract said to report it either way; it is reported here.

One consumer is domain code. Two is a candidate, which is why the SSH lane recorded itself
as consumer #2 and did not extract. Three with identical semantics is the threshold.

## What was NOT extracted

The **anchor for a relative target**. sudo and sshd anchor a relative include to the
including file's directory; authorized_keys anchors a relative `AuthorizedKeysFile` to the
account's home. Same shape, different meaning — so the branch on absoluteness, and the
choice of anchor, stay in the domain. `under()` refuses a relative path rather than
guessing one.

The helper knows nothing about sudo, SSH, accounts, authorized keys, symlinks, whether
anything exists, or what any of it means for security. It is not a path framework and must
not become one.

## The defect this closed

Both lanes carried this expression:

    os.path.join(root, target.lstrip("/"))

It joins first and normalises never. On a Linux host `/etc/../../tmp/x` names `/tmp/x`,
because `..` above `/` is `/`. Under a collection root that expression yields
`<root>/etc/../../tmp/x`, which the kernel resolves to `/tmp/x` — **on the machine running
the tool**. The relative branch escaped the same way from one level deeper.

Observed, not reasoned about: with the previous expression restored, a `Port` directive
from outside the collection root entered SSH evidence as declared configuration of the
host under test, and a sudoers `SPEC` granting NOPASSWD ALL did the same. Both lanes'
adversarial suites now assert containment against bait placed in a sibling of the root, so
the attack is observable without the live machine being involved.

`under()` normalises in **host space, before the join**. An absolute normalised path
contains no `..` component at all, so containment is a property of the construction rather
than a check bolted on after it. `beneath()` applies the same rule to the relative branch.

Production collection runs with root `/`, where both the old and the new expression are the
identity. No released behaviour changes. The defect was in the offline and fixture path —
which is precisely where corpus work and the authorized_keys lane are going.

## Clamping would have been safe and wrong

Refusing anything that leaves the root passes every containment test and loses the host's
meaning: `/etc/../tmp/x` must map to `<root>/tmp/x`, not to `<root>` or to an error. The
tests assert meaning preservation separately from containment, and an injection mutates
the implementation into the clamping version to prove that assertion fires.

## Lexical containment is not the whole guarantee

`under()` and `beneath()` guarantee the path is lexically inside the root. That is not the
same as the OBJECT being inside it, and the authorized_keys adversarial pass found the
gap: an account whose home IS a symlink pointing out of the collection root produces a
path that is lexically contained while `open()` reads the collector's own machine.

No string arithmetic can see that, so the check does not belong here. It belongs in the
layer that performs I/O, which resolves the path and refuses to read one that lands
outside the root - recording `FILE_OUTSIDE_COLLECTION_ROOT`, an observation and never an
absence. `realpath` is used there as a CHECK and never as identity; the path in the
evidence stays the lexical one, because that is what the host declared.

It is a check rather than a guarantee. Resolve-then-open is racy against an adversary who
can rewrite the tree between the two calls, and ISEDRAF observes rather than defends. What
it closes is a fixture tree reading the machine that runs the tool. **This does not prove
race-free containment and must never be described as proving it.** A future descriptor-based
traversal — `openat` and friends — could close the race; none is required to use this
lane, and none is implemented.

That residual is itself an instance of the rule, which belongs in R1.5-P:

    A PATH AUTHORIZATION CHECK MUST DESCRIBE WHAT IT ACTUALLY PROVES

    lexical containment
        !=
    resolved-target containment
        !=
    race-free acquisition

Three different guarantees, and a check that offers the first while its documentation
implies the third is exactly the kind of claim this project exists not to make.

## Gate hole found alongside it

`check_architecture.py` classified a module by prefix and returned `external` for anything
unlisted — and rule 1 skipped `external`. The four Batch 2 domain lanes matched no prefix,
so ssh, sudo, pam and loginpolicy were exempt from the layering rule for the whole of
Batch 2 and nothing said so. An unlisted module is now a failure rather than an exemption,
with its own self-test case and injection.
