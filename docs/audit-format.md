# Audit record format and hash chain

This page is the contract of the `forensic` audit trail: what a record looks like byte for byte, how
its hash is computed, and how to chain and verify records from another language or in your own log.
The Rust code is the reference (`crates/strig/src/audit.rs`); the test
`canonical_vector_matches_the_document` fails if this page and the code drift apart.

## Canonical form

A record is one JSON object in **compact JSON** (no whitespace), encoded as UTF-8.

- **Key order is the order of the fields below**, not alphabetical. Nested objects follow the order
  stated for their type. Maps (`meta`, `attrs`) are written with keys in ascending byte order.
- **Absent fields are omitted**, never `null`: an optional field that is not set, an empty list
  (`violations`, `suggestions`, `roles`, `principals`) and an empty map (`meta`, `attrs`) do not
  appear. A level that does not keep a field leaves it out.
- **Strings** escape only `"` (`\"`), `\` (`\\`) and the control characters below U+0020 (`\b`, `\t`,
  `\n`, `\f`, `\r` for those five, `\u00XX` in lowercase hex for the rest). Everything else, including
  non-ASCII, is written as is in UTF-8 (`é`, not `é`). `/` is not escaped.
- **Integers** are written in decimal with no sign for positive values, no exponent, no fraction
  (`at` is an integer number of milliseconds since the Unix epoch).
- **Enums** are `snake_case` strings.

### Fields of an `AuditRecord`, in order

| # | Field | Type | Present |
|---|---|---|---|
| 1 | `at` | integer, ms since the Unix epoch | always |
| 2 | `level` | `minimal`, `standard`, `detailed`, `forensic` | always |
| 3 | `actor` | string, the actor id (its kind when anonymous) | always |
| 4 | `action` | `grant_add`, `grant_remove`, `tuple_add`, `tuple_remove`, `role_assign`, `role_revoke`, `decision`, `exclusive_acquire`, `exclusive_preempt`, `exclusive_release`, `exclusive_expire`, `mutation_propose`, `mutation_approve`, `mutation_reject`, `mutation_expire`, `elevation_review`, `recert_open`, `recert_decide`, `recert_close` | always |
| 5 | `object` | string: grant id, `object#relation@subject`, `role@subject` (`role#scope@subject` with a scope), or `permission@path` | always |
| 6 | `outcome` | `applied`, `rejected`, `allowed`, `denied`, `pending` | always |
| 7 | `grant` | grant summary | `standard`+ on a grant change |
| 8 | `role` | `{subject, role, scope?}` | `standard`+ on a role change |
| 9 | `violations` | list of strings | `standard`+ on a refusal |
| 10 | `suggestions` | list of suggestions | `standard`+ when an invariant proposed one |
| 11 | `decision` | decision summary | `standard`+ on a decision |
| 11b | `pending` | `{id, author, kind, target, expires_at?, reason?}`, the request of an approval-flow record | `standard`+ on `mutation_*` |
| 11c | `recert` | `{campaign, item?, decision?, target?, reason?}`, the campaign of a recertification record | `standard`+ on `recert_*` |
| 12 | `full_grant` | the whole grant | `detailed`+ on a grant change |
| 13 | `resource` | the whole resource | `detailed`+ on a decision |
| 14 | `explanation` | the full trace | `forensic` on a decision |
| 15 | `tuple` | the ReBAC tuple | `detailed`+ on a tuple change |
| 16 | `actor_detail` | the whole subject | `detailed`+ |
| 17 | `meta` | map of request metadata | `detailed`+, when not empty |
| 17b | `impact` | `{gained, lost, indeterminate, partial?, examples?}`: counts, `partial` only when `true`, and up to 10 example strings (`gained user:bob project.view project:p1`) | `detailed`+, only on a change applied with its impact |
| 18 | `before_digest` | hex string | `forensic` |
| 19 | `after_digest` | hex string | `forensic` |
| 20 | `prev_hash` | hex string, hash of the previous record | `forensic`, omitted on the first record of a chain |
| 21 | `hash` | hex string | `forensic` |

`impact` is the optional field `17b`, written between `meta` and `before_digest`: it is absent from every
record that does not carry an impact, so the canonical form and the hash of those records do not change.
Its keys are `gained`, `lost`, `indeterminate` (integers), `partial` (omitted when `false`) and `examples`
(omitted when empty), in that order.

The order of the nested types is the order of their declaration: a subject is `kind`, `id`, `roles`,
`principals`, `attrs`; a role assignment is `role` and then its scope and validity fields; a tuple is
`object`, `relation`, `subject`. The source of truth for the shape of `grant`, `explanation` and
the rest is the serialization of the Rust types (`serde`, in declaration order); the vector below
covers a tuple change with a subject, and the `forensic` records your own code produces round-trip
through `verifyAuditChain` / `verify_chain`, which re-serialize them in this order.

## Hash of the chain

At the `forensic` level each record carries `prev_hash`, the `hash` of the record before it, and its
own `hash`:

```
hash = lowercase_hex( SHA-256( canonical JSON of the record without the `hash` field ) )
```

The record is serialized with `prev_hash` already set and `hash` left out. Because `hash` is the last
field, a verifier in another language can take a record line as received, cut the trailing
`,"hash":"<64 hex>"` member and hash what is left (it already ends in `}`), with no need to model
every type. The first record of a chain has no `prev_hash`; one that resumes a chain (`resume_chain`,
`audit.prevHash`) carries the hash it continues.

Verification walks the records in the order they were written: each must have a `hash`, each from the
second on must carry a `prev_hash` equal to the `hash` before it, and each `hash` must match the
recomputation. An edited record is `Tampered`, a removed or reordered one makes the next `Broken`.

### The redacted version is what is hashed

Redaction (below) runs before `prev_hash` and `hash` are set: the hash covers the record **as it is
written**, with the sensitive values already masked, so a log that only ever holds the masked version
still verifies. `before_digest` and `after_digest` are computed from the grants before redaction and
carry no attribute.

### Test vector

Record before hashing (a `forensic` tuple change, one line, `prev_hash` of 64 `a`):

```json
{"at":1700000000000,"level":"forensic","actor":"alice","action":"tuple_add","object":"doc:d1#viewer@user:bob","outcome":"applied","tuple":{"object":{"kind":"doc","id":"d1"},"relation":"viewer","subject":{"object":{"kind":"user","id":"bob"}}},"actor_detail":{"kind":"user","id":"alice","roles":[{"role":"admin"}],"principals":["authenticated"]},"meta":{"ip":"203.0.113.42","reason":"ticket \"SUP-1\" é"},"prev_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

SHA-256 of exactly those bytes (UTF-8, no trailing newline):

```
087dbffda54667a64ae971f80c70bf6544b205be90c9ca9cc592ef113f4a4cb5
```

The record as written is the same object with `,"hash":"087dbffd…4cb5"` before the closing `}`. In a
shell: `printf '%s' '<the line above>' | sha256sum`.

## Only the records: chaining in your own log

You do not have to give Strig the destination. `apply` and `applyTemplate` return the records
(`audit` in JS and in `ApplyResult`, `audits` for a template, the `AuditRecord` the `Auditor` returns
in Rust); store them wherever you keep your log, in the order the changes were made.

- **Chain.** Pass `prevHash` (JS) or call `Auditor::resume_chain` (Rust) with the `hash` of the last
  record you stored, so the next record continues it. Keep one writer per chain, or serialize the
  calls: two records made from the same `prevHash` fork the chain.
- **Verify.** In Rust, `verify_chain(&records)`; in JS, `verifyAuditChain(records)`, which answers
  `{ ok: true, head }` or `{ ok: false, code, index }` with `code` one of `TAMPERED`, `BROKEN`,
  `UNCHAINED`, `ANCHOR_MISMATCH`, `HEAD_MISMATCH`. Verify with the records as stored; they are
  re-serialized in the canonical order, so it does not matter that a JavaScript object does not
  keep the order of the keys. Store `hash` and `prev_hash` as opaque strings and do not recompute
  them outside this page's rules.
- **Another language.** Reproduce the vector above, then follow the field order of the table. If you
  keep the JSON Lines text Strig wrote (`JsonLinesAudit`), the bytes of each line already are the
  canonical form and the cut-the-`hash` rule above verifies it with nothing but SHA-256.

## Anchoring the head of the chain

A chain proves that nothing was edited or removed from the middle. It cannot prove that the last
records were not cut off, because there is nothing after them to disagree. Publish the **head**, the
`hash` of the last record, somewhere the writer cannot rewrite: an external log, a signed timestamp, a
ticket. Strig takes no network dependency for this; it only gives you the value and checks against it.

- Rust: `Auditor::chain_head()` (the last record accepted) or `chain_head(&records)`; check with
  `verify_chain_anchored(&records, start, head)`.
- JS: the `hash` of the last `audit` returned, or `verifyAuditChain(records).head`; check with
  `verifyAuditChain(records, { start, head })`.

`head` fails with `HEAD_MISMATCH` if the sequence ends anywhere else, and `start` fails with
`ANCHOR_MISMATCH` if the first record does not continue the hash you know, which lets you verify a
segment (the records since the last anchor) instead of the whole log: the head you published last
time is the `start` of the next check.

## Redaction

`Auditor::with_redactor(mask_attributes(["ip", "email"], "[redacted]"))` (Rust) or
`audit: { redact: { keys: ['ip', 'email'], mask: '[redacted]' } }` (JS) replaces the value of those
attribute keys in `meta`, in the actor's and the resource's `attrs` and in their copies inside a
decision trace, before the record is hashed and written. A custom redactor
(`Auditor::with_redactor`, `hooks.auditRedact` in JS) can change anything else in the record. If it
fails the change is refused whatever the failure mode: the record is never written unmasked.
Redaction does not look inside the condition of a grant or in `object`; keep sensitive values out of
ids.

## When the sink fails

`closed` (the default) refuses the change with the `audit` violation: no record, no change.
`open` lets the change through and keeps the record in an in-memory retry queue:

- Records leave the queue in the order they entered, and nothing is written ahead of the record at
  the head: while it waits, every later record waits behind it, so the sink always sees the chain in
  order. A `closed` record made while others wait forces the queue to drain first and is refused if
  it cannot.
- The queue is bounded (`RetryPolicy::capacity`, default 1024) and retries back off from
  `base_delay_ms` (100) doubling up to `max_delay_ms` (30 000), counted on the auditor's clock.
  Retries happen on the next record or on `flush`.
- A full queue **drops the new record**, keeping the older ones in place. A dropped record is not
  part of the chain (the next record continues the last one that was accepted), so the chain of what
  was written still verifies; the gap is not visible to the verifier. It is reported instead: by
  `AuditStatus::Dropped`, by the `dropped` counter of `AuditStats` and by the `on_drop` callback
  (`onAuditDrop` in JS), which receives the whole record so you can keep it elsewhere.
- The queue lives in memory: records waiting when the process stops are lost. Flush before shutdown
  and treat `pending` as an alarm.

The mode of a record is the first of: the mode of the call (`GovernanceAt::fail_mode`,
`Auditor::grant_mutation_with`, `audit.failMode` in JS), the mode of its permission
(`Auditor::with_permission_fail_mode`, `auditPolicy.permissions` in JS), the auditor's default
(`with_fail_mode`, `auditPolicy.failMode`), `closed`. Role, tuple and exclusive-resource records
carry no permission, so they follow the call and the default. The result of an `apply` says where the
record went: `auditStatus` is `written`, `pending` or `dropped`.

## Approval flow records

The four `mutation_*` actions record the steps of a pending request (`Approvals` in Rust, `propose`,
`resolve` and `expire` in JS). `object` is the request id and `pending` names the request: its `author`
(the actor id of whoever proposed the change), the `kind` of the change (`add`, `remove`, `assign_role`,
`revoke_role`), its `target` (grant id, or `role@subject`), the optional `expires_at` and, on a refusal by
an approver, the `reason`. `outcome` says whether the step took effect:

| action | `actor` | `outcome` |
|---|---|---|
| `mutation_propose` | the author | `pending` when the request was kept, `rejected` when the invariants or the audit refused it |
| `mutation_approve` | the approver | `applied` when the change then went through the governance, `rejected` when the approver was the author, lacked the permission or the invariants now refuse it (`violations` says which) |
| `mutation_reject` | the approver | `applied` when the request was refused, `rejected` when the attempt was refused (`violations`) |
| `mutation_expire` | `strig-expiry` | `applied` |
| `elevation_review` | the reviewer | `applied` when the review of a break-glass elevation was closed (the note is the `reason`), `rejected` when the attempt was refused (the actor reviewing their own use, no permission, no open review, no forensic auditor) |

| `recert_open` | the opener | `applied` when the campaign was opened, `rejected` when it was refused (anonymous opener, deadline not in the future, zero period, empty scope, audit) |
| `recert_decide` | the reviewer | `applied` when the item was kept, revoked or delegated (`recert.decision`, the reason in `recert.reason`), `rejected` when refused (no reviewer permission, own access, separation of duties, past the deadline, invariants) |
| `recert_close` | the closer | `applied` for the closing itself, one record per campaign, `rejected` when refused (before the deadline, no permission). Each item the default action took is a `recert_decide` by the closer with `recert.decision` `expire`, `flag` or `escalate` |

A revocation by a reviewer, or by the closing, also writes the `grant_remove` or `role_revoke` record of the
change itself, as for any governed change.

An elevation (`Elevations` in Rust, `elevate` in the bindings) uses the same actions for its steps, with the
record's metadata carrying `elevation`, `request_id`, `justification`, and, on a break-glass, `break_glass`
and `approved_by` (the actor). The break-glass records (the approval and `elevation_review`) are written under
`FailMode::Closed` and need an auditor at `forensic`; a revocation is a `grant_remove` or `role_revoke`
with `revoked_by` and `reason`. A request for a role or permission the policy does not list is a
`mutation_propose` with outcome `rejected`, the violation `not_in_policy` and `refusal: not_in_policy` in the metadata.

An approval writes `mutation_approve` first and then the `grant_add`/`grant_remove`/`role_*` record of the
change itself, with the author as `actor` and the approver in `meta.approved_by` and the request id in
`meta.request_id` (kept from `detailed`). A request whose approval record exists and whose change record does
not was never applied.

## Merkle tree over a stretch of records

The chain proves the whole log is intact, but only to someone who holds all of it. To hand an auditor
**one record**, or a **stretch**, without the rest, the records are also the leaves of a Merkle tree
as in RFC 6962 (Certificate Transparency), restated by RFC 9162. The hash chain and the record hash
are unchanged; the tree is computed from records as they are written.

- **Leaf.** `leaf = SHA-256( 0x00 || line )`, where `line` is the record exactly as written,
  **including** its `hash` member (the compact JSON of the canonical form above, UTF-8, no trailing
  newline). Including `hash` binds the leaf to the chain.
- **Node.** `node = SHA-256( 0x01 || left || right )` over the two 32-byte child hashes. The distinct
  prefixes keep a leaf from ever being read as a node.
- **Shape.** A tree of `n > 1` leaves splits at `k`, the largest power of two smaller than `n`: the
  left subtree holds the first `k` leaves, the right one the rest. A tree of one leaf has the leaf
  hash as its root. The root of zero leaves is `SHA-256("")`. A tree head is `(size, root)`.
- **Inclusion proof** (RFC 9162 §2.1.3): the sibling hashes from the leaf up to the root, so a
  tree of `size` leaves gives at most `ceil(log2 size)` hashes. The verifier needs the record, its
  `index`, the `size`, the proof and a root it trusts.
- **Consistency proof** (RFC 9162 §2.1.4): proves the tree of `second` leaves extends the tree of
  `first` leaves, so a published older head stays valid and nothing before it was rewritten.

Publish the tree head like the chain head (see Anchoring above); a stamp over the **root** or over
the chain head both work, since each commits to every record before it.

| API | Builds | Verifies |
|---|---|---|
| Rust `strig::merkle` (feature `audit`) | `MerkleTree::from_records`, `inclusion_proof`, `consistency_proof`, `root_at` | `verify_inclusion`, `verify_consistency` |
| JS | | `verifyMerkleInclusion({ record \| leaf, index, size, proof, root })`, `verifyMerkleConsistency({ first, second, firstRoot, secondRoot, proof })` |

The JS functions answer `{ ok: true }` or `{ ok: false, code }` with `code` one of
`INDEX_OUT_OF_RANGE`, `PROOF_LENGTH`, `ROOT_MISMATCH`, `SIZES`; input that is not hex or not a record
throws `INVALID_INPUT`. Hashes are lowercase hex in JSON.

### Test vectors

The RFC 6962 reference leaves, as hex bytes: `""`, `00`, `10`, `2021`, `3031`, `40414243`,
`5051525354555657`, `606162636465666768696a6b6c6d6e6f`. Their leaf hashes make these trees:

| Leaves | Root |
|---:|---|
| 1 | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` |
| 3 | `aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77` |
| 8 | `5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328` |
| 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Leaf 5 (hash `4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658`) in the tree of 8 has
this inclusion proof, in order:

```
bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b
ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0
d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7
```

The consistency proof from the tree of 3 to the tree of 8:

```
0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7
07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7
fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125
6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4
```

And for a record, the leaf of the record of the hash vector above, written with its hash
(`…"prev_hash":"aaaa…aaaa","hash":"087dbffd…4cb5"}`), is:

```
2ae4dc94737c2493a65e7d7329ed18b0a441951dbe14e3f3b5bef172a6a2e658
```

The vectors are pinned by the tests `the_documented_proof_vectors` and
`the_audit_vector_record_has_the_documented_leaf` (Rust) and by `test/audit-proofs.ts` (JS). A
reference in Python, for another language to check against:

```python
import hashlib
H = lambda b: hashlib.sha256(b).digest()
leaf = lambda data: H(b"\x00" + data)
node = lambda l, r: H(b"\x01" + l + r)

def split(n):                       # largest power of two smaller than n
    k = 1
    while k * 2 < n: k *= 2
    return k

def root(ls):
    if not ls: return H(b"")
    if len(ls) == 1: return ls[0]
    k = split(len(ls))
    return node(root(ls[:k]), root(ls[k:]))

def path(i, ls):                    # inclusion proof of leaf i
    if len(ls) <= 1: return []
    k = split(len(ls))
    if i < k: return path(i, ls[:k]) + [root(ls[k:])]
    return path(i - k, ls[k:]) + [root(ls[:k])]

def sub(m, ls, whole):              # consistency proof of the first m leaves
    n = len(ls)
    if m == n: return [] if whole else [root(ls)]
    k = split(n)
    if m <= k: return sub(m, ls[:k], whole) + [root(ls[k:])]
    return sub(m - k, ls[k:], False) + [root(ls[:k])]   # consistency proof = sub(m, leaves, True)
```

## RFC 3161 time stamp of the chain head

A Merkle root or a chain head says what the log held; a time-stamping authority (TSA) says **when**,
signed by someone other than the host. The stamp covers the head, so every record up to it existed
by that time and cannot have been rewritten after it.

- **Request** (`TimeStampReq`, RFC 3161 §2.4.1). `messageImprint` is SHA-256 with the digest being
  the **32 bytes the head's 64 hex characters spell** (not the hex text). `certReq` is true so the
  response carries the TSA certificates; a nonce is optional. Rust: `strig::timestamp::TimestampRequest::for_chain_head(head, nonce)`
  and `to_der()` (feature `timestamp`). POST it with `Content-Type: application/timestamp-query`
  and keep the response, `application/timestamp-reply`; the core does no IO (`examples/timestamp_http.rs`
  shows one way).
- **Verification.** `verify_response` (Rust) and `verifyTimestamp` (JS, no network) fail closed
  unless all hold: the status is granted and a token is present; the `TSTInfo` imprint equals the
  digest and its algorithm; the nonce and the policy match when you give them; the CMS signature over
  the signed attributes is valid and the `messageDigest` covers the `TSTInfo`; and the certificate
  chain from the signer leads to a **root you supply**, with every signature checked, each
  certificate valid at the time the TSA states, intermediates marked as CAs, and the signer's
  extended key usage `id-kp-timeStamping`. With no root, every response is refused. Revocation
  (CRL, OCSP) is not consulted. RSA PKCS#1 v1.5 and ECDSA P-256/P-384 with SHA-256/384/512 are
  supported; BER indefinite lengths and any other algorithm are refused as `MALFORMED` or
  `UNSUPPORTED`.
- **Codes.** `MALFORMED`, `NOT_GRANTED`, `IMPRINT_MISMATCH`, `NONCE_MISMATCH`, `POLICY_MISMATCH`,
  `UNSUPPORTED`, `BAD_SIGNATURE`, `MISSING_SIGNER`, `UNTRUSTED_CHAIN`, `CERTIFICATE_NOT_VALID`,
  `SIGNER_USAGE`.
- **JS input**: `{ response (base64 of the DER), head (hex), roots (PEM text), certificates?, nonce? (hex), policy? }`.
  The answer is `{ ok: true, genTime, time, serial, policy, algorithm, imprint, nonce, signerSubject }`
  or `{ ok: false, code, message }`.

### Test vector

`crates/strig/tests/fixtures/timestamp/` holds a real exchange with the public TSA `freetsa.org`:
`data.txt` (the 24 bytes `strig-audit-head-fixture`), `req.tsq` (made by `openssl ts -query -sha256
-cert -nonce`), `resp.tsr` (the answer, DER), `tsa.crt` and `cacert.pem` (the root to trust).
Reproduce it with:

```
openssl ts -reply -in resp.tsr -text
openssl ts -verify -in resp.tsr -queryfile req.tsq -CAfile cacert.pem
```

which must show SHA-256 imprint `3d5d76d9dea880c2fa7862f7588753877decdd439d905fbae145618888973b95`
(the SHA-256 of `data.txt`), nonce `0x589FA81CDE1D083C`, serial `0x0AC20A6C`, policy `1.2.3.4.1` and
time `2026-11-28T12:18:00Z` (`1795868280`). Treating that digest as a chain head, `verifyTimestamp`
with `head = 3d5d76d9…3b95` and `nonce = 589fa81cde1d083c` answers `ok`; any other head answers
`IMPRINT_MISMATCH`. Revocation of the TSA certificate is not checked, so keep the stamp with the
time you verified it.

## Conformance report

`strig audit report <trail.jsonl>` (and `strig::audit_report::ConformanceReport`, feature `audit`)
reads a JSON Lines trail and summarizes what an auditor asks first: the period; records per action and
outcome; applied changes per actor; refusals per invariant; every chain break (`unchained`, `broken`,
`tampered`) with the record position; the anchors given, compared with the trail; and each time stamp
verified against the chain head. Options: `--anchor-head <hash>`, `--anchor-start <hash>`,
`--timestamp <resp.tsr>` (repeatable) with `--root <ca.pem>` (repeatable, required with a stamp),
`--json` for the report as JSON. The exit status is `0` when the trail conforms (every line read, the
chain intact, every anchor matched, every stamp verified), `1` when it does not and `2` for a usage
error. An empty trail does not conform. The report is data (`serde::Serialize`) with maps ordered by
key, so the same trail gives the same JSON.
