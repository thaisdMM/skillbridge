# Verification — Audit of `profiles/tests/models/test_client_profile.py`

**Date:** 2026-07-29
**Persona:** Verifier (`django_version/VERIFIER.md`)
**Branch:** `feature/django-refactor`
**Audit under verification:** `docs/audits/2026-07-28-audit-test_client_profile.md`

**Primary sources consulted**

- `django_version/profiles/tests/models/test_client_profile.py`
- `django_version/profiles/models/client_profile.py`
- `django_version/profiles/models/base.py`
- `django_version/profiles/models/skill.py`
- `django_version/profiles/tests/conftest.py`
- `django_version/profiles/tests/models/test_base.py`
- `django_version/profiles/tests/models/test_freelancer_profile.py`
- Django 6.0.7 source read inside the container (`Model.full_clean`)
- `ARCHITECTURE.md`, `django_version/CLAUDE.md`, `.claude/rules/testing.md`,
  `.claude/rules/conventions.md`, `django_version/AUDITOR.md`

**Runtime evidence.** All commands executed inside Docker
(`skillbridge-web-1`, Python 3.14.6, Django 6.0.7, pytest 9.1.1,
pytest-django 4.12.0). No file was modified. No state-changing command was run
— the probes below either read framework source or operate on unsaved
in-memory instances that issue no query.

Baseline (the audit was static-only; this establishes the runtime state):

```
$ docker-compose exec web pytest profiles/tests/models/test_client_profile.py
...
18 passed in 1.32s
```

18 collected items = 17 test functions, one of which is parametrized ×2.

**Result:** 9 HOLDS · 0 DOES NOT HOLD · 5 PARTIAL · 2 OPEN QUESTIONS
(14 items reviewed: I-1…I-4, OD-1, O-1…O-8, plus the coverage map)

---

## Part 1 — Finding by finding

### 🟤 Coverage map — PARTIAL (mechanically correct; one framing note)

Every line reference in the map was checked against the source and every one is
correct: `client_profile.py:22, 44, 59, 68, 77, 90, 103, 114, 125, 142, 157,
159`; `base.py:36, 44, 60, 62`. The mapping of production element → covering
test is accurate in all 18 rows.

One note on the row _"`bio` length validation → `test_base.py` (abstract-base
tests, via `FreelancerProfile`) ✅ (by design)"_. This is correct as a statement
of where the test lives (`profiles/tests/models/test_base.py:41-51`, which uses
`FreelancerProfile`), but the behaviour it covers is Django's
`MaxLengthValidator` on `Profile.bio` (`base.py:36-42`) — `Profile` has no
`clean()` at all. So `ClientProfile` inherits _no_ bio invariant of its own.
The "✅ by design" is right; it just is not evidence of project logic being
covered anywhere.

**Source:** `base.py:36-42` (field definition, no `clean()` on `Profile`);
`test_base.py:41-51`.

---

### 🟤 I-1 — No test for the `company_name` guard's false branch — PARTIAL

**The substantive claim HOLDS, and it is stronger than the audit states. The
cited rule does not say what the audit says it says.**

**Verified — the gap is real.**

The guard's false branch is genuinely reachable and genuinely load-bearing.
Probe (no DB access — unsaved instance, `clean()` only):

```
$ docker-compose exec web python -c "... ClientProfile(user=Client(name='X'), company_name='').clean()"
PROBE3: company_name="" passes clean() WITH guard
```

Remove `if self.company_name:` (`client_profile.py:142`) and `"".strip()` is
falsy → `company_name_empty` is raised for every client with no company name.
`company_name` is `blank=True` (`client_profile.py:52-57`), so `""` is a valid,
expected value. The guard is what makes the field optional.

**Verified — no existing test catches that regression.** I checked every
construction site of `ClientProfile` in the codebase:

```
$ grep -rn 'ClientProfile(' profiles accounts config
profiles/tests/models/test_client_profile.py:52, 71, 97, 221
```

Of these, only line 221 (`test_client_profile_user_uniqueness`) builds an
instance with `company_name == ""` and calls `full_clean()`. Lines 52, 71 and
97 all unpack `valid_client_profile_data`, which sets
`company_name="Client Company"` (`conftest.py:122`). The `.create()` paths at
lines 87 and 237 never call `clean()`.

So the whole question is whether `test_client_profile_user_uniqueness` would
fail if the guard were deleted. **It would not** — Django 6.0.7 accumulates
errors rather than short-circuiting. Read from the installed framework:

```
$ docker-compose exec web python -c "import inspect, django.db.models.base as b; print(inspect.getsource(b.Model.full_clean))"

        try:
            self.clean()
        except ValidationError as e:
            errors = e.update_error_dict(errors)

        # Run unique checks, but only for fields that passed validation.
        if validate_unique:
            for name in errors:
                if name != NON_FIELD_ERRORS and name not in exclude:
                    exclude.add(name)
            try:
                self.validate_unique(exclude=exclude)
```

A `company_name` error would add only `company_name` to `exclude`; `user` is
still checked, `unique` is still raised, and both assertions at
`test_client_profile.py:226-227` still pass. **Conclusion: with the guard
deleted, the entire suite goes green on a model that rejects every client
without a company name.** That is exactly the audit's claim, now proved rather
than asserted.

**Does not hold — the rule citation.** The audit cites _`testing.md` → "What to
test in an abstract base model" item 2, "every branch: valid, boundary,
invalid, normalization"_. That section opens with an explicit scope limiter:
_"When writing `test_base.py` for an abstract model, cover these and only
these"_ (`testing.md:737-748`). `ClientProfile` is a concrete model; the
section does not govern it. The audit also cites _"the branch-coverage
principle applied to `clean()` in `conventions.md` → 'Model invariants —
enforced via `clean()`'"_. I read that section in full — it prescribes the
`clean()` _structure_ and warns against **unreachable** conditions. It states
no branch-coverage requirement for tests. That principle does not exist in the
document as cited.

The rule that _does_ support this finding, and that the audit did not cite, is
`testing.md:618-635` — "A test must fail if the behavior under test is
removed", read in the contrapositive: production logic exists whose deletion no
test detects.

**Wording defect in the report.** The sentence _"Delete `if self.company_name:`
and `""` still passes (`"".strip()` is falsy → raises `company_name_empty`)"_
contradicts itself. What is meant is "the test suite still passes". Worth
fixing before this becomes a task, because read literally it says the opposite
of the finding.

**Bottom line: the recommended action stands.** Add the test.

---

### 🟤 I-2 — `get_display_info()`'s documented `ValueError` is untested — PARTIAL

**Every factual claim HOLDS. One rule citation is misapplied. There is a
countervailing rule the audit did not address — I checked it, and the finding
survives it.**

**Verified — the docstring declares it.** `client_profile.py:114-117`:

```python
Raises:
    ValueError: If called on an unsaved instance. The `interests`
        many-to-many relation cannot be used before the instance
        has a primary key.
```

**Verified — the `ValueError` is real.** Probe (no DB access — nothing is
saved, and the exception is raised by the descriptor before any query):

```
$ docker-compose exec web python -c "...
p = ClientProfile(user=Client(name='X'), company_name='Acme', max_budget=Decimal('10'))
p.get_display_info()"

pk = None
PROBE1: ValueError -> "ClientProfile (profile_id=None, user_id=None, max_budget=10)"
        needs to have a value for field "id" before this many-to-many relationship can be used.
```

The dict literal at `client_profile.py:119-126` evaluates `self.user.name`
first (fine, in memory), then `list(self.interests.values_list(...))`, which
raises. The docstring is accurate.

**Verified — no test exercises it.** Neither `test_client_profile.py` nor
`test_freelancer_profile.py` contains a `get_display_info` call on an unsaved
instance; both call it on a fixture-persisted profile
(`test_client_profile.py:136, 152`; `test_freelancer_profile.py:110, 126`).

**Holds — the primary rule citation.** `AUDITOR.md:150` does contain _"TEST
GAPS: missing edge cases"_, and a documented `Raises:` clause is part of the
method contract. Valid.

**Does not hold — the secondary citation.** _"`testing.md` → 'Abstract method
contract' / branch coverage"_ is item 4 of the same abstract-model-scoped
section (`testing.md:737-748`) and does not govern a concrete model; and
`testing.md` contains no "branch coverage" rule by that name. Same defect as
in I-1.

**Objection I raised against the finding, and why it fails.** `testing.md:618`
forbids tests that verify the framework rather than project code — the same
argument the audit itself uses in OD-1 to reject a `URLField` test. The
`ValueError` here is raised by Django's `ManyRelatedManager`, not by any guard
in `ClientProfile`. So: is the proposed test tautological?

Applying the rule's own operational test (`testing.md:634` — _"mentally delete
the line of production code the test targets. If the test still passes, it was
not testing that line"_): delete `"interests": list(self.interests.values_list(
"name", flat=True))` from `client_profile.py:125` and the proposed test fails,
because no `ValueError` is raised. The test therefore targets a line of
`ClientProfile`'s own code — the decision to resolve the M2M eagerly inside
`get_display_info()`. It is not tautological. The finding survives.

`ARCHITECTURE.md:855-862` ("FreelancerProfile — Minimum One Skill Enforced at
Serializer Level") independently confirms the project treats
M2M-on-unsaved-instance as a known trap worth pinning.

**Minor.** The Direction cites `test_base.py:54` for assertion style
("exception type only"). The outcome is right, but the justification does not
transfer: `testing.md:671-689` scopes that rule to `NotImplementedError`
_because_ the message is `gettext_lazy`. Django's `ValueError` message here is
a plain f-string (see probe output). Assert type-only anyway — `ValueError`
has no `code` — but not for the cited reason.

The Direction's note that `@pytest.mark.django_db` is still required is
**correct**: the probe shows `get_display_info()` itself needs no DB, but the
`valid_client_profile_data` → `client_user` → `db` fixture chain does
(`conftest.py:91-125`), and `testing.md:443-448` requires the marker anyway.

**Bottom line: the recommended action stands.**

---

### 🟣 I-3 — `test_add_and_remove_interests` covers two behaviors — HOLDS

Verified against the text of the rule, not a paraphrase of it.

`test_client_profile.py:166-189` performs: `.add(python, django)` → three
assertions (`:179-181`) → `.remove(python)` → three assertions (`:187-189`).
Two state transitions, six assertions, "and" in the name. The audit's count is
exact.

`testing.md:528-540` — all three operational criteria are met:

1. _Naming check_ — the name requires "and" to stay accurate. ✔
2. _One-call rule_ — _"Different calls, different states, or different methods
   belong in different tests, even when they share setup."_ ✔
3. _Failure attribution_ — a failure at `:187` and a failure at `:179` are
   indistinguishable from the test name. ✔

The audit is also right that the shared-expensive-setup exception does not
rescue it. `testing.md:558-562` states the exception _"never covers … [a]ssertions
on different states (before vs after a mutation)"_ — which is precisely this
test.

The consequence stated ("if the `add` assertions fail, the `remove` half never
runs") is correct pytest behaviour: the `assert` at `:179` raises and aborts
the function.

The symmetry note is verified: `test_freelancer_profile.py:140-163` is the same
shape with the same defect.

---

### 🟣 I-4 — Missing `-> None` return annotation — HOLDS

`test_client_profile.py:231-233`:

```python
def test_client_profile_user_uniqueness_enforced_at_database_level(
    client_profile: ClientProfile, client_user: Client
):
```

No return annotation. `testing.md:211` — _"Test functions must always have
return type `-> None`"_; repeated in "Common mistakes to avoid"
(`testing.md:792`). The rule exists and says exactly what the audit quotes.

The comparison is accurate: the freelancer counterpart at
`test_freelancer_profile.py:232-235` is annotated `-> None`, and the count
"the other 16 tests" is right — the file has 17 test functions (18 collected
items, one parametrized ×2), so 16 others.

---

### 🟣 OD-1 — Coverage for optional fields — HOLDS (technical premises)

This is an open decision, not a defect claim, so I verified only its technical
premises. **All of them hold.** The A/B/C choice itself is not something I rule
on.

**"Not open — do not add" half: HOLDS.** A test feeding `"not a url"` and
expecting `ValidationError` would pass with all of `ClientProfile.clean()`
deleted, because `URLField` validation runs in `clean_fields()` — a separate
step from `clean()` in `Model.full_clean` (framework source quoted under I-1).
Same for `max_length=200` on `company_name` (probe:
`max_length = 200`, enforced by `CharField`'s `MaxLengthValidator`) and for
`max_digits`/`decimal_places` on `max_budget` (`DecimalValidator`). The
`testing.md:618` citation is correctly applied here.

**"Genuinely open" half: HOLDS.** The claim that a minimal instance passes
today, and would fail if `blank=True` were dropped from any of the four fields,
is correct. Probe (no DB access):

```
$ docker-compose exec web python -c "...
p = ClientProfile(user=Client(name='X')); p.clean_fields(exclude={'user'}); p.clean()"

OQ/OD-1 probe: minimal ClientProfile passes clean_fields + clean -> '' None '' ''
```

`Field.validate()` raises `blank` for any value in `empty_values`
(probe: `[None, '', [], (), {}]`) when `blank=False` — which covers `None` for
`max_budget` as well as `""` for the three string fields. So one
`full_clean()` call does pin all four `blank=True` declarations.

I make no recommendation between A / B / C — `testing.md` genuinely does not
choose, and per `CLAUDE.md` Rule 5 this is the user's call. The audit's
observation that the choice must be applied symmetrically to
`test_freelancer_profile.py` is sound.

---

### 🟣 O-1 — The new `company_name` test is sound — HOLDS

Verified, and this is the audit's strongest-evidenced item.

Probe:

```
PROBE2 to_python("   ") = '   '
PROBE2 empty_values = [None, '', [], (), {}]
PROBE2 blank = True | max_length = 200
```

Model-level `CharField` does not strip (unlike `forms.CharField`, which has
`strip=True`), and `"   "` is not in `empty_values`, so it survives
`clean_fields()` and reaches `ClientProfile.clean()` intact — the
`company_name_empty` branch is genuinely reachable. Delete
`client_profile.py:145-154` and
`test_client_profile_raises_validation_error_with_empty_company_name` fails.
Not tautological. The assertion shape (`:102-103`) matches
`testing.md:652-658` exactly.

---

### 🟣 O-2 — Typos — HOLDS

All five verified at the cited lines.

| Cited                       | Verified in source                                                                                    |
| --------------------------- | ----------------------------------------------------------------------------------------------------- |
| `:96` `withespace`          | ✔ present                                                                                             |
| `:96` `Validation_Error`    | ✔ present, and the code is unquoted while `:51` quotes its code                                       |
| `:96` no terminating period | ✔ docstring ends `company_name_empty"""`                                                              |
| `:96` awkward phrasing      | ✔                                                                                                     |
| `:51` `"""An max budget`    | ✔ — and `test_freelancer_profile.py:63` does read `An hourly rate`, so the copy-origin claim is right |

---

### 🟤 O-3 — Stray whitespace in the model file — PARTIAL

**The fact holds; the stated consequence does not currently apply to this
repository.**

`git diff` confirms the only working-tree change to the model is trailing blank
lines at EOF:

```
$ git diff -- django_version/profiles/models/client_profile.py
@@ -167,3 +167,5 @@ class ClientProfile(Profile):
             logger.debug("Max budget validation successful")
+
+
```

**Does not hold — "will trip `W391` under flake8/ruff".** No linter is
installed or configured anywhere in this repository: `requirements.txt` pins
neither `flake8` nor `ruff`, and there is no `.flake8`, `ruff.toml`,
`pyproject.toml`, `setup.cfg`, or `.pre-commit-config.yaml` at the repo root or
in `django_version/`. `.github/workflows/ci.yml` runs `pytest` only — no lint
step. Nothing currently flags this. It remains cosmetic noise worth not
committing, which is the audit's actual point.

**Minor.** The reference `client_profile.py:170-172` is off by one — the file
is 171 lines; the blank lines are 170-171.

---

### 🟣 O-4 — `test_client_profile_creation_and_saving` is defensible — HOLDS

Both conditions of `testing.md:542-556` are satisfied, and the audit is right
to say so rather than raise it as a violation:

- All seven assertions (`:31-37`) are facets of **one** return value from **one
  call** — `ClientProfile.objects.get(id=...)` at `:30`. ✔
- Reproducing the setup per assertion would persist a `Client` **and** a
  `ClientProfile` — an FK chain, explicitly named in the exception. ✔

The distinction drawn against I-3 is correct and important: I-3 fails the
exception on _different states_, this test does not. The comparison to
`test_freelancer_profile.py:26` is accurate.

---

### 🟣 O-5 — `assert profile.max_budget is None` is near-tautological — HOLDS

Accurate, and correctly hedged. `test_client_profile.py:79` and
`test_freelancer_profile.py:203` restate a value assigned two lines earlier.
The hedge ("near-", "harmless") is warranted: the assertion is not _fully_
vacuous, because `clean()` in this codebase sometimes mutates during validation
— `Skill.clean()` reassigns `self.name = self.name.strip()`
(`skill.py:110-111`). So the assertion does weakly pin "`ClientProfile.clean()`
does not rewrite `max_budget`". That is not what the test name claims to
verify, which is the audit's point.

---

### 🟣 O-6 — DB-access declarations are correct — HOLDS

Verified test by test. `test_client_profile_inherits_from_profile_class` (`:20`)
and `test_client_profile_ordering` (`:240`) are pure introspection
(`issubclass`, `_meta.ordering`) and correctly carry no marker —
`testing.md:398-404`. Every one of the other 15 test functions carries
`@pytest.mark.django_db`, including those whose fixtures already depend on
`db`, which is what `testing.md:443-448` prescribes as deliberate redundancy.

---

### 🟤 O-7 — Imports and fixtures are clean — PARTIAL

**The substance holds; one count is wrong.**

**Does not hold — "All eight imports are used".** There are **nine** import
statements binding **eleven** names (`test_client_profile.py:7-17`); the audit
then lists all eleven. Trivial, but it is a factual error in the report.

**Holds — everything else.** All eleven names are used: `time` (`:207`),
`Decimal` (`:34`), `pytest`, `ValidationError` (`:59`), `IntegrityError`
(`:235`), `models` (`:161`), `transaction` (`:236`), `Client` (`:84`),
`Profile` (`:22`), `ClientProfile`, `Skill` (`:131`). Ordering is stdlib →
third-party/Django → local per `testing.md:761-776`.

**Holds — the conftest compliance claim.** I verified the "no override
consumers" exception (`testing.md:148-171`) empirically:

```
$ grep -rn 'valid_client_profile_data\|client_user' profiles accounts | grep -v conftest
```

Every override in `profiles/tests/` targets a _profile_ field
(`max_budget`, `company_name`) — no test overrides an email, name, or password
on `Client`. Hardcoding in `client_user` (`conftest.py:98-102`) is therefore
correct. `valid_client_profile_data` returning unparametrized `dict`
(`conftest.py:106`) matches the heterogeneous-dict rule (`testing.md:247-266`),
since it mixes `Client`, `Decimal`, and `str`.

**Holds — the password observation, including "both satisfy the validators".**
I did not take this on trust:

```
$ docker-compose exec web python -c "from accounts.validators.user_validators import validate_strong_password; ..."
Secure!Pass@123 OK
SecurePass@123 OK
```

---

### 🟣 O-8 — Migration-seeded skills are correctly not assumed — HOLDS

`test_client_profile_get_display_info` (`:131-133`) and
`test_add_and_remove_interests` (`:169-173`) both create their `Skill` rows
explicitly. `pytest.ini` does carry `--no-migrations` (verified in the file),
so `profiles/migrations/0002_seed_skills.py` does not run and the `Skill` table
starts empty — `testing.md:485-512`. Correct as stated.

---

## Open questions for the user

These are coherence questions about the project documents, not verdicts. Per
`VERIFIER.md`, I do not rule on them.

### 🟠 OQ-1 — Does the "every branch" rule apply to concrete models?

Both I-1 and I-2 lean on `testing.md`'s _"Field validation via `clean()` —
every branch: valid, boundary, invalid, normalization"_. That list sits under
a heading scoped to abstract base models, and opens with _"cover these and
only these"_ (`testing.md:737-748`).

In practice the project already applies it to concrete models —
`test_client_profile_max_budget_none_passes_validation` (`:66`) and
`test_freelancer_profile_hourly_rate_none_passes_validation` (`:190`) are both
guard-false-branch tests on concrete models, and both exist. So the _intent_
looks broader than the _scope limiter_.

**Question:** was the branch-coverage requirement meant to apply to every
model's `clean()`, with the "abstract base" heading merely being where it was
first written down? If yes, `testing.md` should say so, and I-1/I-2 acquire a
citation that actually supports them.

### 🟠 OQ-2 — Should `ClientProfile.clean()` normalize instead of only rejecting?

Not raised by the Auditor, and **not a finding** — I raise it only because it
changes what I-1's test should assert, so answering it before implementing
avoids writing the test twice.

`Skill.clean()` normalizes then validates (`skill.py:110-113`):

```python
self.name = self.name.strip()
if not self.name:
    raise ValidationError(...)
```

`ClientProfile.clean()` validates against a stripped copy but discards it
(`client_profile.py:144-145`):

```python
stripped_company_name = self.company_name.strip()
if not stripped_company_name:
```

So `company_name = "  Acme  "` is stored with its padding, while
`Skill.name = "  Python  "` is stored as `"Python"`. `conventions.md`
("Field-to-validation contract", step 4) says normalization belongs at the
serializer/form layer — which would make `Skill` the outlier, not
`ClientProfile`.

**Question:** is the divergence intentional (Skill is an admin-managed
controlled vocabulary, so it normalizes; profile fields defer to the
serializer)? I have no way to verify intent from the code, and I am not
proposing a change either way.

---

## Part 2 — Summary

**HOLDS (9)**

- **I-3** — `test_add_and_remove_interests` covers two behaviors. Verified
  against all three criteria in `testing.md:528-540`; the exception provably
  does not apply.
- **I-4** — missing `-> None` at `test_client_profile.py:233`. Rule quoted
  correctly, counts accurate.
- **OD-1** — both halves' technical premises confirmed by runtime probe and
  framework source. The A/B/C choice is the user's (`CLAUDE.md` Rule 5); I make
  no recommendation.
- **O-1** — the new `company_name` test is not tautological. Confirmed by
  runtime probe.
- **O-2** — all five typos confirmed at the cited lines.
- **O-4** — `test_client_profile_creation_and_saving` correctly falls under
  the shared-setup exception.
- **O-5** — near-tautological assertion, correctly hedged.
- **O-6** — DB-access declarations correct throughout.
- **O-8** — seeded skills correctly not assumed.

**DOES NOT HOLD (0)**

No finding was found to be wrong in its substance. Every recommended action in
the audit is warranted.

**PARTIAL (5)**

- **Coverage map** — every line reference correct; one framing note on the
  `bio` row (it covers Django's `MaxLengthValidator`, not project logic).
- **I-1** — the coverage gap is real and I proved it is _worse_ than stated
  (the full suite goes green with the guard deleted, confirmed via Django
  6.0.7's `full_clean` source). But the cited rules do not support it: the
  `testing.md` section is scoped to abstract models, and the
  "branch-coverage principle" attributed to `conventions.md` is not in that
  document. Also, the "Why it matters" sentence contradicts itself as written.
  → **Action stands. Fix the citation and the sentence.**
- **I-2** — every factual claim verified, including the `ValueError` itself via
  runtime probe. One citation misapplied (same abstract-model scope error). I
  tested the finding against `testing.md`'s anti-tautology rule — the objection
  the audit never addressed — and it survives.
  → **Action stands.**
- **O-3** — the trailing whitespace is real (`git diff` confirms), but "will
  trip `W391` under flake8/ruff" does not apply: no linter is installed or
  configured anywhere in this repo and CI runs `pytest` only. Line reference
  off by one.
- **O-7** — "all eight imports" is wrong (nine statements, eleven names).
  Everything else in O-7 verified, including "both passwords satisfy the
  validators", which I ran rather than assumed.

**OPEN QUESTIONS (2)** — OQ-1 (scope of the branch-coverage rule), OQ-2
(normalize-vs-reject divergence between `Skill.clean()` and
`ClientProfile.clean()`). Both go to the user; neither is a verdict.

**Overall.** The audit is substantively accurate. Its recurring weakness is
citation discipline, not analysis: three times it cites a `testing.md` section
that is explicitly scoped to abstract base models as authority over a concrete
model, and once it attributes to `conventions.md` a principle that document
does not contain. The findings themselves survive independent verification —
I-1 emerged stronger than stated once the framework source was read.

---

## Handoff — next session

**Verified.** `docs/audits/2026-07-28-audit-test_client_profile.md` — 4 Issues,
1 Open Decision, 8 Observations, plus the coverage map. 14 items reviewed.

**Counts.** 9 HOLDS · 0 DOES NOT HOLD · 5 PARTIAL · 2 OPEN QUESTIONS.

**Open questions awaiting the user.**

1. OQ-1 — does `testing.md`'s "every branch" rule govern concrete models, or
   only abstract bases? (Affects the citations behind I-1 and I-2.)
2. OQ-2 — is the normalize-vs-reject divergence between `Skill.clean()` and
   `ClientProfile.clean()` intentional? (Affects what I-1's test asserts.)
3. Still open from the audit: **OD-1 option A / B / C** — unchanged by this
   verification; the audit's framing was correct.

**Ready to implement without further input.** I-3 and I-4 — both verdicts are
HOLDS, both are mechanical, and neither depends on any open question. I-4 is a
one-line change; I-3 should be done across `test_client_profile.py` and
`test_freelancer_profile.py` in one pass. O-2's typos and O-3's trailing blank
lines are the same category.

**Blocked.** I-1 (needs OD-1, and ideally OQ-2). I-2 is technically unblocked,
but its citation should be corrected first if OQ-1 is answered.

**Files to attach next session.**

- `django_version/profiles/tests/models/test_client_profile.py`
- `django_version/profiles/tests/models/test_freelancer_profile.py`
- `django_version/profiles/tests/conftest.py`
- `django_version/profiles/models/client_profile.py`
- `.claude/rules/testing.md`
- this report and `docs/audits/2026-07-28-audit-test_client_profile.md`

**Recommended persona.** `DEVELOPER.md` for I-3, I-4, O-2 and O-3 — all
verified HOLDS, all mechanical, none blocked. `PLANNER.md` once OD-1 and OQ-1
are answered, to sequence I-1 and I-2 across both profile test files.

**Verification command.**
`docker-compose exec web pytest profiles/tests/models/test_client_profile.py`
— run during this verification: **18 passed in 1.32s**.

---

Your instinct is sound as a general rule — but this specific test survives it. It is correct and necessary. The reason its necessity isn't obvious is that its name describes the wrong thing.

What the test actually guards
It is not a persistence test. It is the only guard for null=True on client_profile.py:62.

I expected test_client_profile_max_budget_none_passes_validation to already cover that, making this one redundant. It does not. Django 6.0.7 Model.clean_fields:

# Skip validation for empty fields with blank=True. The developer

# is responsible for making sure they have a valid value.

raw_value = getattr(self, f.attname)
if f.blank and raw_value in f.empty_values:
continue
max_budget is blank=True and None is in empty_values → the field is skipped entirely, so Field.validate()'s null check never runs. Probe (in-memory only, no file or DB touched — I simulated deleting null=True by setting f.null = False on the live field object):

as declared: null=True blank=True
WITH null=True -> full_clean path OK
WITHOUT null=True -> full_clean path STILL PASSES <-- validation does NOT catch it
So if you deleted null=True tomorrow:

Test Result
...\_max_budget_none_passes_validation still passes (field skipped)
...\_user_uniqueness (builds ClientProfile(user=...)) still passes
...\_creation_and_saving still passes (max_budget=500)
...\_max_budget_none_persists_on_save fails — IntegrityError, NOT NULL
Apply testing.md:634 — mentally delete the production line. Only this test fails. It is not tautological, and nothing else covers it.

"Shouldn't I test the other fields too?"
No, and this is the key point: there is nothing analogous to test. null=True appears on exactly two model fields in the entire project:

profiles/models/freelancer_profile.py:57 hourly_rate
profiles/models/client_profile.py:62 max_budget
company_name, website_url and bio are blank=True only — their column is NOT NULL with default ''. There is no nullability decision to pin. So the count is already symmetric and complete: one nullable field per profile model, one such test per profile model (test_freelancer_profile_hourly_rate_none_persists_on_save is the twin).

"Should I test saving an updated value?"
No. profile.max_budget = X; save(); reload; assert X exercises Django's ORM UPDATE, not your code — delete every line of ClientProfile and it still passes. That is the tautology rule.

Contrast with test_client_profile_updated_at_changes_on_save, which looks like the same shape but targets auto_now=True on base.py:51 — a project declaration. Remove auto_now=True and it fails. That one earns its place; a generic "update persists" test would not.

Precedent in accounts — yes, and it's a close match
test_freelancer.py:110-155 has the identical two-layer split for the is_active/is_available invariant:

test_freelancer_clean_passes_if_inactive_and_unavailable — validation layer, full_clean() does not raise
test_check_constraint_rejects_inactive_and_available_via_direct_update — DB layer, negative
test_check_constraint_allows_inactive_and_unavailable_via_direct_update — DB layer, positive, .update() then refresh_from_db() then assert
That third one is structurally the same test you're questioning: a positive-path DB-level test whose value is that clean() and the database are separate enforcement layers and one does not imply the other. Your max_budget pair follows the established pattern — validation layer at :67, DB layer at :83.

One honest caveat, and a naming suggestion
The load-bearing line is ClientProfile.objects.create(...) — that is what raises on a NOT NULL column. The .get() + assert ... is None only guards that NULL round-trips as None rather than being coerced, which is psycopg/Django behavior. Marginal, but harmless and consistent with the accounts pattern above.

The real defect is the name. ...\_persists_on_save frames it as a persistence test, which is exactly why it reads as arbitrary to you and why you'd feel obliged to write four more. Something like ...\_max_budget_accepts_null_at_database_level would state the actual contract and sit naturally beside its sibling ...\_user_uniqueness_enforced_at_database_level at :231.

That rename would apply symmetrically to test_freelancer_profile_hourly_rate_none_persists_on_save. Want me to add it to the verification report as a follow-up item, or leave it out? I haven't touched either file.
