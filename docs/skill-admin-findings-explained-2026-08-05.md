# Explained — the mechanics behind the `Skill` admin findings

**Date**: 2026-08-05
**Companion to**: `docs/skill-admin-findings-2026-08-04.md`
**Status**: explanation only. No decision is taken here and no file was changed
by writing it. Written for a developer who is still learning Django, so every
mechanism is spelled out rather than assumed.

Everything below was **executed** against the running project — Django 6.0.7
inside `docker-compose exec web`, against the development database — not
recalled from documentation. The exact commands are listed in section 8 so any
claim can be re-run.

---

## 1. How Django validates a model — the four steps

`full_clean()` is the method that runs model validation. It is **not** called
automatically by `.save()` or `.create()`; the Django admin and `ModelForm`
call it for you, and `BaseUserManager.create_user()` calls it explicitly in
this project.

Its real source, read from the container:

```python
def full_clean(self, exclude=None, validate_unique=True, validate_constraints=True):
    errors = {}
    ...
    try:
        self.clean_fields(exclude=exclude)        # step 1 — per-field rules
    except ValidationError as e:
        errors = e.update_error_dict(errors)

    try:
        self.clean()                              # step 2 — your own rules
    except ValidationError as e:
        errors = e.update_error_dict(errors)

    # Run unique checks, but only for fields that passed validation.
    if validate_unique:
        for name in errors:
            if name != NON_FIELD_ERRORS and name not in exclude:
                exclude.add(name)                 # <-- the important line
        try:
            self.validate_unique(exclude=exclude) # step 3 — unique=True checks
        except ValidationError as e:
            errors = e.update_error_dict(errors)

    if validate_constraints:
        for name in errors:
            if name != NON_FIELD_ERRORS and name not in exclude:
                exclude.add(name)                 # <-- same idea
        try:
            self.validate_constraints(exclude=exclude)  # step 4 — Meta.constraints
        except ValidationError as e:
            errors = e.update_error_dict(errors)

    if errors:
        raise ValidationError(errors)
```

Two things to take from this:

- **Errors accumulate in a dictionary keyed by field name.** `errors["name"]`
  is a *list*, so one field can carry several errors at once. That is not a
  Django quirk; it is by design, and section 6 shows a real case of it.
- **Steps 3 and 4 skip any field that already failed.** That is what the
  `exclude.add(name)` loop does, and Django's own comment says it plainly:
  *"Run unique checks, but only for fields that passed validation."*

> **Beginner aside.** Think of a form at a public office. The clerk checks your
> papers in a fixed order. The moment one document is rejected, they stop
> re-checking that same document at later desks — there is no point telling you
> three different things about a paper you already have to redo.

---

## 2. Why the `unique` code disappears once `clean()` has a duplicate rule

Your reading was correct in its conclusion, but the mechanism is worth getting
exactly right, because it changes how you reason about every future rule.

It is **not** that the `unique` error gets renamed. Nothing is renamed. What
happens is:

1. `Skill.clean()` (step 2) finds the duplicate first and raises an error on
   the field `name`, with our own code.
2. Because `name` now carries an error, step 3 puts `name` in `exclude`.
3. `validate_unique()` therefore never even looks at `name`, and never
   produces its `unique` error.

**Two independent checks; the first one to fire is the only one that speaks.**

Executed proof, against the real database (which already contains a skill named
`Python`, seeded by `0002_seed_skills.py`):

| Input | Today | With the new `clean()` rule |
|---|---|---|
| `"Python"` (exact duplicate) | `['unique']` | `['skill_name_duplicate']` |
| `"python"` (case variant) | **no error at all** — this is F-1 | `['skill_name_duplicate']` |
| `"  python  "` | not tested today | `['skill_name_duplicate']` |

The same holds through the admin screen, not just the model. The admin path is
`BaseModelForm._post_clean()`, whose real source shows it calls
`full_clean(..., validate_unique=False, validate_constraints=False)` first and
then `self.validate_unique()` separately — and `validate_unique()` recomputes
`_get_validation_exclusions()`, which contains this clause:

```python
# Exclude fields that failed form validation. There's no need for
# the model fields to validate them as well.
elif field in self._errors:
    exclude.add(f.name)
```

So the admin reaches the same outcome by the same principle. Executed proof
through the actual `SkillAdmin` form:

```
=== ADMIN FORM, TODAY ===
exact duplicate "Python"   : is_valid=False codes={'name': ['unique']}
case variant    "python"   : is_valid=True  codes={}          <-- the defect
=== ADMIN FORM, WITH THE NEW clean() RULE SIMULATED ===
exact duplicate "Python"   : is_valid=False codes={'name': ['skill_name_duplicate']}
case variant    "python"   : is_valid=False codes={'name': ['skill_name_duplicate']}
case+space  "  python  "   : is_valid=False codes={'name': ['skill_name_duplicate']}
brand new name  "Zig"      : is_valid=True  codes={}
```

**This is why the error contract row is revised and not complemented.** After
the change, no input can ever produce `unique` on a path that runs `clean()`.
Listing both codes for the same trigger would document one line that can never
happen.

### The same principle, one layer lower

You remembered an occasion where an `IntegrityError` "became" a `clean()`
error. It is the same principle applied to a third layer:

| Layer | Who checks | What you get |
|---|---|---|
| `clean()` | your Python code | `ValidationError` with your code, attached to a field |
| `validate_unique()` | Django, from `unique=True` | `ValidationError` with code `unique` |
| the database | PostgreSQL, from the index/constraint | `IntegrityError` — a crash, no field, no friendly message |

Each layer is a net under the previous one. The friendlier the layer, the
earlier it runs. The database is last precisely because it is the one that
cannot be bypassed — a `Skill.objects.create(name="python")` typed in the
shell runs **no** `clean()` and **no** `validate_unique()`, and only the
database can still refuse it. That is why the plan pairs the `clean()` rule
with `UniqueConstraint(Lower("name"))` instead of choosing one of them.

---

## 3. Consequence — `test_skill_name_uniqueness` will fail

`profiles/tests/models/test_skill.py:90-99` today asserts:

```python
assert exc_info.value.error_dict["name"][0].code == "unique"
```

After the change, that same call produces `skill_name_duplicate` (proven in the
table above). The test fails — not because anything broke, but because the
contract it asserts was deliberately changed. The fix is to update the assertion
to the new code.

`test_skill_name_uniqueness_enforced_at_database_level` (line 103) is **not**
affected: it bypasses validation entirely and asserts an `IntegrityError`, which
still happens — raised by whichever database index catches it.

---

## 4. Consequence — `test_skill_clean_strips_whitespace` needs `@pytest.mark.django_db`

This one was read backwards, so to state it plainly:

- **It is not** "adding the marker causes a RuntimeError".
- **It is** "missing the marker causes a RuntimeError, once `clean()` starts
  touching the database".

pytest-django blocks database access by default, and every test must declare it
needs the database. The block is real machinery, not a convention —
pytest-django replaces the database connection's `ensure_connection` method with
this wrapper (`pytest_django/plugin.py:879-885`, version 4.12.0 in the
container):

```python
def _blocking_wrapper(*args, **kwargs) -> NoReturn:
    __tracebackhide__ = True
    raise RuntimeError(
        "Database access not allowed, "
        'use the "django_db" mark, or the '
        '"db" or "transactional_db" fixtures to enable it.'
    )
```

So *any* attempt to open a connection inside an undeclared test raises, no
matter which line triggered it.

Today `test_skill_clean_strips_whitespace` is legitimately marker-free, because
`Skill.clean()` is pure Python — it strips a string and checks it is not empty.
No database, no marker needed.

The new rule changes that. Checking "does a skill with this name already exist,
ignoring case?" is a question only the database can answer, so `clean()` starts
issuing a query. Here is the actual SQL, captured from the container while the
simulated rule ran:

```sql
SELECT 1 AS "a" FROM "skills"
WHERE (UPPER("skills"."name"::text) = UPPER('python') AND NOT ("skills"."id" IS NULL))
LIMIT 1;
```

A test that calls `clean()` and has no marker now hits the blocker. Adding
`@pytest.mark.django_db` is the fix.

The other two `clean()` tests in that file are safe, and it is worth
understanding why, because it is the same "first one to fire wins" logic:

- `test_skill_clean_empty_name_raises_validation_error` — the empty-name check
  raises *before* the duplicate check runs, so no query is ever issued.
- `test_skill_clean_none_name_passes_validation` — `clean()` guards everything
  behind `if self.name is not None`, so again no query.

> **Note for `testing.md`.** That file currently says a test calling `clean()`
> alone needs no database access. That stays true for every model **except**
> `Skill` once this rule lands. Worth a sentence there eventually; it is not
> part of the current plan's scope.

---

## 5. Why a rule in `clean()` needs a database backstop anyway

`clean()` protects the paths that call it: the admin, `ModelForm`, and later the
DRF serializers. It protects nothing else. These all bypass it silently:

```python
Skill.objects.create(name="python", category="TECHNOLOGY")   # no clean()
Skill.objects.bulk_create([...])                             # no clean()
Skill.objects.filter(...).update(name="python")              # no clean()
```

`UniqueConstraint(Lower("name"))` lives in the database, so it refuses all
three. This is exactly the pattern the project already uses for
`freelancer_no_inactive_available` (`ARCHITECTURE.md`, *Freelancer —
Active/Availability Invariant*): the friendly check in `clean()` on top, the
database constraint underneath as the net.

**This constraint has nothing to do with deletion.** It only forbids two rows
whose names match ignoring case. Your reading was right.

---

## 6. The whitespace-only name really does raise two errors (F-2b)

Executed against the real `SkillAdmin` form:

```
whitespace only "   " : is_valid=False codes={'name': ['required', 'skill_name_empty']}
```

Why both:

1. The form's `CharField` has `strip=True` by default, so `"   "` becomes `""`
   before anything else happens. `name` is a required form field, so the form
   raises `required`.
2. `name` now carries a form error, so it enters `_get_validation_exclusions()`.
   But that exclusion only suppresses `clean_fields()` and `validate_unique()` —
   **`Model.clean()` is always called regardless**, as the source of
   `_post_clean()` shows. `Skill.clean()` receives `""`, finds it empty, and
   raises `skill_name_empty`.

The administrator sees two messages under one field. The behaviour is correct
and FR-003 holds; only the contract row that documents a single code is wrong.

---

## 7. Deleting a skill — the hidden third table, and what F-5 actually says

### 7.1 Your design decision is not being questioned

The audit does not say that allowing skills to be deleted is a mistake. It is
recorded as a deliberate decision and it holds: accounts are deactivated, a
vocabulary entry is deleted. `Skill` has no `is_active` field for exactly that
reason, and FR-027 / SC-006 state it explicitly. Nothing in the plan changes it.

### 7.2 What "silently drops the join rows" means

A `ManyToManyField` is not a column. Django creates a **third, hidden table**
holding one row per pair. Verified in the container:

```
FreelancerProfile.skills   -> table freelancer_profiles_skills
   FK freelancerprofile -> FreelancerProfile | on_delete = CASCADE
   FK skill             -> Skill             | on_delete = CASCADE

ClientProfile.interests    -> table client_profiles_interests
   FK clientprofile -> ClientProfile | on_delete = CASCADE
   FK skill         -> Skill         | on_delete = CASCADE
```

So the pairing "profile 3 refers to Python" is a row in
`client_profiles_interests`. Delete the `Python` row from `skills` and the
database deletes that pairing row too. No profile is deleted and no error is
raised — the profile simply, quietly, no longer has that skill.

### 7.3 About `on_delete=PROTECT` — you are right, and the wording in the draft was misleading

`Skill` has no `on_delete` policy of its own, and you never declared one,
because **`ManyToManyField` takes no `on_delete` argument at all**. The two
`CASCADE` values above are not yours: Django writes them into the join table it
auto-creates. Verified in the container on 2026-08-05, not assumed:

```
inspect.signature(ManyToManyField.__init__)
  (self, to, related_name=None, related_query_name=None, limit_choices_to=None,
   symmetrical=None, through=None, through_fields=None, db_constraint=True,
   db_table=None, swappable=True, **kwargs)          <- no on_delete

ManyToManyField('profiles.Skill', on_delete=models.PROTECT)
  TypeError: Field.__init__() got an unexpected keyword argument 'on_delete'
```

and in `django/db/models/fields/related.py`,
`create_many_to_many_intermediary_model()` builds both foreign keys with
`on_delete=CASCADE` written literally, with no parameter routing to it.

> **Careful with the phrase "CASCADE is the Django default".** It is not, in
> general. A plain `ForeignKey` has no default — `on_delete` is a required
> positional argument:
>
> ```
> ForeignKey.__init__: (self, to, on_delete, related_name=None, ...)
> ForeignKey('profiles.Skill')
>   TypeError: ForeignKey.__init__() missing 1 required positional argument: 'on_delete'
> ```
>
> The `CASCADE` you are seeing belongs to the intermediary model Django
> fabricates for a many-to-many, and to nothing else.

The only way to change it would be to write an explicit `through=` model with
your own foreign keys — a schema change.

The `docs/tech_debt/` draft mentioned `on_delete=PROTECT` as a **contrast** with
the rest of the codebase (where every FK and O2O does use `PROTECT`), not as a
claim that `Skill` has it or should have it. That sentence will be rewritten so
it cannot be read as a claim.

### 7.4 What F-5 is, then

Narrow and specific: the "cannot delete a skill that is in use" rule lives
**only** in `SkillAdmin.get_deleted_objects()`. That is a method on an admin
screen. It runs when an administrator clicks Delete. It does not run for:

```python
Skill.objects.filter(name="Python").delete()   # shell, script, data migration
```

That deletion succeeds today and takes the pairing rows with it. FR-028 scopes
the rule to "every removal route offered by the skill screens", so the code is
correct *as specified*; SC-010 ("zero profiles lose a skill without the
administrator being told") reads wider. Given that no route outside the admin
exists yet, the decision already taken is to record it as technical debt with
reversal criteria — the same route used for the `company_name` case — rather
than build a `through=` model now.

---

## 8. F-4 — counting references instead of profiles, proven on your own data

The current code (`profiles/admin.py:72-75`):

```python
referring_profiles = sum(
    skill.freelancerprofile_set.count() + skill.clientprofile_set.count()
    for skill in objs
)
```

`objs` is everything the administrator selected. For **one** skill this is
exactly right — a profile can pair with a given skill only once, so pairs and
profiles are the same number. For a **bulk selection** they diverge, because one
profile paired with three selected skills contributes 3.

Executed against the development database. It currently holds these pairings:

```
client profile 2 -> UI/UX Design
client profile 2 -> Content Marketing
client profile 3 -> Python
client profile 3 -> Django
client profile 3 -> Docker
```

Selecting all five of those skills for deletion:

```
current formula (counts references): 7
distinct profiles                  : 3
```

The screen would say *"Still in use by 7 profiles"* when 3 profiles are
affected. The refusal itself is correct — nothing is deleted either way — only
the number is inflated.

**Is the code wrong?** The code matches its contract exactly:
`contracts/admin-surface.md:42-43` literally prescribes that summation. So the
contract carries the imprecision first, and the code faithfully implements it.
That is why the plan corrects both, in the same task.

**Why not simply drop the number?** FR-028 requires it: the refusal must report
*how many profiles refer to it*. Removing the count would fail the requirement.
The count is also the only thing the administrator can act on, since FR-028
forbids listing the profiles individually (GDPR posture). So the fix is to make
the number true, not to hide it.

The replacement also happens to fix F-6 for free: instead of two `COUNT`
queries per selected skill (60 queries for a 30-skill selection), it is two
aggregate queries in total, whatever the selection size.

---

## 9. Commands used

All read-only. Re-runnable from `django_version/`.

```bash
# Django version actually running, and the source of the four validation steps
docker-compose exec web python -c "import django, inspect; \
  from django.db.models import Model; \
  print(django.get_version()); print(inspect.getsource(Model.full_clean))"

# The admin form path: _post_clean, validate_unique, _get_validation_exclusions
docker-compose exec web python -c "import inspect; \
  from django.forms.models import BaseModelForm; \
  print(inspect.getsource(BaseModelForm._post_clean)); \
  print(inspect.getsource(BaseModelForm._get_validation_exclusions))"

# The hidden join tables and their hard-coded CASCADE
docker-compose exec web python manage.py shell   # see section 7.2

# pytest-django's database blocker
docker-compose exec web grep -n -B 3 -A 6 'Database access not allowed' \
  /usr/local/lib/python3.14/site-packages/pytest_django/plugin.py
```

The duplicate-rule behaviour in sections 2 and 6 was reproduced by monkey-patching
`Skill.clean()` **inside a throwaway `manage.py shell` process**. No project file
was modified and nothing was written to the database — `form.is_valid()` and
`full_clean()` only read.
