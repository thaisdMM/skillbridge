# SkillBridge

[![CI](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thaisdMM/ae3f8ce794a99531a58a906e10095831/raw/tests-badge.json)](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml)

A freelancer marketplace platform connecting clients and freelancers. Built as a professional portfolio project targeting the European job market, demonstrating clean Django architecture, REST API design, automated testing, and GDPR-compliant design from day one.

> Architecture decisions and trade-offs documented in [ARCHITECTURE.md](../ARCHITECTURE.md).

---

## Tech Stack

| Layer            | Technology                                                              |
| ---------------- | ----------------------------------------------------------------------- |
| Language         | Python 3.14                                                             |
| Framework        | Django 6.0.7                                                            |
| Database         | PostgreSQL 17                                                           |
| Auth             | Custom user model (`StaffUser` as `AUTH_USER_MODEL`, email-based login) |
| Password hashing | Argon2id                                                                |
| Testing          | pytest · pytest-django                                                  |
| Containerization | Docker · docker-compose                                                 |
| CI               | GitHub Actions                                                          |

---

## Quick Start

**Requirements:** Docker and docker-compose installed.

```bash
git clone https://github.com/thaisdMM/skillbridge.git
cd skillbridge/django_version
cp .env.example .env   # fill in your credentials
docker-compose up --build
```

Run the test suite inside the container:

```bash
docker-compose exec web pytest
```

---

## Architecture

Key decisions documented in [ARCHITECTURE.md](../ARCHITECTURE.md).

### User model hierarchy

The platform uses three independent user tables backed by an abstract base class:

```
BaseUser (abstract — no table)
  ├── Freelancer    → freelancers table
  ├── Client        → clients table
  └── StaffUser     → staff_users table  ← AUTH_USER_MODEL
```

`StaffUser` is the Django `AUTH_USER_MODEL`. `Client` and `Freelancer` are the
platform's business-domain user types. All three share `email` as the primary
identifier (`USERNAME_FIELD = "email"`).

### Profile and skill layer

Each business-domain user owns a one-to-one profile, and both profile types
share a controlled vocabulary of skills:

```
Profile (abstract — no table)
  ├── FreelancerProfile  → OneToOne with Freelancer
  └── ClientProfile      → OneToOne with Client

Skill  ← ManyToManyField from both profile types, admin-curated vocabulary
```

### Key decisions

- **Abstract Base Classes over Multi-Table Inheritance** — independent tables, no
  implicit JOINs
- **Custom validators over Django built-ins** — specific error codes and
  human-readable messages per failure case
- **Argon2id** — primary password hasher; PBKDF2 as legacy fallback only
- **GDPR-aligned logging from day one** — no PII in any log call; `user.id` is
  the only user identifier ever logged
- **`Skill` as an admin-curated vocabulary** — freelancers select from the
  existing list and never create skills
- **Monorepo structure** — `django_version` is the production phase of a
  deliberate learning progression from a pure Python `oop_version`

---

## Apps

### `accounts/`

- Custom user model (`AbstractBaseUser` + `BaseUserManager`, email login)
- `Client`, `Freelancer`, and `StaffUser` with Abstract Base Class pattern
- Custom validators (name, email, password) with specific error codes per failure case
- PostgreSQL integration (psycopg3 + connection pooling)
- GDPR-aligned logging — no PII in any log output

### `profiles/`

- `FreelancerProfile` and `ClientProfile`, each a `OneToOneField(PROTECT)` onto
  its account
- `Skill`, a controlled vocabulary shared by both profile types through a
  `ManyToManyField`
- `clean()` invariants on both profile types — hourly rate / max budget must
  be positive, a profile cannot be created for an inactive account
- 30 seeded skills across 4 categories (`profiles/migrations/0002_seed_skills.py`)

### Admin panel

Profiles have **no standalone screen**. They are edited inline on the account
screen — `FreelancerProfileInline` and `ClientProfileInline`
(`accounts/admin.py`) — so an administrator never leaves the account to view
or edit its profile. `SkillAdmin` (`profiles/admin.py`) is the one screen
`profiles` owns, and the only admin class in the project that permits
deletion, refused while any profile still refers to the skill.

---

## Tests

The suite spans `accounts/` (models, admin, validators) and `profiles/`
(models, admin). The **Tests** badge above tracks the current total live,
recomputed on every push to `main` — see
[.github/workflows/ci.yml](../.github/workflows/ci.yml).

```bash
docker-compose exec web pytest
```

---

## Roadmap

The full feature roadmap is maintained in
[docs/ROADMAP_SKILLBRIDGE.md](../docs/ROADMAP_SKILLBRIDGE.md).

---

## Author

**Thaís Moreira** — Career transition: Law → Backend Python
Open to junior backend Python positions in Europe and remote.
