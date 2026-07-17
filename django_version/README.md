# SkillBridge

[![CI](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/thaisdMM/skillbridge/actionsZ/workflows/ci.yml)

A freelancer marketplace platform connecting clients and freelancers. Built as a professional portfolio project targeting the European job market, demonstrating clean Django architecture, REST API design, automated testing, and GDPR-compliant design from day one.

> Architecture decisions and trade-offs documented in [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Tech Stack

| Layer            | Technology                                                              |
| ---------------- | ----------------------------------------------------------------------- |
| Language         | Python 3.14                                                             |
| Framework        | Django 6.0.3                                                            |
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

Key decisions documented in [ARCHITECTURE.md](./ARCHITECTURE.md).

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

### Key decisions

- **Abstract Base Classes over Multi-Table Inheritance** — independent tables, no
  implicit JOINs
- **Custom validators over Django built-ins** — specific error codes and
  human-readable messages per failure case
- **Argon2id** — primary password hasher; PBKDF2 as legacy fallback only
- **GDPR-aligned logging from day one** — no PII in any log call; `user.id` is
  the only user identifier ever logged
- **Monorepo structure** — `django_version` is the production phase of a
  deliberate learning progression from a pure Python `oop_version`

---

## Foundation

The `accounts/` app is fully implemented and tested:

- Custom user model (`AbstractBaseUser` + `BaseUserManager`, email login)
- `Client`, `Freelancer`, and `StaffUser` with Abstract Base Class pattern
- Custom validators (name, email, password) with specific error codes per failure case
- PostgreSQL integration (psycopg3 + connection pooling)
- GDPR-aligned logging — no PII in any log output
- Docker + docker-compose
- GitHub Actions CI

The platform is in active development. The full feature roadmap is maintained
separately in `ROADMAP.md`.

---

## Author

**Thaís Moreira** — Career transition: Law → Backend Python
Open to junior backend Python positions in Europe and remote.
