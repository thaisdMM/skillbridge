# SkillBridge

[![CI](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml)

A freelancer marketplace platform connecting clients and freelancers. Built as a professional portfolio project targeting the European job market, demonstrating clean Django architecture, REST API design, automated testing, and GDPR awareness.

> This repository documents the full technical evolution of the project. See [ARCHITECTURE.md](./ARCHITECTURE.md) for design decisions and trade-offs.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.14 |
| Framework | Django 6.0.3 |
| Database | PostgreSQL 17 |
| Auth | Custom user model (email-based login) |
| Password hashing | Argon2id |
| Testing | pytest · pytest-django |
| Containerization | Docker · docker-compose |
| CI | GitHub Actions |

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

## Project Status

**django_version** — active development

- [x] Custom user model (`AbstractBaseUser` + `BaseUserManager`, email login)
- [x] `Client` and `Freelancer` models with Abstract Base Class pattern
- [x] Custom validators (name, email, password) ported from pure Python
- [x] PostgreSQL integration (psycopg3 + connection pooling)
- [x] 65 tests passing
- [x] Docker + docker-compose
- [x] GitHub Actions CI
- [ ] `profiles/` app
- [ ] `jobs/` app
- [ ] Django REST Framework + JWT
- [ ] OpenAPI documentation (drf-spectacular)
- [ ] Deployment (Railway or Render)

---

## Architecture

Key decisions documented in [ARCHITECTURE.md](./ARCHITECTURE.md):

- **Abstract Base Classes over Multi-Table Inheritance** — two independent tables, no unnecessary JOINs
- **Custom user model** — email as `USERNAME_FIELD`, built from `AbstractBaseUser`
- **Service layer** — business logic separated from models
- **Monorepo structure** — `django_version` as a deliberate learning progression

---

## Author

**Thais Moreira** — Career transition: Law → Backend Python
Open to junior backend Python positions in Europe and remote.
