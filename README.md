# SkillBridge

[![CI](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thaisdMM/ae3f8ce794a99531a58a906e10095831/raw/tests-badge.json)](https://github.com/thaisdMM/skillbridge/actions/workflows/ci.yml)

Freelancer marketplace platform connecting clients and freelancers. Built as a professional portfolio project targeting the European job market.

This repository is structured as a monorepo documenting the full technical evolution of the project — from a pure Python OOP foundation to a production-ready Django application.

---

## Django Version — Active Development

Production-oriented backend, built with:

- **Django 6.1** + **PostgreSQL 17** (psycopg3, connection pooling)
- **Docker** + **docker-compose** for a reproducible dev environment
- **CI/CD** via GitHub Actions — automated tests run on every push
- **pytest** / **pytest-django** — automated test suite, live count tracked by the badge above
- **Argon2id** password hashing, GDPR-aligned logging from day one
- Custom user model, Abstract Base Classes over Multi-Table Inheritance — see [ARCHITECTURE.md](./ARCHITECTURE.md)

→ [`django_version/README.md`](./django_version/README.md) for setup instructions and full technical details.

---

## Repository Structure

| Directory                              | Description                                                     |
| -------------------------------------- | --------------------------------------------------------------- |
| [`django_version/`](./django_version/) | Django application — production-oriented, active development    |
| [`oop_version/`](./oop_version/)       | Pure Python implementation — OOP foundations, 100 tests, closed |

Each directory contains its own `README.md` with setup instructions and technical details.

---

## Author

**Thaís Moreira** — Career transition: Law → Backend Python
Open to junior backend Python positions in Europe and remote.
