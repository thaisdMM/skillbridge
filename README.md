# SkillBridge

Freelancer marketplace platform - Evolution from pure Python OOP to Django framework.

## 📂 Project Structure

This repository showcases the architectural evolution of the project:

```
skillbridge/
├── oop_version/      # Pure Python implementation (foundational learning)
│   ├── src/          # OOP models with ABC patterns
│   └── tests/        # 73 tests (pytest)
│
└── django_version/   # Django framework implementation (production-ready)
    ├── config/       # Django project settings
    └── manage.py     # Django management
```

## 🎯 Why Two Versions?

It started with OOP to put OOP knowledge into practice.

It switched to Django to apply Django knowledge and for better project development.

**OOP Version:** Demonstrates understanding of:

- Abstract Base Classes & composition patterns
- Type hints & SOLID principles
- Test-driven development (73 tests passing)
- Security best practices (Argon2, GDPR logging)

**Django Version:** Production-ready implementation with:

- Django ORM with PostgreSQL
- Connection pooling (psycopg3)
- Environment-based configuration
- RESTful API architecture (in progress)

## 🚀 Quick Start

### OOP Version

```bash
cd oop_version
python -m venv .venv
source .venv/bin/activate  # Mac/Linux
pip install -r requirements.txt
pytest
```

### Django Version

```bash
cd django_version
python -m venv .venv
source .venv/bin/activate  # Mac/Linux
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## 🛠️ Tech Stack

- **Language:** Python 3.13+
- **Framework:** Django 6.0
- **Database:** PostgreSQL 15
- **Testing:** pytest, pytest-django
- **ORM:** Django ORM (psycopg3 driver)

## 📝 Development Status

🚧 Under active development

**Completed:**

- [x] OOP foundation (User, Profile models with ABC)
- [x] 73 unit tests (pytest)
- [x] Django project setup
- [x] PostgreSQL integration with connection pooling
- [x] Environment-based configuration

**In Progress:**

- [ ] Django models migration (User, Profile)
- [ ] REST API (Django REST Framework)
- [ ] JWT Authentication
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Deployment configuration

## 👤 Author

**Thais Moreira**
Backend Python Developer
Portfolio project for international job market

## 📧 Contact

Looking for junior backend Python positions in Europe/remote
