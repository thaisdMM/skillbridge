# SkillBridge — OOP Version

Pure Python implementation of the SkillBridge domain models, built as a deliberate learning phase before migrating to Django.

---

## Purpose

This version was built to apply and consolidate Object-Oriented Programming concepts in Python before introducing a framework. The goal was to write real, tested code — not toy examples — using patterns that would later translate directly into the Django version.

---

## What was implemented

**Models**
- `User` — abstract base class with user_id, email, name, hashed_password and created_at
- `Client` and `Freelancer` — concrete subclasses of `User`
- `Profile` — abstract class using `UserProtocol`
- `ClientProfile` and `FreelancerProfile` — concrete profile implementations

**Protocols**
- `UserProtocol` — structural typing to decouple `Profile` from `User` directly, allowing type-safe composition without tight inheritance coupling

**Validators** (`utils/validators.py`)
- Email validation using regex pattern
- Password validation with specific, user-friendly error messages (minimum length, character requirements, special character check)

**Security** (`utils/security.py`)
- Argon2id password hashing

**Logging** (`config/logging_config.py`)
- Structured logging with debug-level tracing on model operations

---

## Tests

100 tests passing with pytest and pytest-cov.

```
tests/models/test_user.py
tests/models/test_client.py
tests/models/test_freelancer.py
tests/models/test_profile.py
tests/models/test_client_profile.py
tests/models/test_freelancer_profile.py
tests/utils/test_security.py
tests/utils/test_validate_email.py
tests/utils/test_validate_password.py
```

---

## Tech Stack

- Python 3.14
- pytest · pytest-cov
- argon2-cffi
- python-dotenv

---

## Quick Start

```bash
cd oop_version
python3.14 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest
```

---

## Why this version was closed

Once Django study reached a sufficient level, continuing this version no longer made sense. The next step would have been simulating a fake database layer — introducing complexity with no real-world value. The decision was made to migrate to Django and apply the same concepts with a real framework and a real database. See [`django_version/`](../django_version/) for the current implementation.
