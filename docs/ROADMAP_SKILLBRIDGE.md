# SkillBridge — Plataforma Freelancer Profissional

## Portfólio Mercado Internacional | ROADMAP v2.0

---

## 📊 CONTEXTO DO PROJETO

### Sobre o Projeto

Plataforma de marketplace conectando clientes e freelancers. Escolha estratégica para portfólio internacional: domínio reconhecível por recrutadores europeus, permite aplicar arquitetura real, GDPR compliance, API REST, testes e deploy profissional.

### Status Atual (referência março 2026)

- ✅ App `accounts/` criado com estrutura profissional
- ✅ Models: `BaseUser` (abstract), `Client`, `Freelancer`, `StaffUser`
- ✅ Validators migrados do Python puro para Django
- ✅ `conftest.py` com fixtures criado
- ✅ Testes com `pytest-django`, `@pytest.mark.django_db`, `@pytest.mark.parametrize`
- ✅ Migration gerada e aplicada no PostgreSQL
- ✅ PostgreSQL conectado via `.env`
- ✅ Docker configurado (`Dockerfile` + `docker-compose.yml`)
- ✅ CI/CD configurado (GitHub Actions + badge no README)
- ✅ App `profiles/` criado — `Profile` (base), `Skill` e `FreelancerProfile` implementados; `ClientProfile` em andamento
- ⏳ App `jobs/` ainda não criado

### Decisão Arquitetural Documentada

**Abstract Base Classes (Opção B) escolhida sobre Multi-Table Inheritance (Opção A)**

- Razão: evita JOINs desnecessários em queries simples
- Resultado: 2 tabelas independentes (Client, Freelancer) em vez de 3 (User + Client + Freelancer)
- Trade-off aceito: não é possível fazer query `User.objects.all()` polimórfica

### Princípios Aplicados

- ✅ SOLID (Single Responsibility, Open/Closed, Liskov Substitution)
- ✅ Clean Code (nomes descritivos, funções pequenas, docstrings Google style)
- ✅ Design Patterns (Abstract Factory, Repository, Service Layer)
- ✅ Type Hints (Python 3.14)
- ✅ Testes automatizados (pytest-django)
- ✅ Logging profissional (GDPR-compliant)
- ✅ Docker (containerização)
- ✅ CI/CD (GitHub Actions)

### Stack Técnica

- Python 3.14
- Django 6.x
- PostgreSQL 17+
- Django REST Framework
- djangorestframework-simplejwt
- drf-spectacular (Swagger)
- pytest-django + factory-boy
- Docker + docker-compose
- GitHub Actions (CI/CD)
- Railway ou Render (deploy)

---

# 📅 ROADMAP — 12 SEMANAS (~120h)

## 🔷 FASE 1: FUNDAÇÃO

### Semanas 1-2 (20h)

---

### SPRINT 1.1 — Setup & Infraestrutura Base

**Tempo:** 8h | **Complexidade:** ⭐⭐

### TASK 1.1.1 — Ambiente & Database ✅ CONCLUÍDA

- [x] Criar `.env` com credenciais PostgreSQL
- [x] Criar database no PostgreSQL
- [x] Testar conexão (`psql`)
- [x] Branch `feature/django-refactor` criada
- [x] Projeto Django rodando
- [x] `migrate` inicial funcionando

---

### TASK 1.1.2 — Docker (2h) 🆕 PRIORIDADE ALTA

**Por que agora:** todo o projeto vai rodar sobre Docker. Entrar no CI cedo significa que o histórico de commits já mostra o badge verde desde o início — recrutadores veem isso.

**Entregáveis:**

- [x] `Dockerfile` para a aplicação Django
- [x] `docker-compose.yml` com serviços: `web` (Django) + `db` (PostgreSQL)
- [x] Variáveis de ambiente via `.env` funcionando no container
- [x] `docker-compose up` sobe o projeto completo
- [x] `docker-compose exec web pytest` roda os testes

**Estrutura esperada:**

`skillbridge/
├── Dockerfile
├── docker-compose.yml
├── .env
├── .env.example        ← commitar esse (sem credenciais reais)
└── .dockerignore`

**Conceitos para estudar:**

- Diferença entre `Dockerfile` e `docker-compose`
- Volumes para persistência do banco de dados
- `depends_on` e `healthcheck` no docker-compose
- Por que não commitar `.env` (segurança)

**Testes esperados:** nenhum novo — os existentes devem passar dentro do container.

**Entrega:** `docker-compose up` funciona + testes passam dentro do container.

---

### TASK 1.1.3 — GitHub Actions CI (2h) 🆕 PRIORIDADE ALTA

**Por que agora:** CI rodando desde o início significa que cada commit da Fase 2 em diante já aparece com ✅ ou ❌ no GitHub. Isso é visível publicamente no repositório.

**Entregáveis:**

- [x] Arquivo `.github/workflows/ci.yml`
- [x] Workflow roda `pytest` a cada push em qualquer branch
- [x] PostgreSQL como service no workflow (não mock)
- [x] Badge de CI no README

**Conceitos para estudar:**

- Estrutura de um workflow YAML (name, on, jobs, steps)
- `services` no GitHub Actions para subir PostgreSQL
- GitHub Secrets para variáveis sensíveis
- O que é um badge de status

**Entrega:** push no GitHub → testes rodam automaticamente → badge verde no README.

---

### TASK 1.1.4 — README Inicial em Inglês (1h)

**Por que agora:** recrutador abre o repositório e o README é o que ele vê em 30 segundos. Não precisa estar completo — precisa estar profissional.

**Entregáveis:**

- [x] Descrição do projeto em inglês (3-4 linhas)
- [x] Badge do CI (do GitHub Actions)
- [x] Stack listada
- [x] Instruções básicas: como clonar e rodar com Docker
- [x] Seção "Architecture Decisions" com a decisão Abstract vs Multi-Table documentada

**Entrega:** README que um recrutador europeu consegue ler e entender o projeto.

---

### TASK 1.1.5 — accounts/ `user_validators.py` — Validators ✅ CONCLUÍDA

**Arquivo:** `accounts/validators/user_validators.py`

**Validators implementados** (reutilizáveis em models, serializers e forms):

- [x] `validate_email` — regex `EMAIL_PATTERN` com empty-check explícito primeiro; `strip()` no input. Codes:
  - `empty_email`
  - `invalid_email`
- [x] `validate_user_name` — checagens de comprimento (min 2, max 50), sem regex. Codes:
  - `empty_name`
  - `name_too_short`
  - `name_too_long`
- [x] `validate_strong_password` — checagens condicionais sequenciais, um code por falha; a senha **nunca** é `strip()`/normalizada — qualquer whitespace é rejeitado. Codes:
  - `password_too_short`
  - `password_contains_whitespace`
  - `password_only_digits`
  - `password_missing_lowercase`
  - `password_missing_uppercase`
  - `password_no_special_char`

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- Validators customizados preferidos aos built-ins do Django quando um `code` específico é necessário — `EmailValidator` do Django retorna erro genérico; `validate_email` retorna `empty_email` ou `invalid_email`
- Cada falha levanta `ValidationError` com um `code` único — o `code` é o contrato, a mensagem pode mudar por tradução/copy
- GDPR — logs registram propriedade derivada não sensível (`len(value)`), nunca o valor validado

**Testes implementados:**

`accounts/tests/validators/test_validate_email.py` — **15 testes**, `accounts/tests/validators/test_validate_name.py` — **6 testes**, `accounts/tests/validators/test_validate_password.py` — **11 testes** — **32 testes, todos passando**.

`test_validate_email.py` (15 testes):

1. [x] `test_validate_email_valid_simple` — formato válido aceito
2. [x] `test_validate_email_valid_with_compound_domain` — formato válido aceito
3. [x] `test_validate_email_valid_with_subdomain` — formato válido aceito
4. [x] `test_validate_email_valid_with_numbers_in_username` — formato válido aceito
5. [x] `test_validate_email_valid_with_special_characters` — formato válido aceito
6. [x] `test_validate_email_invalid_empty` — `code` `empty_email`
7. [x] `test_validate_email_invalid_empty_stripped_whitespace` — `code` `empty_email`
8. [x] `test_validate_email_invalid_missing_at_symbol` — `code` `invalid_email`
9. [x] `test_validate_email_invalid_missing_dot_symbol_after_at_symbol` — `code` `invalid_email`
10. [x] `test_validate_email_invalid_format_with_double_dots` — `code` `invalid_email`
11. [x] `test_validate_email_invalid_format_with_spaces` — `code` `invalid_email`
12. [x] `test_validate_email_invalid_format_with_single_letter_tld` — `code` `invalid_email`
13. [x] `test_validate_email_invalid_missing_domain` — `code` `invalid_email`
14. [x] `test_validate_email_invalid_format_without_username` — `code` `invalid_email`
15. [x] `test_validate_email_invalid_format_compound_domain_short_tld` — `code` `invalid_email`

`test_validate_name.py` (6 testes):

1. [x] `test_validate_user_name_with_valid_requirements` — formato válido aceito
2. [x] `test_validate_user_name_with_valid_requirements_min_length` — formato válido aceito no limite mínimo
3. [x] `test_validate_user_name_with_error_stripped_whitespace` — `code` `empty_name`
4. [x] `test_validate_user_name_with_error_empty` — `code` `empty_name`
5. [x] `test_validate_user_name_with_error_too_short` — `code` `name_too_short`
6. [x] `test_validate_user_name_with_error_too_long` — `code` `name_too_long`

`test_validate_password.py` (11 testes):

1. [x] `test_validate_strong_password_with_all_requirements_valid` — caso válido
2. [x] `test_validate_strong_password_with_whitespace_raises_error` — parametrizado (2 casos), `code` `password_contains_whitespace`
3. [x] `test_validate_strong_password_with_error_length_too_short` — `code` `password_too_short`
4. [x] `test_validate_strong_password_with_only_digits_raises_error` — `code` `password_only_digits`
5. [x] `test_validate_strong_password_missing_lowercase_raises_error` — parametrizado (4 casos), `code` `password_missing_lowercase`
6. [x] `test_validate_strong_password_missing_uppercase_raises_error` — `code` `password_missing_uppercase`
7. [x] `test_validate_strong_password_with_error_no_special_character` — `code` `password_no_special_char`

**Padrões estabelecidos:**

- Testes de validator chamam a função diretamente e fazem assert em `exc_info.value.code` (um único `ValidationError`, não `error_dict`) — diferente dos testes de `clean()`, que usam a forma dict por campo
- `@pytest.mark.parametrize` só quando múltiplos inputs compartilham o mesmo `code`; cada `code` distinto tem seu próprio teste nomeado
- Sem `@pytest.mark.django_db` — validators são Python puro, não tocam o banco

**Total accounts/ até aqui: 32 testes passando (32 validators).**

---

### SPRINT 1.2 — Completar accounts/ (já em andamento)

**Tempo:** 6h | **Complexidade:** ⭐⭐⭐

---

### TASK 1.2.1 — accounts/ `base.py` — BaseUser + BaseUserManager ✅ CONCLUÍDA

**Arquivo:** `accounts/models/base.py`

**Campos implementados** (`BaseUser`, `abstract = True`):

- [x] `email` — `EmailField(unique=True, max_length=255, validators=[validate_email])`, `USERNAME_FIELD = "email"`, `REQUIRED_FIELDS = ["name"]`
- [x] `name` — `CharField(max_length=50, validators=[validate_user_name])`
- [x] `created_at` — `DateTimeField(auto_now_add=True)`
- [x] `is_active` (default `True`), `is_staff` (default `False`), `is_superuser` (default `False`)

**Manager implementado** (`BaseUserManager`, definido só em `BaseUser`, herdado pelos concretos):

- [x] `create_user()` — valida email/name/password, normaliza email, hasheia a senha (ou `set_unusable_password()` se ausente) e chama `full_clean()` antes de `save()`
- [x] `create_superuser()` — delega a `create_user()`; faz `setdefault` das flags e levanta `ValueError` se `is_staff` ou `is_superuser` não forem `True`

**Métodos implementados:**

- [x] `user_type` — `@property` → `self.__class__.__name__.lower()` (nunca um field)
- [x] `__str__` → `"{user_type.capitalize()} (id=…)"` · `__repr__` → `"{ClassName} (id=…)"` — sem PII (GDPR: sem email/name)
- [x] `has_perm` exige `is_active and is_superuser`; `has_module_perms` exige `is_active and is_staff`
- [x] `clean()` — invariantes `superuser_without_staff` (superuser ⇒ staff) e `invalid_staff_privileges` (models não-staff não podem ter `is_staff`/`is_superuser`)

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- Abstract Base Classes sobre Multi-Table Inheritance — tabelas independentes, sem JOINs implícitos
- Manager definido só em `BaseUser`, nunca redeclarado nos concretos
- `full_clean()` no caminho do manager — invariantes de `clean()` aplicados na criação via `create_user`/`create_superuser`
- GDPR — `__str__`/`__repr__` sem PII (só type/class + `id`)

**Testes implementados:**

`accounts/tests/models/test_base.py` — **50 testes, todos passando**. Como `BaseUser` é abstract, usa `Freelancer` (casos não-staff) e `StaffUser` (casos superuser/staff).

1. [x] `test_create_user_saves_to_database` — criação/persistência via `create_user()`
2. [x] `test_create_user_stores_correct_email` — criação/persistência via `create_user()`
3. [x] `test_create_user_stores_correct_name` — criação/persistência via `create_user()`
4. [x] `test_create_user_hashes_password` — criação/persistência via `create_user()`
5. [x] `test_create_user_default_flags` — defaults (`is_active=True`, `is_staff=False`, `is_superuser=False`)
6. [x] `test_create_user_without_password_has_no_usable_password` — sem senha → `set_unusable_password()`
7. [x] `test_create_user_normalizes_email` — email normalizado (domínio lowercase)
8. [x] `test_create_user_strips_name_whitespace` — `name` sem espaços nas bordas
9. [x] `test_create_user_accepts_extra_fields` — campo extra do concreto (`is_available`) aceito
10. [x] `test_create_user_email_empty_raises_validation_error` — parametrizado (2 casos), `code` `empty_email`
11. [x] `test_create_user_invalid_email_raises_validation_error` — parametrizado (10 casos), `code` `invalid_email`
12. [x] `test_create_user_name_empty_raises_validation_error` — parametrizado (2 casos), `code` `empty_name`
13. [x] `test_create_user_name_too_short_raises_validation_error` — `code` `name_too_short`
14. [x] `test_create_user_name_too_long_raises_validation_error` — `code` `name_too_long`
15. [x] `test_create_user_password_too_short_raises_validation_error` — parametrizado (2 casos), `code` `password_too_short`
16. [x] `test_create_user_password_contains_whitespace_raises_validation_error` — parametrizado (2 casos), `code` `password_contains_whitespace`
17. [x] `test_create_user_password_only_digits_raises_validation_error` — `code` `password_only_digits`
18. [x] `test_create_user_password_missing_lowercase_raises_validation_error` — `code` `password_missing_lowercase`
19. [x] `test_create_user_password_missing_uppercase_raises_validation_error` — `code` `password_missing_uppercase`
20. [x] `test_create_user_password_no_special_char_raises_validation_error` — `code` `password_no_special_char`
21. [x] `test_create_superuser_saves_to_database` — via `StaffUser`
22. [x] `test_create_superuser_has_correct_admin_flags` — via `StaffUser`
23. [x] `test_create_superuser_hashes_password` — via `StaffUser`
24. [x] `test_create_super_user_with_is_staff_false_raises_value_error` — via `StaffUser`
25. [x] `test_create_super_user_with_is_superuser_false_raises_value_error` — via `StaffUser`
26. [x] `test_clean_method_raises_validation_error_for_superuser_without_staff_status` — invariante `clean()` (`superuser_without_staff`)
27. [x] `test_clean_method_passes_for_valid_superuser` — invariante `clean()` (`superuser_without_staff`), caso válido
28. [x] `test_clean_method_raises_validation_error_for_non_staff_with_privileges` — parametrizado (2 casos: `is_staff`, `is_superuser`), invariante `clean()` (`invalid_staff_privileges`)
29. [x] `test_create_user_rejects_superuser_without_staff_status` — invariante de `clean()` via `create_user()`
30. [x] `test_create_user_rejects_non_staff_model_with_privileges` — invariante de `clean()` via `create_user()`
31. [x] `test_has_perm_returns_false_for_inactive_superuser` — gates de permissão (sem DB, instância não salva)
32. [x] `test_has_perm_returns_true_for_active_superuser` — gates de permissão (sem DB, instância não salva)
33. [x] `test_has_perm_returns_false_for_non_superuser` — gates de permissão (sem DB, instância não salva)
34. [x] `test_has_module_perms_returns_true_for_active_staff_user` — gates de permissão (sem DB, instância não salva)
35. [x] `test_has_module_perms_returns_false_for_inactive_staff_user` — gates de permissão (sem DB, instância não salva)
36. [x] `test_has_module_perms_returns_false_for_non_staff_user` — gates de permissão (sem DB, instância não salva)

**Padrões estabelecidos:**

- Asserção sempre no `code` do `ValidationError`, nunca na string da mensagem
- `@pytest.mark.parametrize` para inputs inválidos que compartilham o mesmo `code`
- `@pytest.mark.django_db` só em testes que tocam o banco; `has_perm`/`has_module_perms` testados sem DB

**Total accounts/ até aqui: 82 testes passando (32 validators + 50 base).**

---

### TASK 1.2.2 — accounts/ `freelancer.py` — Freelancer ✅ CONCLUÍDA

**Arquivo:** `accounts/models/freelancer.py`

**Campos implementados** (`Freelancer(BaseUser)`, tabela `freelancers`):

- [x] `is_available` — `BooleanField(default=True)` — freelancer pode alternar sem desativar a conta
- [x] Demais campos herdados de `BaseUser` (email, name, created_at, flags)

**Métodos implementados:**

- [x] `__repr__` sobrescrito incluindo `is_available` (não-PII); `__str__` herdado de `BaseUser`
- [x] `clean()` — chama `super().clean()` e enforça a invariante `freelancer_inactive_available` (inativo ⇒ não disponível)

**Meta:**

- [x] `db_table = "freelancers"`
- [x] `CheckConstraint` `freelancer_no_inactive_available` — backstop de BD para caminhos que ignoram `clean()` (`0006_freelancer_freelancer_no_inactive_available.py`)

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- Invariante ativo/disponível em duas camadas: `clean()` (app, erro amigável por campo) + `CheckConstraint` (BD, backstop para `.update()`/shell/scripts)
- `is_available` separado de `is_active` — indisponibilidade não é desativação

**Testes implementados:**

`accounts/tests/models/test_freelancer.py` — **12 testes, todos passando**.

1. [x] `test_freelancer_user_type_returns_freelancer` — identidade e default
2. [x] `test_freelancer_is_available_default_is_true` — identidade e default
3. [x] `test_freelancer_is_available_can_be_set_false` — `is_available` pode ser atualizado para `False` e a mudança persiste
4. [x] `test_freelancer_str_representation` — `__repr__` inclui `is_available`
5. [x] `test_freelancer_repr_representation` — `__repr__` inclui `is_available`
6. [x] `test_freelancer_email_is_unique` — email duplicado é rejeitado por `create_user()` com `ValidationError` `code="unique"` (via `full_clean()` → `validate_unique()`), **antes** de tocar o banco
7. [x] `test_create_user_rejects_inactive_and_available_freelancer` — invariante `clean()` (`freelancer_inactive_available`)
8. [x] `test_freelancer_clean_raises_if_inactive_and_available` — invariante `clean()` (`freelancer_inactive_available`)
9. [x] `test_freelancer_clean_passes_if_inactive_and_unavailable` — invariante `clean()` (`freelancer_inactive_available`)
10. [x] `test_freelancer_created_at_is_set_on_creation` — `created_at` preenchido no save
11. [x] `test_check_constraint_rejects_inactive_and_available_via_direct_update` — `.update()` direto ignora `clean()` e levanta `IntegrityError` pela `CheckConstraint`
12. [x] `test_check_constraint_allows_inactive_and_unavailable_via_direct_update` — combinação válida via `.update()` persiste

**Padrões estabelecidos:**

- `clean()` (app) → `ValidationError` amigável por campo; `CheckConstraint` (BD) → `IntegrityError` nos caminhos que ignoram `clean()` (`.update()`, shell, scripts)
- Email duplicado → `ValidationError` `code="unique"` via `create_user()`, **não** `IntegrityError`
- `.save()` + `.refresh_from_db()` antes do assert quando o teste verifica persistência

**Total accounts/ até aqui: 94 testes passando (32 validators + 50 base + 12 freelancer).**

---

### TASK 1.2.3 — accounts/ `client.py` — Client ✅ CONCLUÍDA

**Arquivo:** `accounts/models/client.py`

**Campos implementados** (`Client(BaseUser)`, tabela `clients`):

- [x] Sem campos próprios — herda todos de `BaseUser` (email, name, created_at, flags)

**Métodos implementados:**

- [x] Herda `user_type`, `__str__`, `__repr__`, `has_perm`, `has_module_perms`, `clean()` e o manager de `BaseUser` — sem overrides (nem `objects=` redeclarado)

**Meta:**

- [x] `db_table = "clients"`

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- Abstract Base Classes — `Client` é tabela independente, sem campos extras nesta fase
- `__repr__` herdado de `BaseUser` (sem `is_available`, diferente de `Freelancer`)

**Testes implementados:**

`accounts/tests/models/test_client.py` — **6 testes, todos passando**.

1. [x] `test_client_user_type_returns_client` — `user_type` retorna `"client"`
2. [x] `test_client_str_representation` — sem PII, sem `is_available` (herdado de `BaseUser`)
3. [x] `test_client_repr_representation` — sem PII, sem `is_available` (herdado de `BaseUser`)
4. [x] `test_client_email_is_unique` — email duplicado rejeitado por `create_user()` com `ValidationError` `code="unique"`
5. [x] `test_client_create_user_has_correct_flags` — `is_staff`/`is_superuser` `False`, `is_active` `True` por default
6. [x] `test_client_created_at_is_set_on_creation` — `created_at` preenchido no save

**Padrões estabelecidos:**

- Model concreto sem campos próprios ainda tem testes de identidade (`user_type`, `__str__`/`__repr__`) e de defaults herdados
- Email duplicado → `ValidationError` `code="unique"` (mesmo padrão de `Freelancer`)

**Total accounts/ até aqui: 100 testes passando (32 validators + 50 base + 12 freelancer + 6 client).**

---

### TASK 1.2.4 — accounts/ `staff_user.py` — StaffUser ✅ CONCLUÍDA

**Arquivo:** `accounts/models/staff_user.py`

**Campos implementados** (`StaffUser(BaseUser)`, tabela `staff_users`):

- [x] `is_staff` — override para `BooleanField(default=True)` (default de `BaseUser` é `False`)
- [x] Demais campos herdados de `BaseUser`

**Métodos implementados:**

- [x] `clean()` — chama `super().clean()` e enforça a invariante `staffuser_active_without_staff` (ativo ⇒ staff)
- [x] `user_type` retorna `"staffuser"`; `__str__`/`__repr__` herdados de `BaseUser`

**Meta:**

- [x] `db_table = "staff_users"`
- [x] `CheckConstraint` `staffuser_active_no_staff_status` — backstop de BD (`0007_staffuser_staffuser_active_no_staff_status.py`)

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- `StaffUser` é o `AUTH_USER_MODEL` (configuração na TASK 1.2.6)
- Invariante ativo/staff em duas camadas: `clean()` (app) + `CheckConstraint` (BD)
- `is_staff` default `True` — `StaffUser` existe para acessar o Django admin

**Testes implementados:**

`accounts/tests/models/test_staff_user.py` — **9 testes, todos passando**.

1. [x] `test_create_staff_user_has_is_staff_true_by_default` — override do default
2. [x] `test_staff_user_user_type_returns_staffuser` — `user_type` `"staffuser"` (sem DB)
3. [x] `test_clean_raises_when_active_and_not_staff` — invariante `clean()` (`staffuser_active_without_staff`)
4. [x] `test_create_user_rejects_active_staff_user_without_staff_status` — invariante `clean()` (`staffuser_active_without_staff`)
5. [x] `test_clean_does_not_raise_for_valid_active_staff_states` — parametrizado, 3 combinações válidas
6. [x] `test_constraint_raises_integrity_error_on_update_bypassing_clean` — `.update()` ignora `clean()` → `IntegrityError` pela `CheckConstraint`
7. [x] `test_constraint_allows_inactive_non_staff_via_direct_update` — combinação válida via `.update()`

**Padrões estabelecidos:**

- Mesma dupla camada `clean()` (app) / `CheckConstraint` (BD) de `Freelancer`
- Combinações válidas testadas via `@pytest.mark.parametrize`

**Total accounts/ até aqui: 109 testes passando (32 validators + 50 base + 12 freelancer + 6 client + 9 staff_user).**

---

### TASK 1.2.5 — accounts/ `admin.py` — Django Admin ✅ CONCLUÍDA

**Arquivo:** `accounts/admin.py`

**Estrutura implementada** (composição base + mixin, sem duplicação de método):

- [x] `BaseAccountAdmin` (não registrado) — comportamento comum: `has_delete_permission=False`, `save_model` com `set_unusable_password()`, `created_at_display`
- [x] `StatusBadgeMixin` (opt-in) — `status_badge` verde ativo / vermelho inativo com `format_html` (XSS-safe)
- [x] `FreelancerAdmin(StatusBadgeMixin, BaseAccountAdmin)` — registrado via `@admin.register(Freelancer)`
- [x] `ClientAdmin(StatusBadgeMixin, BaseAccountAdmin)` — registrado via `@admin.register(Client)`
- [x] `StaffUserAdmin(BaseAccountAdmin)` — registrado via `@admin.register(StaffUser)`; não usa `StatusBadgeMixin` (colunas cruas `is_active`/`is_staff`)

**`FreelancerAdmin`:**

- [x] `list_display`: `id`, `name`, `email`, `status_badge`, `availability_badge`, `created_at_display`
- [x] `list_display_links`: `name`, `email`
- [x] `list_filter`: `is_active`, `is_available`, `created_at`
- [x] `search_fields`: `name`, `email` · `ordering`: `-created_at` · `list_per_page`: 25
- [x] `readonly_fields`: `created_at`, `last_login`
- [x] `fieldsets`: (sem título) `name`/`email`; `Account Status` `is_active`/`is_available`; `Important Dates` `created_at`/`last_login` (colapsável)
- [x] `availability_badge` com `format_html` (azul disponível / laranja ocupado)
- [x] actions: `activate_accounts` (bulk `.update()`), `set_available` (loop + `obj.clean()`, pula inativos), `set_unavailable` (bulk `.update()`)

**`ClientAdmin`:**

- [x] `list_display`: `name`, `email`, `status_badge`, `created_at_display`
- [x] `list_display_links`: `name`, `email` · `list_filter`: `is_active`, `created_at`
- [x] `search_fields`: `name`, `email` · `ordering`: `-created_at` · `list_per_page`: 25
- [x] `readonly_fields`: `created_at`, `last_login`
- [x] `fieldsets`: (sem título) `name`/`email`; `Account Status` `is_active`; `Important Dates` (colapsável)
- [x] actions: `activate_accounts` (bulk `.update()`)

**`StaffUserAdmin`** (interface mínima, focada em segurança):

- [x] `list_display`: `name`, `email`, `is_active`, `is_staff`, `created_at_display`
- [x] `list_display_links`: `name`, `email` · `list_filter`: `is_active`, `created_at`
- [x] `search_fields`: `name`, `email` · `ordering`: `-created_at` · `list_per_page`: 25
- [x] `readonly_fields`: `created_at`, `last_login`, `is_superuser` (`is_superuser` sempre readonly)
- [x] `fieldsets`: (sem título) `name`/`email`; `Account Status` `is_active`; `Administrative` `is_staff`/`is_superuser` (colapsável); `Important Dates` (colapsável)
- [x] `get_readonly_fields` — adiciona `is_staff` ao readonly para não-superusers
- [x] actions: `activate_accounts` (loop + `obj.clean()`, pula não-staff), `deactivate_accounts` (bulk `.update()`)

**Segurança e padrões transversais:**

- [x] `has_delete_permission = False` em todos os admins — contas devem ser desativadas, não deletadas
- [x] `save_model` em todos os admins chama `set_unusable_password()` quando o campo senha está vazio — previne string vazia no banco
- [x] `is_staff` e `is_superuser` fora de `FreelancerAdmin`/`ClientAdmin` — não são atributos de negócio desses models
- [x] `has_module_perms` (em `base.py`) exige `is_active` e `is_staff` — gate de acesso ao admin
- [x] `ngettext` nas bulk actions para pluralização correta
- [x] Type hints: `SafeString` nos badge methods, `ModelForm` no `save_model`
- [x] CRUD de `Client`, `Freelancer` e `StaffUser` verificado no painel `/admin/`

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- Password handling — `set_unusable_password()` via `save_model`
- Staff access control — acesso ao admin exige `is_active=True` + `is_staff=True`
- Deletion disabled — desativação via `is_active` é a operação correta
- Privilege field separation — `is_staff`/`is_superuser` fora do Admin de `Client` e `Freelancer`
- Deduplicação de comportamento via `BaseAccountAdmin` (não registrado) + `StatusBadgeMixin` (opt-in)
- Actions que podem violar invariante usam loop + `obj.clean()` (pula inválidos com `WARNING`); actions seguras usam bulk `.update()`

**Testes implementados:**

`accounts/tests/admin/test_admin.py` — **17 testes, todos passando**.

1. [x] `test_set_unavailable_sets_all_selected_freelancers_to_unavailable` — actions de disponibilidade
2. [x] `test_set_available_sets_active_freelancers_to_available` — actions de disponibilidade
3. [x] `test_set_available_skips_inactive_freelancer_and_does_not_persist_forbidden_state` — `set_available` pula inativos (loop + `clean()`); estado proibido nunca persiste
4. [x] `test_set_available_updates_active_and_skips_inactive_in_mixed_queryset` — `set_available` pula inativos (loop + `clean()`); estado proibido nunca persiste
5. [x] `test_freelancer_activate_accounts_activates_inactive_freelancer` — `activate_accounts` (bulk)
6. [x] `test_client_activate_accounts_activates_inactive_client` — `activate_accounts` (bulk)
7. [x] `test_staff_user_activate_accounts_activates_users_with_staff_status` — `activate_accounts` de staff ativa bloco todo com `is_staff=True`
8. [x] `test_staff_user_activate_accounts_skips_non_staff_user_and_does_not_persist_forbidden_state` — `activate_accounts` de staff pula não-staff
9. [x] `test_staff_user_activate_accounts_activates_staff_and_skips_non_staff_in_mixed_queryset` — `activate_accounts` de staff pula não-staff em queryset misto
10. [x] `test_staff_user_deactivate_accounts_deactivates_active_staff_user` — `deactivate_accounts` (bulk)
11. [x] `test_freelancer_admin_neither_defines_nor_inherits_deactivate_accounts` — Freelancer/Client não expõem bulk deactivation
12. [x] `test_client_admin_neither_defines_nor_inherits_deactivate_accounts` — Freelancer/Client não expõem bulk deactivation
13. [x] `test_admin_disables_delete_permission` — parametrizado (3 admins), `has_delete_permission` `False`
14. [x] `test_save_model_sets_unusable_password_when_password_missing` — senha inutilizável quando ausente
15. [x] `test_get_readonly_fields_makes_is_staff_readonly_for_non_superuser` — `is_staff` readonly para não-superuser

**Padrões estabelecidos:**

- Actions que podem violar invariante (`set_available`, `activate_accounts` de staff) usam loop + `obj.clean()` e pulam inválidos com mensagem `WARNING`; actions seguras usam bulk `.update()`
- Testes de admin usam `RequestFactory` + `FallbackStorage` para capturar `messages`

**Total accounts/ até aqui: 126 testes passando (32 validators + 50 base + 12 freelancer + 6 client + 9 staff_user + 17 admin).**

---

### TASK 1.2.6 — accounts/ — AUTH_USER_MODEL & reset de migrações ✅ CONCLUÍDA

**Arquivos:** `config/settings.py`, `accounts/models/__init__.py`, `accounts/migrations/`, `pytest.ini`

**Configuração implementada:**

- [x] `AUTH_USER_MODEL = "accounts.StaffUser"` em `config/settings.py`
- [x] `StaffUser` exposto em `accounts/models/__init__.py` (`__all__`)
- [x] `PASSWORD_HASHERS` com `Argon2PasswordHasher` como primário (fallback PBKDF2)
- [x] Migrações pré-StaffUser apagadas e `0001_initial.py` recriado do zero
- [x] Banco resetado no Docker: tabelas `staff_users`, `clients`, `freelancers` independentes
- [x] `django_admin_log` referencia `AUTH_USER_MODEL` (`staff_users`)
- [x] Superuser criado em `staff_users` com senha hasheada via Argon2; login verificado no Django Admin
- [x] `--no-migrations` adicionado ao `pytest.ini` — testes desacoplados dos arquivos de migração

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- `AUTH_USER_MODEL = "accounts.StaffUser"` — terceiro model concreto, preserva a decisão ABC vs MTI; escolhido antes da primeira migração e não deve mudar
- Argon2id como hasher primário — decisão arquitetural, não configuração
- `--no-migrations` nos testes — schema criado direto dos models; data migrations (ex.: seed de skills) não rodam no ambiente de teste

**Total accounts/ até aqui: 126 testes passando (sem novos testes — tarefa de configuração).**

---

✅ CHECKPOINT FASE 1

- [x] Docker rodando localmente (`docker-compose up`)
- [x] CI verde no GitHub Actions (badge no README)
- [x] 126 testes passando dentro do container
- [x] README profissional em inglês com badge CI + instruções Docker

* decisões arquiteturais

- [x] `accounts/` completo: models, admin, testes, validators
- [x] `AUTH_USER_MODEL` configurado antes de qualquer migração
      dependente
- [x] `ARCHITECTURE.md` com todas as decisões documentadas

## 🔷 FASE 2: PROFILES & JOBS

### Semanas 3-4 (20h)

---

### SPRINT 2.1 — App profiles/

**Tempo:** 6h | **Complexidade:** ⭐⭐⭐

---

### TASK 2.1.1 — Criar app profiles/ e estrutura ✅ CONCLUÍDA

**Estrutura implementada:**

- [x] `python manage.py startapp profiles`
- [x] Subpastas `models/`, `tests/` (com `tests/models/`)
- [x] Registrado em `INSTALLED_APPS` (`config/settings.py:36`, via `profiles.apps.ProfilesConfig`)
- [x] `profiles/apps.py` configurado — mesmo padrão de `accounts/apps.py`: apenas
      `verbose_name` e `ready()` com `pass`; nenhuma configuração adicional
      (signals, validators) é necessária nesta fase do projeto

**Estrutura real:**

`profiles/
├── models/
│   ├── __init__.py
│   ├── base.py
│   ├── skill.py
│   ├── freelancer_profile.py
│   └── client_profile.py
├── admin.py
├── apps.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    └── models/
        ├── __init__.py
        ├── test_base.py
        ├── test_skill.py
        ├── test_freelancer_profile.py
        └── test_client_profile.py`

---

### TASK 2.1.2 — profiles/ `base.py` — Profile Abstract Base ✅ CONCLUÍDA

**Arquivo:** `profiles/models/base.py`

**Campos implementados** (`Profile(models.Model)`, `abstract = True`):

- [x] `bio` — `TextField(max_length=500, blank=True, validators=[MaxLengthValidator(500)])`
      — o `validators` explícito é necessário: ao contrário de `CharField`,
      `TextField` não adiciona `MaxLengthValidator` automaticamente a partir de
      `max_length`, então sem ele `full_clean()` não rejeitaria um `bio` acima
      do limite
- [x] `created_at` — `DateTimeField(auto_now_add=True)`
- [x] `updated_at` — `DateTimeField(auto_now=True)`

**Métodos implementados:**

- [x] `__str__` e `__repr__` — ambos retornam `"{ClassName} (profile_id=…)"` (sem PII)
- [x] `get_display_info()` — método abstrato: levanta `NotImplementedError` e força
      implementação nas subclasses concretas

**Meta:**

- [x] `abstract = True`
- [x] `verbose_name`, `verbose_name_plural`
- [x] `ordering = ["-created_at"]`

**Nota — sem `clean()`:**
`Profile` não define `clean()`. Não há invariante intrínseca ao nível do base
abstrato que precise de validação própria; a validação de `bio` é resolvida
inteiramente pelo `MaxLengthValidator` do field, e `hourly_rate`/`max_budget`
são regras dos concretos (`FreelancerProfile`/`ClientProfile`).

**Testes implementados:**

`profiles/tests/models/test_base.py` — **5 testes, todos passando**.

1. [x] `test_profile_is_abstract` — `Profile._meta.abstract is True`
2. [x] `test_valid_bio_passes_validation` — `bio` dentro do limite
3. [x] `test_exactly_500_char_bio_passes_validation` — `bio` no limite exato (500)
4. [x] `test_exceeding_500_char_bio_raises_validation_error` — `bio` acima do limite, código `max_length`
5. [x] `test_unimplemented_get_display_info_raises_not_implemented_error` — usa `UnimplementedProfile`, dummy definido em `conftest.py` (exceção documentada em `testing.md` para testar enforcement de método abstrato)

**Padrões estabelecidos:**

- Timestamps não são testados no base abstrato — cobertos em `test_freelancer_profile.py` (`test_freelancer_profile_timestamps_auto_set`), seguindo a regra do projeto de que timestamps são comportamento de model concreto
- `__str__`/`__repr__` não são testados no base abstrato — mesmo padrão de `accounts/tests/models/test_base.py` (`BaseUser`): testados apenas nos concretos (`test_freelancer_profile.py`)
- `UnimplementedProfile` (dummy que não implementa `get_display_info`) definido em `conftest.py`, distinto de um dummy funcional — usado exclusivamente para testar o enforcement do método abstrato

**Total profiles/ até aqui: 5 testes passando (5 base).**

---

### TASK 2.1.3a — profiles/ `skill.py` — Skill ✅ CONCLUÍDA

**Arquivo:** `profiles/models/skill.py`

**Campos implementados** (`Skill(models.Model)`, tabela `skills`):

- [x] `name` — `CharField(max_length=100, unique=True)`
- [x] `category` — `CharField(max_length=20, choices=Category.choices)`, com `Category(TextChoices)`: `TECHNOLOGY`, `DESIGN`, `WRITING`, `MARKETING`

**Métodos implementados:**

- [x] `__str__` → `self.name`
- [x] `__repr__` → `"{ClassName} (id=…, name=…!r, category=…!r)"` — usa `!r` para citar as strings
- [x] `clean()` — normaliza `name` com `.strip()` e levanta `ValidationError` com código `skill_name_empty` se vazio após o strip

**Meta:**

- [x] `db_table = "skills"`
- [x] `ordering = ["category", "name"]`
- [x] `verbose_name`, `verbose_name_plural`

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- Skills são geridas exclusivamente por admins. Freelancers selecionam da lista existente. Vocabulário controlado garante filtragem e matching fiáveis em `list_open_jobs(skills=...)` (Sprint 2.3)
- Exposto em `profiles/models/__init__.py` (`__all__`)
- Migration de schema gerada e aplicada (`0001_initial.py`)

---

### TASK 2.1.3b — profiles/ Testes Skill + Seed ✅ CONCLUÍDA

**Arquivo:** `profiles/tests/models/test_skill.py`

**Testes implementados:**

`profiles/tests/models/test_skill.py` — **12 testes, todos passando**.

1. [x] `test_skill_str_representation` — `__str__` retorna o nome da skill
2. [x] `test_skill_repr_representation` — `__repr__` numa instância não salva, `category` renderizado como membro do `TextChoices`
3. [x] `test_skill_repr_representation_after_reload` — `__repr__` após save + reload, `category` renderizado como string simples (comportamento distinto do teste anterior)
4. [x] `test_skill_clean_strips_whitespace` — `clean()` normaliza espaços
5. [x] `test_skill_clean_empty_name_raises_validation_error` — parametrizado com `""` e `"   "`, verifica `code="skill_name_empty"`
6. [x] `test_skill_clean_none_name_passes_validation` — `clean()` não altera e não levanta erro quando `name=None`
7. [x] `test_skill_creation_assigns_id` — criação atribui chave primária
8. [x] `test_skill_is_persisted_and_retrievable` — skill salva é recuperável com os campos corretos
9. [x] `test_skill_name_uniqueness` — `unique=True` aplicado via `full_clean()`, código `unique`
10. [x] `test_skill_name_uniqueness_enforced_at_database_level` — duplicata inserida sem `full_clean()` levanta `IntegrityError`
11. [x] `test_skill_ordering` — ordering por categoria e depois por nome é respeitado

**Seed:**

- [x] Data migration de seed criada e aplicada (`0002_seed_skills.py`) — 30 skills em 4 categorias (8 TECHNOLOGY, 8 DESIGN, 7 WRITING, 7 MARKETING)

**Padrões estabelecidos:**

- Testes sem base de dados para `clean()`, `__str__`, `__repr__` (instância não salva) — sem `@pytest.mark.django_db`
- Testes de `__repr__` usam `!r` no assert f-string em vez de aspas literais — mais robusto e consistente com o código real do modelo
- `@pytest.mark.django_db` apenas para testes que tocam a base de dados
- `bulk_create(ignore_conflicts=True)` para seeds — eficiente e idempotente
- `full_clean()` para testar `unique=True` — evita depender do `IntegrityError` da base de dados diretamente
- Fixtures de modelo ficam locais ao ficheiro enquanto usadas por apenas um ficheiro de teste

**Decisões arquiteturais** (documentadas no `ARCHITECTURE.md`):

- `bulk_create` sem `full_clean()` no seed é intencional — dados controlados, revistos antes do commit. `clean()` permanece ativo para o único caminho externo de inserção: Django Admin restrito a administradores da plataforma

**Total profiles/ até aqui: 17 testes passando (5 base + 12 skill).**

---

### TASK 2.1.4 — profiles/ `freelancer_profile.py` — FreelancerProfile ✅ CONCLUÍDA

**Arquivo:** `profiles/models/freelancer_profile.py`

**Campos implementados** (`FreelancerProfile(Profile)`, tabela `freelancer_profiles`):

- [x] Herda de `Profile` (`bio`, `created_at`, `updated_at`)
- [x] `user` — `OneToOneField(Freelancer, on_delete=PROTECT, related_name="profile")`
- [x] `hourly_rate` — `DecimalField(max_digits=8, decimal_places=2, null=True, blank=True)`
      — campo opcional. Migração `0003_freelancerprofile.py` criou-o obrigatório;
      `0005_alter_freelancerprofile_options_and_more.py` relaxou para `null=True, blank=True`
- [x] `skills` — `ManyToManyField(Skill, blank=True)`
- [x] `portfolio_url` — `URLField(blank=True)` — sem checagem extra de string vazia em `clean()`
- [x] `years_of_experience` — `PositiveIntegerField(default=0)`

**Métodos implementados:**

- [x] `clean()` — valida apenas `hourly_rate`: deve ser estritamente > 0 quando
      fornecido (código `hourly_rate_not_positive`). `portfolio_url` não é
      validado em `clean()` — o formato já é garantido pelo `URLField`, e não
      existe checagem de string vazia. Skills não validadas aqui — `ManyToManyField`
      indisponível antes do `.save()`; obrigatoriedade de pelo menos uma skill
      fica no serializer (Sprint DRF)
- [x] `get_display_info()` — retorna dict com `name`, `hourly_rate`,
      `years_of_experience`, `portfolio_url`, `bio`, `skills` (lista de nomes).
      **Não inclui `email`**
- [x] `__str__` — herdado de `Profile`, não sobrescrito
- [x] `__repr__` — sobrescrito: `profile_id=`, `user_id=`, `hourly_rate=`.
      Nenhum campo é string, então não usa `!r` (padrão `!r` é exclusivo de
      `Skill`, ver TASK 2.1.3c)

**Meta:**

- [x] `class Meta(Profile.Meta)` — herda `ordering = ["-created_at"]`
- [x] `verbose_name`, `verbose_name_plural`
- [x] `db_table = "freelancer_profiles"`

**Nota — GDPR em `get_display_info()`:**
`email` não é retornado. `user.name` é o identificador público de exibição;
`email` permanece privado, alinhado com a política de GDPR do projeto.

**Decisões arquiteturais:**

- `on_delete=PROTECT` em vez de `CASCADE` — documentado em "FreelancerProfile —
  on_delete=PROTECT on OneToOneField" (`ARCHITECTURE.md:800`)
- Sem `is_active` próprio no perfil — desativação controlada por
  `freelancer__is_active` nas queries
- `hourly_rate` validado via `clean()`, sem `CheckConstraint` — documentado em
  `docs/adr/no-check-constraint-for-positive-amount-invariants.md`
- `clean()` assume o tipo já convertido (`Decimal`) para `hourly_rate`, sem
  type guard — documentado em `docs/adr/model-clean-assumes-converted-field-types.md`
- Skills obrigatória (mínimo uma) é regra de negócio aplicada no serializer
  DRF, não no model — documentado em "FreelancerProfile — Minimum One Skill
  Enforced at Serializer Level" (`ARCHITECTURE.md:843`)

**Testes implementados:**

`profiles/tests/models/test_freelancer_profile.py` — **18 testes, todos passando**.

1. [x] `test_freelancer_profile_inherits_from_profile_class`
2. [x] `test_freelancer_profile_creation_and_saving`
3. [x] `test_freelancer_profile_default_years_of_experience`
4. [x] `test_freelancer_profile_raises_validation_error_with_non_positive_hourly_rate` — parametrizado (2 casos: `0.00`, `-10.50`)
5. [x] `test_freelancer_profile_hourly_rate_none_passes_validation`
6. [x] `test_freelancer_profile_hourly_rate_none_persists_on_save`
7. [x] `test_freelancer_profile_str_representation`
8. [x] `test_freelancer_profile_repr_representation`
9. [x] `test_freelancer_profile_get_display_info`
10. [x] `test_freelancer_profile_get_display_info_without_skills`
11. [x] `test_freelancer_profile_on_delete_protect`
12. [x] `test_add_and_remove_skills`
13. [x] `test_freelancer_profile_created_at_is_set_on_creation`
14. [x] `test_freelancer_profile_updated_at_changes_on_save`
15. [x] `test_freelancer_profile_user_uniqueness`
16. [x] `test_freelancer_profile_user_uniqueness_enforced_at_database_level`
17. [x] `test_freelancer_profile_ordering`

**Padrões estabelecidos:**

- Timestamps testados no concreto, não no base abstrato — dois testes
  separados por comportamento (`created_at` na criação, `updated_at` na
  atualização), não um único `..._timestamps_auto_set`
- Unicidade de `user` testada em dois níveis: `full_clean()` (código `unique`)
  e `IntegrityError` direto na base de dados, sem passar por `full_clean()`
- `hourly_rate=None` testado tanto na validação (`full_clean()` não levanta)
  quanto na persistência (valor sobrevive ao save/reload)

**Total profiles/ até aqui: 35 testes passando (5 base + 12 skill + 18 freelancer_profile).**

---

### TASK 2.1.5a — profiles/ `client_profile.py` — ClientProfile ✅ CONCLUÍDA

**Arquivo:** `profiles/models/client_profile.py`

**Campos implementados** (`ClientProfile(Profile)`, tabela `client_profiles`):

- [x] Herda de `Profile` (`bio`, `created_at`, `updated_at`)
- [x] `user` — `OneToOneField(Client, on_delete=PROTECT, related_name="profile")`
- [x] `company_name` — `CharField(max_length=200, blank=True)`
- [x] `max_budget` — `DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)`
- [x] `interests` — `ManyToManyField(Skill, blank=True)`
- [x] `website_url` — `URLField(blank=True)`

**Métodos implementados:**

- [x] `clean()` — valida:
  - `company_name`, se fornecido, não pode ser string vazia após `.strip()`
    (código `company_name_empty`). Se `company_name` for `""`, a checagem
    não é acionada (`if self.company_name:` é falso). **Nota:** este
    `.strip()` é validação, não normalização — a normalização real de
    `company_name` (persistir o valor já limpo) fica planejada para o
    serializer na TASK 3.x.x (ClientProfile/FreelancerProfile serializers),
    ainda por revisar
  - `max_budget`, se fornecido, deve ser estritamente maior que zero
    (código `max_budget_not_positive`)
  - Interests **não** validadas aqui — `ManyToManyField` indisponível
    antes do `.save()`
- [x] `get_display_info()` — retorna dict com `name`, `max_budget`,
      `company_name`, `website_url`, `bio`, `interests` (lista de nomes).
      **Não inclui `email`**
- [x] `__str__` — herdado de `Profile`, não sobrescrito
- [x] `__repr__` — sobrescrito: `profile_id=`, `user_id=`, `max_budget=`.
      Nenhum campo é string, então não usa `!r`

**Meta:**

- [x] `class Meta(Profile.Meta)` — herda `ordering = ["-created_at"]`
- [x] `verbose_name`, `verbose_name_plural`
- [x] `db_table = "client_profiles"`
- [x] Exportado em `profiles/models/__init__.py`

**Migração:**

- [x] `profiles/migrations/0006_clientprofile.py` — cria o modelo com todos
      os campos concretos. Aplicada: `showmigrations profiles` confirma
      `[X] 0006_clientprofile`

**Decisões arquiteturais:**

- `on_delete=PROTECT` em vez de `CASCADE` — mesma decisão do
  `FreelancerProfile`: deleção física não ocorre no sistema; PROTECT
  torna a violação explícita
- Sem `is_active` próprio no perfil — desativação controlada por
  `client__is_active` nas queries
- `max_budget` validado via `clean()`, sem `CheckConstraint` — documentado
  em `docs/adr/no-check-constraint-for-positive-amount-invariants.md`
  (aplica-se explicitamente a `ClientProfile.max_budget`)
- `clean()` assume o tipo já convertido (`Decimal`) para `max_budget`, sem
  type guard — documentado em `docs/adr/model-clean-assumes-converted-field-types.md`
  (aplica-se explicitamente a `ClientProfile.max_budget`)

---

### TASK 2.1.5b — profiles/ Testes ClientProfile

**Status:** PENDING — nenhum teste existe ainda para `ClientProfile`
(confirmado: `profiles/tests/models/` não contém `test_client_profile.py`
nem qualquer outro ficheiro relacionado).

**Plano de testes** (baseado na cobertura real de
`test_freelancer_profile.py`, adaptado aos campos reais de `ClientProfile`):

- [ ] `test_client_profile_inherits_from_profile_class`
- [ ] `test_client_profile_creation_and_saving`
- [ ] `test_client_profile_raises_validation_error_with_non_positive_max_budget` — parametrizado (`0.00`, negativo)
- [ ] `test_client_profile_max_budget_none_passes_validation`
- [ ] `test_client_profile_max_budget_none_persists_on_save`
- [ ] `test_client_profile_raises_validation_error_with_whitespace_company_name` — código `company_name_empty`
- [ ] `test_client_profile_empty_company_name_passes_validation` — `company_name=""` não aciona a validação
- [ ] `test_client_profile_str_representation`
- [ ] `test_client_profile_repr_representation`
- [ ] `test_client_profile_get_display_info`
- [ ] `test_client_profile_get_display_info_without_interests`
- [ ] `test_client_profile_on_delete_protect`
- [ ] `test_add_and_remove_interests`
- [ ] `test_client_profile_created_at_is_set_on_creation`
- [ ] `test_client_profile_updated_at_changes_on_save`
- [ ] `test_client_profile_user_uniqueness`
- [ ] `test_client_profile_user_uniqueness_enforced_at_database_level`
- [ ] `test_client_profile_ordering`

**Nota:** este plano não inclui testes para `years_of_experience`-like
defaults (não há campo equivalente em `ClientProfile`) nem para
`portfolio_url`-style empty-string checks (não existe tal validação em
`FreelancerProfile`, e `website_url` não tem validação própria em
`clean()` além do formato já garantido pelo `URLField`).

---

## 📋 STACK TRIAGE — Revisão Consolidada (FASE 1 completa + SPRINT 2.1 até TASK 2.1.5a)

> Conteúdo migrado de `ROADMAP_STACK_TRIAGE.md` (triagem de 12 June 2026,
> follow-up de 19 July 2026). Cobre apenas os itens ainda em aberto
> (🟡 verificar / 🔴 problema / ⚠️ conflito) das tasks já concluídas até
> este ponto — não é mais necessário reabrir o documento de triagem para
> elas. A partir da TASK 2.1.6, as notas de triagem em aberto aparecem
> inline em cada task, dentro do bloco **Stack Triage Notes**.

- ✅ **TASK 1.1.1** — RESOLVIDO. A tag flutuante `postgres:17` estava resolvida em cache para **17.9** (verificado via `docker-compose exec db postgres --version`), enquanto o patch mais novo do major 17 é **17.10** (postgresql.org, 14/05/2026). **Decisão:** fixar `docker-compose.yml` em `postgres:17.10` — reprodutibilidade + correções de segurança do patch. Troca de patch dentro do major 17, sem recriação de volume.
- ✅ **TASK 1.1.2** — RESOLVIDO. O container já roda **Python 3.14.6** (verificado via `docker-compose exec web python --version`), que é o patch mais novo da série 3.14 (python.org, 10/06/2026). **Decisão:** fixar a base image do `Dockerfile` em `python:3.14.6-slim` — reprodutibilidade.
- ✅ **TASK 1.1.3** — RESOLVIDO. Mesmo tratamento da TASK 1.1.1: o service `postgres` do CI (`.github/workflows/ci.yml`) usava `postgres:17` flutuante. **Decisão:** fixar em `postgres:17.10`, alinhado ao `docker-compose.yml`.
- ✅ **SPRINT 1.2 (accounts/)** — RESOLVIDO. Comportamento **intencional e correto**. No Django 6.0 o default global de `DEFAULT_AUTO_FIELD` já é `BigAutoField` (docs oficiais 6.0), e as migrations do projeto já geram `BigAutoField` (`0001_initial.py`, `0001_profiles_initioal.py`, todas com `auto_created=True`). `python manage.py check` retorna **0 issues** (nenhum `models.W042`). **Decisão:** deixar **implícito** — declarar o setting apenas repetiria o default da versão, sem ganho de correção. Nenhuma mudança de código.
- ✅ **SPRINT 2.1 (profiles/)** — RESOLVIDO (Observation — sem ação agora). Confirmado nas release notes do Django 6.0 que o scheme padrão do `forms.URLField` mudou de `http` para `https` (a equipe de segurança do Django avaliou e **não** classificou como problema de segurança). A normalização atua na **camada de form/serializer**, não no model: `portfolio_url` e `website_url` são `models.URLField` puros (sem validators customizados) e **não mudam**; os 161 testes continuam passando. **Ressalva registrada:** a afirmação de que "serializers DRF são backed por `forms.URLField`" **não é exata** — `rest_framework.serializers.URLField` é classe própria do DRF. **Ação deferida ao Sprint 3.2:** verificar **empiricamente** o comportamento de `serializers.URLField` do DRF para URLs sem scheme ao implementar a camada de serialização.

---

### TASK 2.1.6 — Migrations & Admin profiles/ (30min)

- [ ] `makemigrations profiles`
- [ ] `migrate`
- [ ] Admin com `TabularInline` (mostrar Profile inline ao User)
- [ ] Testar no Admin
- [ ] **No admin action may write `max_budget` or `hourly_rate` through
      `queryset.update()`.** Both invariants live in `ClientProfile.clean()` /
      `FreelancerProfile.clean()` alone, with no `CheckConstraint` backstop.
      `update()` bypasses `clean()`, so such an action would write a negative
      amount with no error at any layer. If the action becomes necessary, the
      ADR must be revisited and the `CheckConstraint` added **in the same change
      that introduces the write path** — not after.
      → ADR: _Positive-Amount Invariants Enforced by `clean()` Only — No
      `CheckConstraint`_

**Conceitos para estudar:** `TabularInline` vs `StackedInline`.

---

### SPRINT 2.2 — App jobs/

**Tempo:** 6h | **Complexidade:** ⭐⭐⭐

### TASK 2.2.1 — Criar app jobs/ e estrutura (30min)

- [ ] `python manage.py startapp jobs`
- [ ] Subpastas: `models/`, `services/`, `tests/`
- [ ] Registrar em `INSTALLED_APPS`

**Estrutura:**

`jobs/
├── models/
│   ├── __init__.py
│   ├── job.py
│   ├── proposal.py
│   └── status_history.py    ← NOVO
├── services/
│   ├── __init__.py
│   ├── job_service.py
│   └── proposal_service.py
├── admin.py
├── apps.py
└── tests/
    ├── __init__.py
    ├── test_models.py
    └── test_services.py`

---

### TASK 2.2.2 — Job Model (2h)

**Stack Triage Notes:**

- ⚠️ **ARCH CONFLICT** — o requisito abaixo (`client = ForeignKey(Client, on_delete=CASCADE)`) contradiz `ARCHITECTURE.md`/`conventions.md`: **use `on_delete=PROTECT`**. `CASCADE` é explicitamente rejeitado — a plataforma desativa via `is_active=False`, não deleta fisicamente. Corrigir o roadmap para `PROTECT` antes de escrever qualquer código desta task (ver `ARCHITECTURE.md` → "ForeignKey and OneToOneField — on_delete policy").

**Arquivo:** `jobs/models/job.py`

**Requisitos:**

- [ ] `client` — `ForeignKey(Client, on_delete=CASCADE, related_name='jobs')`
- [ ] `title` — `CharField(max_length=200)`
- [ ] `description` — `TextField(max_length=2000)`
- [ ] `budget` — `DecimalField(max_digits=10, decimal_places=2)`
- [ ] `deadline` — `DateField(null=True, blank=True)`
- [ ] `required_skills` — `ManyToManyField(Skill, blank=True)`
- [ ] `status` — choices: `OPEN`, `IN_PROGRESS`, `COMPLETED`, `CANCELLED`
- [ ] `created_at`, `updated_at` automáticos

**Conceitos para estudar:**

- `related_name` — como acessar `client.jobs.all()`
- Choices com `TextChoices` (forma moderna no Django 3+)
- ForeignKey vs ManyToMany

**Testes esperados:**

- [ ] `test_create_job()`
- [ ] `test_job_default_status_is_open()`
- [ ] `test_job_requires_client()`
- [ ] `test_budget_must_be_positive()`

---

### TASK 2.2.3 — Proposal Model (2h)

**Stack Triage Notes:**

- ⚠️ **ARCH CONFLICT** — `job = ForeignKey(Job, on_delete=CASCADE)` e `freelancer = ForeignKey(Freelancer, on_delete=CASCADE)` abaixo contradizem `ARCHITECTURE.md`/`conventions.md`: **ambos devem usar `on_delete=PROTECT`**. Mesmo raciocínio da TASK 2.2.2 — `CASCADE` é explicitamente rejeitado pela arquitetura. Corrigir antes de escrever qualquer código desta task.
- 🟡 `UniqueConstraint` + DRF `violation_error_code` — DRF 3.17.0 adicionou suporte a `violation_error_code` e `violation_error_message` de `UniqueConstraint` no `UniqueTogetherValidator`. Ao implementar o serializer de `Proposal` (Sprint 3.2), usar essa feature para propagar o error code customizado do model constraint para a response da API, alinhado com o padrão de error codes do projeto (baseline §3, "3.17.0 features").

**Arquivo:** `jobs/models/proposal.py`

**Requisitos:**

- [ ] `job` — `ForeignKey(Job, on_delete=CASCADE, related_name='proposals')`
- [ ] `freelancer` — `ForeignKey(Freelancer, on_delete=CASCADE, related_name='proposals')`
- [ ] `cover_letter` — `TextField(max_length=1000)`
- [ ] `proposed_price` — `DecimalField(max_digits=10, decimal_places=2)`
- [ ] `delivery_days` — `PositiveIntegerField()`
- [ ] `status` — choices: `PENDING`, `ACCEPTED`, `REJECTED`, `WITHDRAWN`
- [ ] Constraint único: 1 freelancer = 1 proposta por job

**Conceitos para estudar:**

- `UniqueConstraint` em `Meta.constraints` (forma moderna)
- Por que usar `constraints` em vez de `unique_together` (deprecated)

**Testes esperados:**

- [ ] `test_create_proposal()`
- [ ] `test_freelancer_cannot_submit_duplicate_proposal()`
- [ ] `test_proposal_default_status_is_pending()`

---

### TASK 2.2.X — SDD Tooling Decision Checkpoint 🆕 PROCESS GATE

**Objetivo:** Decidir, antes de iniciar a `TASK 2.2.4 — StatusHistory Model`,
se o projeto continua com o fluxo SDD DIY (markdown manual em `docs/specs/`)
ou adota uma ferramenta SDD reconhecida no mercado.

**Por que essa decisão acontece nessa task específica:**
StatusHistory é a primeira feature de alta complexidade do projeto
(audit trail, signals, FKs múltiplas, GDPR, queries de histórico). É o
ponto natural para avaliar se o fluxo DIY está se sustentando ou se as
limitações começaram a aparecer.

**Pré-requisito obrigatório:** nova pesquisa do estado do ecossistema SDD
no momento da decisão. As ferramentas listadas abaixo refletem o cenário
de junho de 2026 e mudam rapidamente. Decidir com base em pesquisa antiga
é um anti-padrão explícito.

**Critérios para considerar migração para tooling externo:**

- Specs em DIY estão ficando inconsistentes entre features
- Tempo significativo gasto recriando estrutura de pastas/templates
- Necessidade de demonstrar uma ferramenta SDD reconhecível no portfolio

**Restrições inegociáveis sobre a ferramenta escolhida (caso migre):**

- A ferramenta deve preservar approval gates manuais entre fases.
  Implementação totalmente autônoma por subagentes não é aceitável —
  o objetivo do projeto é aprendizado ativo, não delegação.
- A ferramenta deve permitir que o usuário leia e revise cada etapa
  (spec, plan, tasks, código) antes de avançar.
- A ferramenta deve ser reconhecida no mercado europeu/internacional
  (visibilidade em currículo e portfolio).

**Candidatas atuais (a serem re-verificadas via pesquisa antes da decisão):**

- GitHub Spec Kit — agent-agnostic, ~90k stars (junho 2026), fluxo
  /speckit.specify → /speckit.plan → /speckit.tasks → /speckit.implement.
- Superpowers — plugin nativo do Claude Code, ~50k stars (junho 2026),
  forte ênfase em TDD enforced. Atenção: usa subagentes autônomos por
  padrão — verificar se há modo controlado antes de adotar.

**Resultado esperado:**

- [ ] Pesquisa atualizada do ecossistema SDD documentada (data + fontes)
- [ ] Decisão registrada em `ARCHITECTURE.md` (manter DIY ou migrar)
- [ ] Se migrar: ferramenta escolhida instalada e configurada
- [ ] Se migrar: spec da StatusHistory escrito no novo fluxo
- [ ] Se manter DIY: justificativa documentada do que está funcionando

**Tempo estimado:** 2h (pesquisa + decisão + setup ou documentação)

---

### TASK 2.2.4 — StatusHistory Model (2h) 🆕 FEATURE DE COMPLEXIDADE

**Stack Triage Notes:**

- 🟡 Django Signals (`post_save`) para audit trail — Django 6.0 introduziu um Background Tasks framework (`django.tasks`) com decorator `@task()` e queue mechanism. Casos de uso distintos: **Signals** são síncronos, em-linha com a transação do save, corretos para audit trail atômico; **Background Tasks** são para trabalho assíncrono diferido que requer worker separado (ex: envio de email). Para `StatusHistory`, Signals continuam sendo a escolha correta — confirmar conscientemente ao iniciar esta task, pois é o trigger point para re-avaliação de SDD tooling (baseline §2, "Background Tasks framework").

**Arquivo:** `jobs/models/status_history.py`

**Por que esta feature:** demonstra auditabilidade — rastrear quem mudou o status de um Job ou Proposta, quando, e de qual status para qual. Empresas europeias que lidam com contratos e pagamentos exigem isso. Em entrevistas, esta feature é fácil de explicar e difícil de ignorar.

**Requisitos:**

- [ ] `content_type` — `ForeignKey(ContentType)` OU ForeignKey direto para Job + Proposal
- [ ] `previous_status` — `CharField()`
- [ ] `new_status` — `CharField()`
- [ ] `changed_by` — `ForeignKey(settings.AUTH_USER_MODEL)` (quem fez a mudança)
- [ ] `changed_at` — `DateTimeField(auto_now_add=True)`
- [ ] `reason` — `TextField(blank=True)` (motivo opcional)

**Opção recomendada:** ForeignKey separado para Job e Proposal é mais simples que `GenericForeignKey` e suficiente para este projeto.

**Conceitos para estudar:**

- Django Signals (`post_save`) — registrar histórico automaticamente ao salvar
- `settings.AUTH_USER_MODEL` em vez de importar direto (boa prática)
- Diferença entre `GenericForeignKey` e ForeignKey direto

**Testes esperados:**

- [ ] `test_status_history_created_on_job_status_change()`
- [ ] `test_status_history_created_on_proposal_status_change()`
- [ ] `test_status_history_records_who_changed()`
- [ ] `test_status_history_records_previous_status()`

**Entrega:** toda transição de status de Job e Proposal é auditada automaticamente.

---

### SPRINT 2.3 — Services Layer

**Tempo:** 6h | **Complexidade:** ⭐⭐⭐⭐

### TASK 2.3.1 — JobService (3h)

> **Nota arquitectural:** o parâmetro `skills` filtra por instâncias do modelo
> `Skill` (vocabulary controlado), não por strings livres. A query usará
> `ManyToManyField` entre `Job` e `Skill` — a ser definida quando o modelo
> `Job` for criado na Sprint 2.2.

**Arquivo:** `jobs/services/job_service.py`

**Requisitos:**

- [ ] `create_job(client: Client, data: dict) -> Job`
  - Validar que `client` é instância de `Client` (não Freelancer)
  - Criar Job com status `OPEN`
  - Registrar no StatusHistory
- [ ] `accept_proposal(client: Client, proposal_id: int) -> Proposal`
  - Validar que o client é dono do job
  - Mudar proposta para `ACCEPTED`
  - Mudar todas as outras propostas do job para `REJECTED`
  - Mudar job para `IN_PROGRESS`
  - Tudo em `@transaction.atomic`
- [ ] `list_open_jobs(skills: list = None, max_budget: Decimal = None) -> QuerySet`

**Conceitos para estudar:**

- Service Layer — por que separar lógica dos models
- `@transaction.atomic` — garantir consistência em operações múltiplas
- QuerySet filtering, `Q` objects para filtros complexos

**Testes esperados:**

- [ ] `test_create_job_as_client_succeeds()`
- [ ] `test_create_job_as_freelancer_raises_permission_error()`
- [ ] `test_accept_proposal_rejects_all_others()`
- [ ] `test_accept_proposal_changes_job_to_in_progress()`
- [ ] `test_accept_proposal_is_atomic()`

---

### TASK 2.3.2 — ProposalService (3h)

**Arquivo:** `jobs/services/proposal_service.py`

**Requisitos:**

- [ ] `submit_proposal(freelancer: Freelancer, job_id: int, data: dict) -> Proposal`
  - Validar que job está `OPEN`
  - Validar que freelancer não tem proposta existente neste job
  - Criar proposta com status `PENDING`
- [ ] `withdraw_proposal(freelancer: Freelancer, proposal_id: int) -> Proposal`
  - Validar que freelancer é dono da proposta
  - Mudar para `WITHDRAWN`
  - Só permitir se status atual for `PENDING`

**Testes esperados:**

- [ ] `test_submit_proposal_as_freelancer_succeeds()`
- [ ] `test_submit_proposal_to_closed_job_raises_error()`
- [ ] `test_submit_duplicate_proposal_raises_error()`
- [ ] `test_withdraw_pending_proposal_succeeds()`
- [ ] `test_withdraw_accepted_proposal_raises_error()`

---

### SPRINT 2.4 — Admin Avançado

**Tempo:** 2h | **Complexidade:** ⭐⭐

### TASK 2.4.1 — Admin jobs/ (2h)

**Arquivo:** `jobs/admin.py`

**Requisitos:**

- [ ] Job admin com `list_display`: title, client, status, budget, created_at
- [ ] Filtros: `list_filter` por status e deadline
- [ ] `search_fields` por title e client email
- [ ] Proposal como `TabularInline` dentro de Job admin
- [ ] StatusHistory como `TabularInline` readonly (auditoria)
- [ ] Action customizada: `mark_as_cancelled` para bulk action

**Conceitos para estudar:**

- `list_display`, `list_filter`, `search_fields`
- `readonly_fields` para dados de auditoria
- `admin.action` para bulk actions

---

## ✅ CHECKPOINT FASE 2

- [ ] 30+ testes passando
- [ ] 3 apps funcionando: `accounts/`, `profiles/`, `jobs/`
- [ ] Services implementados com transações atômicas
- [ ] StatusHistory auditando todas as transições
- [ ] Admin avançado com inlines e filtros
- [ ] CI ainda verde após todos os commits
- [ ] Commit: `"feat: implement profiles, jobs, proposals and status audit trail"`

---

## 🔷 FASE 3: API REST

### Semanas 5-7 (30h)

---

### SPRINT 3.1 — DRF Setup

**Tempo:** 4h | **Complexidade:** ⭐⭐

### TASK 3.1.1 — Instalação e Configuração (2h)

**Stack Triage Notes:**

- 🟡 `djangorestframework` — versão a pinnar. A primeira versão com suporte oficial ao Django 6.0 + Python 3.14 é a **3.17.0** (18 Mar 2026); versão atual: **3.17.1** (24 Mar 2026). Pin obrigatório: `djangorestframework==3.17.1`. Versões anteriores (toda a série 3.16.x) não suportam oficialmente Django 6.0. Não usar "latest" nem range aberto (baseline §3).
- 🔴 **[MAINTENANCE-RISK]** `djangorestframework-simplejwt` — última versão: **5.5.1** (21 Jul 2025), **zero releases** desde Django 6.0 (3 Dez 2025) e Python 3.14 (7 Out 2025). Compatibilidade com Django 6.0 + Python 3.14 + DRF 3.17 **não confirmada oficialmente** pelo maintainer. Pesquisa aprofundada obrigatória antes de instalar (baseline §4).
- 🔴 **[MAINTENANCE-RISK]** `drf-spectacular` — última versão: **0.29.0** (1 Nov 2025), lançada **antes** do Django 6.0 (3 Dez 2025). Compatibilidade com Django 6.0 não declarada no changelog nem no README. Agravante: política sub-1.0 — "every new version may potentially break you." Pesquisa aprofundada obrigatória antes de instalar (baseline §7).

- [ ] Instalar: `djangorestframework`, `djangorestframework-simplejwt`, `drf-spectacular`
- [ ] Configurar `REST_FRAMEWORK` em settings:
  - `DEFAULT_AUTHENTICATION_CLASSES`: JWT
  - `DEFAULT_PERMISSION_CLASSES`: `IsAuthenticated`
  - `DEFAULT_PAGINATION_CLASS`: `PageNumberPagination`
  - `PAGE_SIZE`: 20
- [ ] Configurar `SPECTACULAR_SETTINGS` para Swagger

**Conceitos para estudar:**

- DRF — o que é e por que usar em vez de views Django puras
- JWT — como funciona (access token + refresh token)
- Swagger/OpenAPI — documentação automática de API

### TASK 3.1.2 — JWT Endpoints (2h)

**Stack Triage Notes:**

- 🔴 **[MAINTENANCE-RISK]** `POST /api/auth/token/` e demais endpoints JWT dependem diretamente de `simplejwt` (ver risco na TASK 3.1.1). Todos os endpoints JWT herdam o risco de incompatibilidade não verificada com o stack atual (baseline §4).

- [ ] Endpoint de registro: `POST /api/auth/register/`
- [ ] Endpoint de login: `POST /api/auth/token/` (retorna access + refresh)
- [ ] Endpoint de refresh: `POST /api/auth/token/refresh/`
- [ ] Endpoint de logout (blacklist do refresh token)

**Testes esperados:**

- [ ] `test_register_new_client()`
- [ ] `test_register_new_freelancer()`
- [ ] `test_login_returns_tokens()`
- [ ] `test_access_protected_endpoint_without_token_returns_401()`
- [ ] `test_refresh_token_returns_new_access_token()`

---

### SPRINT 3.2 — Serializers

**Tempo:** 6h | **Complexidade:** ⭐⭐⭐

### TASK 3.2.X — Relocate input normalization to the serializer layer ⏳ DEFERRED (DRF)

**Depends on:** TASK 3.2.1 — User Serializers. Do this in the _same_ change that
introduces `accounts/serializers.py`, so the normalization lands in the serializer
instead of disappearing.

**Context:** Normalization (whitespace trimming, formatting) is owned by the
serializer layer — not by validators or the manager. Today the `.strip()` calls
sit in the wrong place. Decision, reasoning and trade-off are already recorded in
`ARCHITECTURE.md` → "User Input Normalization — Owned by the Serializer Layer".

**Deliverables:**

- [ ] Remove the internal `.strip()` from `validate_email`
      (`accounts/validators/user_validators.py`); move trimming to the
      registration serializer.
- [ ] Remove the internal `.strip()` from `validate_user_name` (same file);
      move trimming to the registration serializer.
- [ ] Remove `name.strip()` from `BaseUserManager.create_user`
      (`accounts/models/base.py`). Per ARCHITECTURE.md, only the `.strip()`
      calls are relocated — `normalize_email` is NOT slated for removal; it
      stays as the manager's email normalization for non-API paths
      (shell, `createsuperuser`, scripts, Admin).
- [ ] Revisit `test_validate_email_invalid_empty_stripped_whitespace` and
      `test_validate_user_name_with_error_stripped_whitespace`: whitespace-only
      input behaviour may change depending on what the serializer does before
      calling the validator (input may arrive already stripped to `""`, or be
      rejected upstream).

**Not in scope:** `validate_strong_password` — passwords are never normalized; it
already rejects all whitespace (`password_contains_whitespace`). Never add
stripping to it.

---

## TASK 3.x.x — ClientProfile / FreelancerProfile serializers: enforce clean() invariants

DRF's `ModelSerializer` does **not** call `full_clean()`. Verified on
django 6.0.6 + DRF 3.17.1: a `ModelSerializer` over a model whose `clean()`
rejects `max_budget=-5` returns `is_valid() == True` for that input.

- [ ] `ClientProfileSerializer.validate()` calls `full_clean(validate_unique=False)`
      on the instance so `max_budget_not_positive` and `company_name_empty` run in
      the API.
- [ ] Same for `FreelancerProfileSerializer` (`hourly_rate_not_positive`).
- [ ] Confirm the error `code` survives the conversion — DRF catches Django's
      `ValidationError` and re-raises it as its own, preserving the code
      (verified: `-5` → `code='max_budget_not_positive'`).
- [ ] Relocate normalization here: `company_name.strip()`, `bio`, and the strips
      still living in `validate_email` / `validate_user_name` / `create_user`
      (`ARCHITECTURE.md` → _User Input Normalization_).
- [ ] Close the admin-layer gap recorded in
      `docs/tech_debt/002-whitespace-only-company-name-accepted-in-admin.md`: the
      form's `strip=True` reduces a whitespace-only `company_name` to `""`
      before `clean()` runs, so `company_name_empty` never fires in the admin
      (FR-016, FR-020 of `001-profiles-admin-panel`). Deferred to here rather
      than patched in the admin form, to avoid duplicating the rule in a layer
      this task replaces.
- [ ] **Set `trim_whitespace` explicitly on every serializer `CharField`.** DRF
      defaults it to `True`, which reproduces the gap above at the API layer —
      whitespace-only input arrives at `clean()` already reduced to `""`, and
      the invariant never fires. Not yet verified against a pinned version;
      DRF is not installed.
- [ ] Keep the `company_name` branch in `ClientProfile.clean()` — it is the
      backstop for shell, scripts and data migrations, and it is what
      `full_clean()` invokes from the serializer.
- [ ] Pin the exact DRF version in `conventions.md` on install.

---

### TASK 3.2.1 — User Serializers (2h)

**Stack Triage Notes:**

- 🟡 `UniqueConstraint` → `violation_error_code` no serializer de `Proposal` — DRF 3.17.0 adicionou suporte a `violation_error_code` e `violation_error_message` de `UniqueConstraint` no `UniqueTogetherValidator`. Ao implementar o serializer de `Proposal` (nesta Sprint 3.2), usar essa feature para propagar o error code do constraint diretamente para a API response, alinhado com a política de error codes do projeto — assertions nos códigos, nunca nas mensagens (baseline §3, "3.17.0 features").

**Arquivos:** `accounts/serializers.py`

- [ ] `ClientRegistrationSerializer` — campos de registro do Client
- [ ] `FreelancerRegistrationSerializer` — campos de registro do Freelancer
- [ ] `UserSerializer` — read-only para retornar dados do usuário autenticado
- [ ] Password confirmação + validação de força

**Conceitos para estudar:**

- `write_only=True` para senha
- `validate_password()` customizado
- `create()` override no serializer

### TASK 3.2.2 — Profile Serializers (2h)

**Stack Triage Notes:**

- 🟡 `UniqueConstraint` → `violation_error_code` no serializer de `Proposal` — DRF 3.17.0 adicionou suporte a `violation_error_code` e `violation_error_message` de `UniqueConstraint` no `UniqueTogetherValidator`. Ao implementar o serializer de `Proposal` (TASK 3.2.3, nesta mesma Sprint 3.2), usar essa feature para propagar o error code do constraint diretamente para a API response, alinhado com a política de error codes do projeto — assertions nos códigos, nunca nas mensagens (baseline §3, "3.17.0 features").

**Arquivos:** `profiles/serializers.py`

- [ ] `SkillSerializer`
- [ ] `FreelancerProfileSerializer` — inclui skills aninhadas
- [ ] `ClientProfileSerializer`
- [ ] `SerializerMethodField` para campos calculados (ex: número de jobs completados)

**Conceitos para estudar:**

- Nested serializers (serializer dentro de serializer)
- `read_only_fields`
- `SerializerMethodField`

### TASK 3.2.3 — Job/Proposal Serializers (2h)

**Stack Triage Notes:**

- 🟡 `UniqueConstraint` → `violation_error_code` no serializer de `Proposal` — DRF 3.17.0 adicionou suporte a `violation_error_code` e `violation_error_message` de `UniqueConstraint` no `UniqueTogetherValidator`. Usar essa feature para propagar o error code do constraint (1 freelancer = 1 proposta por job, definido na TASK 2.2.3) diretamente para a API response, alinhado com a política de error codes do projeto — assertions nos códigos, nunca nas mensagens (baseline §3, "3.17.0 features").

**Arquivos:** `jobs/serializers.py`

- [ ] `JobSerializer` — inclui client info e required_skills
- [ ] `JobCreateSerializer` — para criação (campos diferentes do retorno)
- [ ] `ProposalSerializer`
- [ ] `StatusHistorySerializer` — read-only, para auditoria

**Conceitos para estudar:**

- Serializers diferentes para leitura e escrita (boa prática)
- `depth` vs nested serializer explícito

---

### SPRINT 3.3 — ViewSets e Permissions

**Tempo:** 8h | **Complexidade:** ⭐⭐⭐⭐

### TASK 3.3.1 — Custom Permissions (1h)

**Arquivo:** `core/permissions.py` (criar app `core/` para código compartilhado)

- [ ] `IsClient` — usuário autenticado é instância de Client
- [ ] `IsFreelancer` — usuário autenticado é instância de Freelancer
- [ ] `IsOwner` — usuário é dono do objeto

**Conceitos para estudar:**

- `BasePermission` do DRF
- `has_permission()` vs `has_object_permission()`

### TASK 3.3.2 — User ViewSets (2h)

- [ ] `POST /api/auth/register/client/` — registro de client
- [ ] `POST /api/auth/register/freelancer/` — registro de freelancer
- [ ] `GET /api/auth/me/` — dados do usuário autenticado
- [ ] `PATCH /api/profiles/me/` — atualizar próprio perfil

### TASK 3.3.3 — Job ViewSets (3h)

- [ ] `GET /api/jobs/` — listar jobs abertos (público)
- [ ] `GET /api/jobs/{id}/` — detalhe do job (público)
- [ ] `POST /api/jobs/` — criar job (só Client)
- [ ] `PATCH /api/jobs/{id}/` — editar job (só Client dono)
- [ ] `GET /api/jobs/{id}/proposals/` — listar propostas do job (só Client dono)
- [ ] Filtros: `?skill=python`, `?max_budget=5000`, `?status=open`

### TASK 3.3.4 — Proposal ViewSets (2h)

- [ ] `POST /api/jobs/{id}/proposals/` — submeter proposta (só Freelancer)
- [ ] `PATCH /api/proposals/{id}/accept/` — aceitar proposta (só Client dono do job)
- [ ] `PATCH /api/proposals/{id}/withdraw/` — retirar proposta (só Freelancer dono)
- [ ] `GET /api/proposals/my/` — minhas propostas (Freelancer)

---

### SPRINT 3.4 — GDPR Compliance (Logging de Acesso)

**Tempo:** 4h | **Complexidade:** ⭐⭐⭐ 🆕 DIFERENCIAL EUROPEU

**Por que esta sprint:** em entrevistas para empresas suíças, alemãs ou holandesas, mencionar GDPR compliance ativo é um diferencial real e imediato. Não é só "respeito à privacidade" — é código concreto que demonstra consciência profissional.

### TASK 3.4.1 — Estrutura de Logging (1h)

**Stack Triage Notes:**

- 🟡 `python-json-logger` — não coberto pelo baseline pesquisado. Pesquisar compatibilidade com Python 3.14 ao iniciar esta task, em particular o impacto do PEP 649 (deferred annotation evaluation) em bibliotecas que introspectam annotations.

- [ ] Configurar logging Django com formato JSON estruturado (usar `python-json-logger`)
- [ ] Logger separado para eventos de dados pessoais: `skillbridge.data_access`
- [ ] Logger separado para eventos de segurança: `skillbridge.security`
- [ ] Logs em arquivo em dev, stdout em produção (para Railway/Render capturar)

**Conceitos para estudar:**

- Logging hierárquico do Python
- Formato JSON para logs (parseável por ferramentas como Datadog, Papertrail)
- `python-json-logger` library

### TASK 3.4.2 — Data Access Middleware (2h)

**Arquivo:** `core/middleware/gdpr_logging.py`

- [ ] Middleware que intercepta requests a endpoints com dados pessoais
- [ ] Registra: `who` (user_id), `what` (endpoint + método), `when` (timestamp), `ip`
- [ ] Nunca loga o conteúdo dos dados (só o acesso)
- [ ] Endpoints monitorados: `/api/profiles/`, `/api/auth/me/`

**Conceitos para estudar:**

- Django Middleware — `__call__`, `process_request`, `process_response`
- O que o GDPR diz sobre Data Access Logs (Article 30)
- Por que logar acesso e não conteúdo

### TASK 3.4.3 — Security Events Logging (1h)

- [ ] Log de login bem-sucedido
- [ ] Log de tentativa de login com falha
- [ ] Log de acesso negado (403)
- [ ] Usando Django Signals para auth events

**Testes esperados:**

- [ ] `test_profile_access_is_logged()`
- [ ] `test_failed_login_is_logged()`
- [ ] `test_log_does_not_contain_sensitive_data()`

---

### SPRINT 3.5 — Testes de API

**Tempo:** 6h | **Complexidade:** ⭐⭐⭐

### TASK 3.5.1 — Factory Boy Setup (1h)

**Stack Triage Notes:**

- 🔴 **[MAINTENANCE-RISK]** `factory-boy` — última versão released: **3.3.3** (3 Feb 2025). **Zero releases** desde Django 6.0 (3 Dez 2025) ou Python 3.14 (7 Out 2025). O changelog do repositório mostra `3.3.4 (unreleased)` adicionando apenas Django 5.2 — Django 6.0 e Python 3.14 não têm cobertura em **nenhuma versão released**. Pesquisa aprofundada obrigatória antes de instalar (baseline §9).

- [ ] Instalar `factory-boy`
- [ ] `ClientFactory`, `FreelancerFactory`
- [ ] `JobFactory`, `ProposalFactory`
- [ ] `SkillFactory`

**Conceitos para estudar:**

- Factory Boy vs fixtures manuais — por que factories são melhores em escala
- `SubFactory` para relacionamentos
- `LazyAttribute` para dados dinâmicos

### TASK 3.5.2 — Testes de Autenticação (2h)

**Stack Triage Notes:**

- 🔴 **[MAINTENANCE-RISK]** Testes de JWT (token endpoints) — dependência indireta de `simplejwt`. Se `simplejwt` tiver incompatibilidade com o stack, os testes de autenticação herdam o problema (baseline §4).

- [ ] `test_register_client_returns_201()`
- [ ] `test_register_with_weak_password_returns_400()`
- [ ] `test_login_returns_access_and_refresh_tokens()`
- [ ] `test_expired_token_returns_401()`
- [ ] `test_refresh_returns_new_access_token()`

### TASK 3.5.3 — Testes de Permissions (3h)

**Stack Triage Notes:**

- 🔴 **[MAINTENANCE-RISK]** Testes de JWT (token endpoints) — dependência indireta de `simplejwt`. Se `simplejwt` tiver incompatibilidade com o stack, os testes de autenticação/permissions herdam o problema (baseline §4).

- [ ] `test_freelancer_cannot_create_job()`
- [ ] `test_client_cannot_submit_proposal()`
- [ ] `test_client_cannot_accept_proposal_of_another_clients_job()`
- [ ] `test_unauthenticated_user_cannot_access_protected_endpoints()`
- [ ] `test_freelancer_can_only_withdraw_own_proposal()`

---

### SPRINT 3.6 — Swagger Documentation

**Tempo:** 2h | **Complexidade:** ⭐⭐

### TASK 3.6.1 — drf-spectacular Setup (2h)

**Stack Triage Notes:**

- 🔴 **[MAINTENANCE-RISK]** `drf-spectacular==0.29.0` — lançado em 1 Nov 2025, **anterior** ao Django 6.0 (3 Dez 2025). Nenhuma declaração de suporte ao Django 6.0 no changelog ou README upstream. Agravante adicional: política sub-1.0 explícita — "every new version may potentially break you" — o projeto recomenda pinning e diff de schema em cada update. Pesquisa aprofundada obrigatória antes de instalar (baseline §7).

- [ ] Schema gerado automaticamente
- [ ] Customizar descrições dos endpoints mais importantes
- [ ] Swagger UI acessível em `/api/docs/`
- [ ] ReDoc acessível em `/api/redoc/`
- [ ] Exportar schema para arquivo `openapi.yaml` (commitar no repositório)

**Entrega:** link do Swagger vai no README.

---

## ✅ CHECKPOINT FASE 3

- [ ] 60+ testes passando
- [ ] Coverage >70%
- [ ] JWT authentication funcionando
- [ ] Todos os endpoints documentados no Swagger
- [ ] GDPR logging implementado e testado
- [ ] Permissions testadas para todos os casos
- [ ] CI ainda verde
- [ ] Commit: `"feat: REST API with JWT auth, permissions, and GDPR logging"`

---

## 🔷 FASE 4: FRONTEND (FUNCIONAL)

### Semanas 8-9 (15h) — foco reduzido, back-end é o diferencial

---

### SPRINT 4.1 — Templates Funcionais

**Tempo:** 10h | **Complexidade:** ⭐⭐

**Objetivo desta fase:** mostrar que a API funciona de ponta a ponta em um fluxo real. Não é para impressionar com design — é para o video demo ter algo navegável.

### TASK 4.1.1 — Base e Autenticação (3h)

**Stack Triage Notes:**

- 🟡 Bootstrap 5 via CDN — não coberto pelo baseline pesquisado. Verificar versão atual e integridade de CDN ao iniciar esta task.

- [ ] `base.html` com Bootstrap 5 (CDN — sem build step)
- [ ] Navbar com login/logout
- [ ] Página de login
- [ ] Página de registro (escolher Client ou Freelancer)
- [ ] Redirect após login baseado no tipo de usuário

### TASK 4.1.2 — Job Listings (3h)

**Stack Triage Notes:**

- 🟡 Template Partials (Django 6.0 built-in) — Django 6.0 introduziu as tags `{% partialdef %}` e `{% partial %}` nativas, que substituem o pacote third-party `django-template-partials`. O roadmap não planeja instalar esse pacote, mas vale avaliar o uso das partials nativas para componentes reutilizáveis (navbar, cards, pagination). Não é blocking, mas evita uma dependência desnecessária (baseline §2, "Template Partials").

- [ ] Listar jobs abertos com paginação
- [ ] Filtros: skill, budget máximo
- [ ] Detalhe do job com lista de propostas (se Client)
- [ ] Botão "Submit Proposal" (se Freelancer)

### TASK 4.1.3 — Proposal Flow (4h)

**Stack Triage Notes:**

- 🟡 Template Partials (Django 6.0 built-in) — Django 6.0 introduziu as tags `{% partialdef %}` e `{% partial %}` nativas, que substituem o pacote third-party `django-template-partials`. O roadmap não planeja instalar esse pacote, mas vale avaliar o uso das partials nativas para componentes reutilizáveis (navbar, cards, pagination). Não é blocking, mas evita uma dependência desnecessária (baseline §2, "Template Partials").

- [ ] Formulário de proposta (Freelancer)
- [ ] Dashboard Client: ver propostas recebidas, aceitar/rejeitar
- [ ] Dashboard Freelancer: ver próprias propostas + status
- [ ] Mensagens de sucesso/erro com Django messages framework

**Conceitos para estudar:**

- `ModelForm` para forms baseados em models
- `LoginRequiredMixin` para views protegidas
- Django messages framework

---

### SPRINT 4.2 — Upload e Static Files

**Tempo:** 5h | **Complexidade:** ⭐⭐

### TASK 4.2.1 — Static Files (2h)

**Stack Triage Notes:**

- 🟡 `whitenoise` para servir static em produção — não coberto pelo baseline pesquisado. Pesquisar compatibilidade com Django 6.0 + Python 3.14 ao iniciar esta task. Escolha comum para Railway/Render, mas precisa de confirmação.

- [ ] Configurar `STATIC_ROOT` e `MEDIA_ROOT`
- [ ] `whitenoise` para servir static em produção
- [ ] `collectstatic` funcionando

### TASK 4.2.2 — Upload de Foto de Perfil (3h)

- [ ] Campo `avatar` no Profile
- [ ] Upload funcional no formulário de perfil
- [ ] Validação: tamanho máximo, tipos aceitos (jpg, png)
- [ ] Placeholder quando sem foto

---

## ✅ CHECKPOINT FASE 4

- [ ] Fluxo completo navegável: cadastro → criar job → submeter proposta → aceitar
- [ ] Upload de foto de perfil funcionando
- [ ] Frontend responsivo básico
- [ ] Commit: `"feat: add frontend templates with Bootstrap 5"`

---

## 🔷 FASE 5: DEPLOY & PORTFÓLIO

### Semanas 10-12 (25h)

---

### SPRINT 5.1 — Preparação para Produção

**Tempo:** 8h | **Complexidade:** ⭐⭐⭐

### TASK 5.1.1 — Settings por Ambiente (2h)

**Stack Triage Notes:**

- 🟡 `django-environ` — não coberto pelo baseline pesquisado. Pesquisar compatibilidade com Django 6.0 ao iniciar esta task.

**Estrutura:**

`skillbridge/
└── settings/
    ├── __init__.py
    ├── base.py          ← configurações comuns
    ├── development.py   ← DEBUG=True, SQLite opcional para dev rápido
    └── production.py    ← DEBUG=False, variáveis de ambiente obrigatórias`

- [ ] `django-environ` para variáveis de ambiente
- [ ] `ALLOWED_HOSTS` correto em produção
- [ ] `SECRET_KEY` obrigatoriamente via env var em produção
- [ ] `CORS_ALLOWED_ORIGINS` configurado

### TASK 5.1.2 — Security Checklist (3h)

**Stack Triage Notes:**

- 🔴 **[OVERLAP]** Content Security Policy via `django-csp` (third-party) — Django 6.0 introduziu `ContentSecurityPolicyMiddleware` nativo com settings `SECURE_CSP` e `SECURE_CSP_REPORT_ONLY`, **substituindo** a necessidade do pacote `django-csp`. O roadmap não cita `django-csp` explicitamente, mas a security checklist tipicamente o inclui — usar o built-in do Django 6.0 em vez de instalar o pacote third-party (baseline §2, "Content Security Policy built-in. Replaces the need for the django-csp third-party package.").
- 🟡 `django-axes` para brute force protection — não coberto pelo baseline pesquisado. Pesquisar compatibilidade com Django 6.0 ao iniciar esta task.
- 🟡 `django-ratelimit` para rate limiting em endpoints de autenticação — não coberto pelo baseline pesquisado. Pesquisar compatibilidade com Django 6.0 ao iniciar esta task.

- [ ] Rodar `python manage.py check --deploy` e resolver TODOS os avisos
- [ ] `SECURE_HSTS_SECONDS`, `SECURE_SSL_REDIRECT`
- [ ] `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`
- [ ] Rate limiting nos endpoints de autenticação (evitar brute force)
- [ ] `django-axes` ou similar para bloquear tentativas de login repetidas

**Conceitos para estudar:**

- Django deployment checklist (documentação oficial)
- OWASP Top 10 — conhecer os principais, saber quais o Django mitiga
- Rate limiting com `django-ratelimit`

### TASK 5.1.3 — Testes em Modo Produção (3h)

- [ ] Rodar testes com `settings/production.py` localmente
- [ ] Verificar `collectstatic` sem erros
- [ ] Testar Docker em modo produção: `DEBUG=False`

---

### SPRINT 5.2 — Deploy Railway ou Render

**Tempo:** 8h | **Complexidade:** ⭐⭐⭐

### TASK 5.2.1 — Preparar Deploy (3h)

**Stack Triage Notes:**

- 🟡 `gunicorn` como WSGI server — não coberto pelo baseline pesquisado. Pesquisar compatibilidade com Django 6.0 + Python 3.14 ao iniciar esta task. É a escolha padrão para Railway/Render, mas requer confirmação de versão.

- [ ] `Procfile`: `web: gunicorn skillbridge.wsgi`
- [ ] `runtime.txt`: `python-3.14.x`
- [ ] `requirements.txt` atualizado e limpo
- [ ] Variáveis de ambiente configuradas no painel do Railway/Render

### TASK 5.2.2 — Deploy Inicial (3h)

- [ ] PostgreSQL provisionado no Railway/Render
- [ ] Primeiro deploy manual funcionando
- [ ] Migrations rodando em produção
- [ ] Superuser criado em produção
- [ ] Swagger acessível em produção

### TASK 5.2.3 — CD no GitHub Actions (2h)

Expandir o workflow de CI criado na Fase 1 para incluir deploy automático.

- [ ] Job `deploy` no workflow, roda apenas em push na `main`
- [ ] Deploy só acontece se todos os testes passarem
- [ ] Notificação de sucesso/falha no GitHub

**Estrutura do workflow final:**

yaml

`jobs:
  test:      ← roda em todo push
    ...
  deploy:    ← roda só em push na main, depende de test
    needs: test
    ...`

---

### SPRINT 5.3 — Documentação Final

**Tempo:** 5h | **Complexidade:** ⭐⭐

### TASK 5.3.1 — README Profissional Final (3h)

O README é o cartão de visita. Um recrutador europeu vai abrir isso antes de qualquer entrevista.

**Estrutura obrigatória (em inglês):**

markdown

`# SkillBridge
[badge CI] [badge coverage] [badge Python version]

Brief description (2-3 lines)

## Live Demo

[link deploy] | [link Swagger]

## Architecture Overview

- Why Abstract Base Classes (not Multi-Table Inheritance)
- Service Layer pattern
- GDPR compliance approach
- Status audit trail

## Tech Stack

...

## Running Locally

# with Docker (recommended)

docker-compose up

## Running Tests

docker-compose exec web pytest --cov

## API Documentation

[link Swagger em produção]

## Key Technical Decisions

[decisões documentadas com raciocínio]`

### TASK 5.3.2 — Code Quality Final (2h)

**Stack Triage Notes:**

- 🟡 `flake8` ou `ruff` — não coberto pelo baseline pesquisado. Pesquisar compatibilidade com Python 3.14 ao iniciar esta task, em particular o impacto do **PEP 649** (deferred annotation evaluation) em linters que analisam type hints. `ruff` costuma ter suporte mais rápido a novas features do Python (baseline §1, "PEP 649 — deferred annotation evaluation").

- [ ] Todas as funções/classes com docstrings (Google style) em inglês
- [ ] Type hints em todo código novo
- [ ] Remover TODOs e comentários de debug
- [ ] Rodar `flake8` ou `ruff` e corrigir avisos

---

### SPRINT 5.4 — Apresentação Portfólio

**Tempo:** 4h | **Complexidade:** ⭐

### TASK 5.4.1 — Demo Video (3h)

**Ferramenta:** Loom (gratuito) **Duração:** máximo 4 minutos **Idioma:** inglês

**Roteiro sugerido:**

1. (30s) "SkillBridge is a freelancer marketplace I built to demonstrate..."
2. (60s) Arquitetura — mostrar estrutura de pastas, explicar Service Layer
3. (60s) Feature técnica de destaque — StatusHistory ou GDPR logging (escolher um)
4. (60s) Demo ao vivo — fluxo: criar job → submeter proposta → aceitar
5. (30s) Swagger — mostrar que a API está documentada

### TASK 5.4.2 — LinkedIn + Portfolio (1h)

- [ ] Post no LinkedIn com link GitHub + live demo + Swagger
- [ ] Adicionar no portfolio pessoal com case study curto (problema → solução → resultado)

---

## ✅ CHECKPOINT FINAL

- [ ] 80+ testes passando
- [ ] Coverage >80%
- [ ] `python manage.py check --deploy` sem erros
- [ ] Projeto no ar (Railway ou Render)
- [ ] README profissional em inglês com badges
- [ ] Swagger acessível em produção
- [ ] Video demo no Loom (máximo 4 min, em inglês)
- [ ] LinkedIn post publicado
- [ ] Commit: `"chore: final polish for portfolio presentation"`

---

# 📊 MÉTRICAS DE SUCESSO

### Técnicas

- [ ] 80+ testes automatizados com docstrings
- [ ] Coverage >80% (medido com `pytest-cov`)
- [ ] 0 erros no `python manage.py check --deploy`
- [ ] API REST completa com Swagger
- [ ] Deploy funcionando e estável
- [ ] Docker funcionando (local e produção)
- [ ] CI/CD verde desde a Fase 1

### Portfólio

- [ ] README em inglês com badges e instruções claras
- [ ] Video demo em inglês (≤4 minutos)
- [ ] Código 100% em inglês (variáveis, comentários, docstrings, commits)
- [ ] Decisões arquiteturais documentadas

### Conceitos Demonstráveis em Entrevista

- [ ] Django ORM: herança, relacionamentos, signals
- [ ] REST API: DRF, serializers, viewsets, permissions
- [ ] Autenticação: JWT, access/refresh tokens
- [ ] Testes: pytest-django, factory-boy, APIClient, coverage
- [ ] GDPR: o que é, por que importa, como implementei
- [ ] Docker: containerização, docker-compose
- [ ] CI/CD: GitHub Actions, deploy automático
- [ ] Service Layer: por que separar lógica dos models
- [ ] Audit trail: StatusHistory, por que auditabilidade importa

---

# 🎯 RESUMO EXECUTIVO

**Tempo total:** ~120 horas (12 semanas @ 10h/semana) **Python:** 3.14 **Stack:** Django 6.0.3 + DRF + PostgreSQL + Docker + GitHub Actions

### Entregas por semana

| Semana | Entrega                                      |
| ------ | -------------------------------------------- |
| 2      | Docker + CI + accounts/ completo             |
| 4      | profiles/ + jobs/ + services + StatusHistory |
| 7      | API REST + JWT + GDPR logging + Swagger      |
| 9      | Frontend funcional                           |
| 12     | Deploy + README + video demo                 |

### Diferenciais para mercado europeu

- ✅ GDPR compliance com código concreto (não só mencionado)
- ✅ Audit trail de status (StatusHistory)
- ✅ Docker desde o início
- ✅ CI/CD desde o início
- ✅ Arquitetura com decisões documentadas
- ✅ 80+ testes com coverage
- ✅ Swagger docs em produção
- ✅ Código 100% em inglês

---

# 📝 FORMATO PARA NOVAS CONVERSAS

Ao iniciar uma nova conversa para trabalhar em uma task específica, use este template:

`## CONTEXTO
Projeto: SkillBridge — plataforma freelancer/cliente para portfólio mercado europeu
Stack: Python 3.14, Django 6.0.3, PostgreSQL, DRF, Docker, pytest-django
Repositório: [link do seu GitHub]
Roadmap: [colar o conteúdo deste arquivo]

## STATUS ATUAL

- [x] Task X concluída
- [x] Task Y concluída
- [ ] Task Z em andamento

## OBJETIVO DESTA SESSÃO

[descrever a task específica]

## CÓDIGO ATUAL (se relevante)

[colar o arquivo que quer discutir]

## DÚVIDA ESPECÍFICA

[sua pergunta]`

---

_Documento gerado em: março 2026 | Versão: 2.0_ _Próxima revisão: ao completar Fase 2 (semana 4)_
