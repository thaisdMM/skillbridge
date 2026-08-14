# AUDITORIA TÉCNICA — SKILLBRIDGE

**Data da auditoria:** 2026-08-11
**Escopo:** monorepo `thaisdMM/skillbridge`, branch `feature/django-refactor` (HEAD `19b3ac9`)
**Modo:** somente leitura. Nenhum arquivo do projeto foi alterado. O único arquivo escrito é este.
**Ambiente de execução dos comandos:** Docker (`docker compose exec -T web ...`) a partir de `django_version/`, mais comandos `git`, `find`, `wc` e `curl` no host.

---

## ERRATA (2026-08-13)

Três correções foram aplicadas ao corpo deste documento após a verificação de
2026-08-12 (`VERIFICACAO_AUDITORIA_SKILLBRIDGE.md`):

- A contagem de códigos de invariante distintos, na seção sobre `clean()`.
- A partição dos 304 testes por categoria (models/admin/validators).
- As citações de linha do §13.8 para `README.md` e `.gitignore`.

Detalhes completos na Limitação 15.

---

## 1. IDENTIFICAÇÃO

| Item | Valor | Origem |
|---|---|---|
| Nome do repositório | `skillbridge` | `git remote -v` |
| URL | `git@github.com:thaisdMM/skillbridge.git` → https://github.com/thaisdMM/skillbridge | `git remote -v` |
| Visibilidade | **Público** (`"private": false`) | `curl https://api.github.com/repos/thaisdMM/skillbridge` |
| Criação do repositório no GitHub | 2025-12-20T14:49:00Z | API GitHub |
| Último push | 2026-08-09T15:56:37Z | API GitHub |
| Licença | `null` — **NÃO EXISTE** arquivo de licença | API GitHub |
| Branch default no GitHub | `main` | API GitHub |

**Commits**

| Item | Valor | Comando |
|---|---|---|
| Total na branch atual | **245** | `git rev-list --count HEAD` |
| Total em todas as branches | 246 | `git rev-list --count --all` |
| Primeiro commit | 2025-12-20 15:54:29 +0100 — `d0318dd` "Initial commit: project structure with requirements.txt and venv setup" | `git log --reverse --date=iso` |
| Último commit | 2026-08-09 19:31:29 +0200 — `19b3ac9` "docs(spec/001-profiles-admin-panel): walk the skill filter rows in quickstart.md" | `git log -1 --date=iso` |

**Branches**

- Locais: `main`, `feature/django-refactor` (atual)
- Remotas: `origin/main`, `origin/feature/django-refactor`

**Divergência entre branches** — medida contra `origin/main`, não contra o ref local:

```
$ git rev-list --left-right --count origin/main...feature/django-refactor
1       61
```

`origin/main` aponta para `c149ae0`, **2026-07-17T16:04:15Z**, "Merge pull request #4 from thaisdMM/feature/django-refactor" — SHA conferido contra a API do GitHub (`/repos/.../branches/main`), idêntico. O único commit exclusivo de `origin/main` é esse próprio commit de merge. `feature/django-refactor` está **61 commits à frente**.

> **Atenção ao ref local.** `git log -1 main` retorna `329d1f1`, de 2026-03-25. O ref local `main` está parado porque a branch nunca foi atualizada nesta máquina após o merge feito pela interface do GitHub — ele reflete o último `checkout main` local, **não** o estado publicado. Qualquer afirmação sobre o que está no GitHub deve usar `origin/main` ou a API, nunca `main`.

**O que `origin/main` já contém:** os 6 models concretos (incluindo `skill.py`, `freelancer_profile.py`, `client_profile.py`), 13 migrations, o app `accounts` inteiro e `accounts/admin.py` na sua forma anterior à spec.

**O que falta em `origin/main`** (`git ls-tree -r --name-only` comparado entre os dois refs, mais `wc -l` por arquivo via `git show`):

| Item | `origin/main` | `feature/django-refactor` |
|---|---|---|
| `django_version/profiles/admin.py` | **3 linhas — scaffold do `startapp`, sem `SkillAdmin`** | 120 linhas |
| `django_version/accounts/admin.py` | 429 linhas — sem inlines, sem `ProfilePresenceMixin`, sem `HasProfileFilter`/`SkillInUseFilter` | 718 linhas |
| `profiles/models/skill.py` | 124 linhas (sem a regra case-insensitive) | 159 linhas |
| `profiles/models/client_profile.py` | 169 linhas (sem `profile_for_inactive_account`) | 207 linhas |
| `profiles/models/freelancer_profile.py` | 157 linhas (idem) | 195 linhas |
| `config/settings.py` | 180 linhas | 180 linhas — idêntico |
| Arquivos `.py` em `django_version/` | 61 | 68 |
| Funções `def test_` | **137** | **272** |
| `specs/`, `.specify/`, skills `speckit-*` | ausentes | presentes |
| `docs/adr/` (5), `docs/tech_debt/` (4), `docs/audits/` (6), roadmaps | ausentes | presentes |
| `docs/tech_debt.md` (arquivo único) | presente | substituído pelo diretório `docs/tech_debt/` |

Os 7 arquivos `.py` ausentes em `origin/main` são: `accounts/tests/admin/test_account_list_profile.py`, `test_client_profile_inline.py`, `test_freelancer_profile_inline.py`, `profiles/migrations/0007_skill_skill_unique_name_case_insensitive.py`, `profiles/tests/admin/__init__.py`, `profiles/tests/admin/test_skill_admin.py`, `profiles/tests/models/test_client_profile.py`.

Em resumo: a branch default pública tem os **models** de profiles desde o merge de 2026-07-17, e **não tem o painel de administração de profiles** — que é exatamente o entregável da spec 001 — nem os artefatos de SDD, ADRs e dívida técnica produzidos em agosto.

> Nota sobre a contagem de testes: 137 e 272 são funções `def test_`, não testes coletados. Na branch atual, 272 funções expandem para os 304 testes coletados por causa de `@pytest.mark.parametrize`. A contagem coletada de `origin/main` não foi medida — exigiria checkout daquele ref.

**Commits locais não enviados** — `git status -sb` retorna `## feature/django-refactor...origin/feature/django-refactor [ahead 8]`, e `git rev-list --left-right --count origin/feature/django-refactor...HEAD` retorna `0  8`. **8 commits existem apenas nesta máquina.** Toda medição desta auditoria foi feita sobre a árvore de trabalho local; 8 commits dela ainda não estão publicados em nenhuma branch remota.

**READMEs existentes** (3 arquivos rastreados, `find . -iname 'README*'` + `wc -l`):

| Arquivo | Linhas | O que cobre |
|---|---|---|
| [README.md](README.md) | 25 | Badge de CI, descrição de 1 parágrafo, tabela com as duas pastas do monorepo, seção "Author" |
| [django_version/README.md](django_version/README.md) | 98 | Badge de CI, tabela de stack, Quick Start com Docker, hierarquia de models de usuário, 5 decisões-chave, seção "Foundation" listando o app `accounts`, seção "Author" |
| [oop_version/README.md](oop_version/README.md) | 77 | O que foi implementado na versão OOP, lista dos 9 arquivos de teste, stack, quick start, motivo do encerramento |

**Divergências encontradas nos READMEs** (todas verificadas contra os arquivos citados):

- `django_version/README.md:16` declara `Django 6.0.3`; `django_version/requirements.txt:5` fixa `Django==6.0.7`.
- `django_version/README.md:3` — a URL do link do badge contém `actionsZ/workflows` (a URL da imagem, na mesma linha, está correta).
- `django_version/README.md:6` e `:45` linkam `./ARCHITECTURE.md`; o arquivo está na raiz do monorepo ([ARCHITECTURE.md](ARCHITECTURE.md)), não em `django_version/`. `ls django_version/ARCHITECTURE.md` → "No such file or directory".
- `django_version/README.md:96` diz que o roadmap é mantido em `ROADMAP.md`. `ls ROADMAP.md django_version/ROADMAP.md` → não existe em nenhum dos dois. O roadmap real é [docs/ROADMAP_SKILLBRIDGE.md](docs/ROADMAP_SKILLBRIDGE.md).
- `django_version/README.md:82-92` (seção "Foundation") descreve apenas o app `accounts`. O app `profiles` (4 models, admin, 104 testes) não é mencionado em nenhum README.

---

## 2. STACK REAL

Fonte: [django_version/requirements.txt](django_version/requirements.txt). **NÃO EXISTE** `pyproject.toml`, `Pipfile`, `setup.cfg` nem `poetry.lock` no repositório (`ls -a` na raiz e em `django_version/`).

- **Python:** 3.14 — `python:3.14.6-slim` em [django_version/Dockerfile:2](django_version/Dockerfile#L2); `python-version: "3.14.6"` em [.github/workflows/ci.yml:46](.github/workflows/ci.yml#L46)
- **Django:** 6.0.7 — `requirements.txt:5`

**Dependências declaradas — 19 linhas em `requirements.txt`.** `pip list` dentro do container retorna 20 pacotes (as 19 + `pip 26.1.2`), confirmando que o ambiente instalado corresponde exatamente ao arquivo.

### (a) Declaradas E efetivamente usadas

Base: `grep -rhE '^\s*(import|from) ' --include='*.py'` sobre `accounts/`, `config/`, `profiles/`, `manage.py`.

| Pacote | Versão | Como é usado |
|---|---|---|
| `Django` | 6.0.7 | `from django...` em praticamente todos os módulos |
| `python-dotenv` | 1.2.2 | `from dotenv import load_dotenv` — [config/settings.py:3](django_version/config/settings.py#L3) |
| `pytest` | 9.1.1 | `import pytest` em todos os arquivos de teste |
| `pytest-django` | 4.12.0 | Plugin — ativado por `DJANGO_SETTINGS_MODULE` em [django_version/pytest.ini:2](django_version/pytest.ini#L2); fixture `db` e marker `django_db` usados nos testes |
| `argon2-cffi` | 25.1.0 | Sem `import` direto. Consumido por referência de string: `"django.contrib.auth.hashers.Argon2PasswordHasher"` em [config/settings.py:104](django_version/config/settings.py#L104) |
| `psycopg` | 3.3.4 | Sem `import` direto. Consumido pelo `ENGINE` `django.db.backends.postgresql` em [config/settings.py:77](django_version/config/settings.py#L77) |
| `psycopg-pool` | 3.3.1 | Sem `import` direto. Exigido por `OPTIONS: {"pool": True}` em [config/settings.py:83-85](django_version/config/settings.py#L83-L85) |

### (b) Declaradas mas nunca importadas nem referenciadas

| Pacote | Versão | Observação |
|---|---|---|
| `pillow` | 12.3.0 | `grep -rn 'ImageField\|FileField\|PIL\|Pillow'` sobre `accounts/`, `config/`, `profiles/` → nenhum resultado. `libjpeg-dev` e `zlib1g-dev` são instalados no [Dockerfile:16-17](django_version/Dockerfile#L16-L17) apenas para compilá-lo. O roadmap prevê upload de foto na TASK 4.2.2, ainda não iniciada. |

### (c) Dependências transitivas (declaradas por pinagem, não usadas diretamente)

`argon2-cffi-bindings` 25.1.0, `asgiref` 3.12.1, `cffi` 2.1.0, `iniconfig` 2.3.0, `packaging` 26.2, `pluggy` 1.6.0, `psycopg-binary` 3.3.4, `pycparser` 3.0, `Pygments` 2.20.0, `sqlparse` 0.5.5, `typing_extensions` 4.16.0.

### (d) Declaradas na documentação mas NÃO instaladas

`docker compose exec web pip list | grep -iE 'rest|spectacular|cov|ruff|black|mypy'` → nenhum resultado.

- **DRF** — citado em [CLAUDE.md:5](CLAUDE.md#L5), [.claude/rules/conventions.md](.claude/rules/conventions.md) ("Not yet installed"), [ARCHITECTURE.md](ARCHITECTURE.md) em 6 seções. **NÃO INSTALADO.**
- **drf-spectacular** — mesma situação. **NÃO INSTALADO.**

### Banco de dados

| Ambiente | Configuração | Arquivo |
|---|---|---|
| Local (Docker) | PostgreSQL `postgres:17.10`, porta host `5433` → container `5432`, volume nomeado `postgres_data`, healthcheck `pg_isready` | [django_version/docker-compose.yml:4-20](django_version/docker-compose.yml#L4-L20) |
| Local (app) | `ENGINE=django.db.backends.postgresql`, `NAME/USER/PASSWORD` de env, `HOST` default `localhost`, `PORT` default `5432`, `OPTIONS.pool=True` | [config/settings.py:75-87](django_version/config/settings.py#L75-L87) |
| CI | PostgreSQL `postgres:17.10` como service, porta `5432:5432`, `DB_NAME=skillbridge_ci`, `DB_USER=skillbridge_user`, `DB_PASSWORD=skillbridge_pass`, `DB_HOST=localhost` | [.github/workflows/ci.yml:15-36](.github/workflows/ci.yml#L15-L36) |

**Diferenças local × CI:**

1. `DB_HOST` é `db` (nome do serviço Docker) no `.env.example` e `localhost` no CI.
2. A porta exposta ao host é `5433` localmente e `5432` no CI.
3. As credenciais do CI estão em texto claro no workflow; só `SECRET_KEY` vem de `secrets.SECRET_KEY`.
4. O CI **não** usa Docker para a aplicação — instala as dependências com `pip install -r requirements.txt` direto no runner ([ci.yml:48-49](.github/workflows/ci.yml#L48-L49)), enquanto o desenvolvimento local roda dentro do container `web`.

**`CONN_MAX_AGE` não aparece em `settings.py`** — ausência registrada como decisão em [ARCHITECTURE.md](ARCHITECTURE.md) (seção "PostgreSQL with psycopg3 and Connection Pooling").

---

## 3. ARQUITETURA

### Apps Django

`INSTALLED_APPS` em [config/settings.py:28-37](django_version/config/settings.py#L28-L37):

- 6 apps do próprio Django (`admin`, `auth`, `contenttypes`, `sessions`, `messages`, `staticfiles`)
- **2 apps do projeto:** `accounts.apps.AccountsConfig`, `profiles.apps.ProfilesConfig`

Um terceiro app, `jobs`, tem logger configurado em [config/settings.py:159-163](django_version/config/settings.py#L159-L163) mas **NÃO EXISTE** como diretório (`ls django_version/jobs` → "No such file or directory") e não está em `INSTALLED_APPS`.

### Estrutura de diretórios (2 níveis, excluindo `.git`, `.venv`, `__pycache__`, `.pytest_cache`)

```
skillbridge/
├── .claude/
│   ├── rules/          conventions.md, testing.md, "sdd-workflow.md " (nome com espaço final)
│   ├── skills/         10 skills speckit-*
│   └── settings.local.json
├── .github/workflows/  ci.yml
├── .specify/           feature.json, memory/, scripts/, templates/, workflows/, integrations/
├── .vscode/settings.json   (ignorado pelo .gitignore, não rastreado)
├── ARCHITECTURE.md     952 linhas
├── CLAUDE.md           contexto raiz
├── README.md           25 linhas
├── django_version/     ← ATIVO
│   ├── accounts/
│   ├── config/
│   ├── profiles/
│   ├── Dockerfile, docker-compose.yml, .dockerignore
│   ├── .env (ignorado), .env.example
│   ├── manage.py, pytest.ini, requirements.txt
│   ├── README.md
│   └── AUDITOR.md VERIFIER.md PLANNER.md DEVELOPER.md TEACHER.md CLAUDE.md
├── docs/
│   ├── ROADMAP_SKILLBRIDGE.md (2014 linhas), ROADMAP_STACK_TRIAGE.md (551), SYSTEM_OVERVIEW.md (153)
│   ├── adr/            5 arquivos
│   ├── audits/         6 arquivos
│   ├── tech_debt/      4 arquivos
│   ├── spekit_setup/   3 arquivos
│   ├── plan/           ← DIRETÓRIO VAZIO
│   └── skill-admin-findings-2026-08-04.md, skill-admin-findings-explained-2026-08-05.md
├── oop_version/        ← FECHADO (src/, tests/, README.md, requirements.txt)
└── specs/001-profiles-admin-panel/   12 arquivos, 4321 linhas
```

### Padrão de settings

**Arquivo único.** [config/settings.py](django_version/config/settings.py), 180 linhas. **NÃO EXISTE** split por ambiente (`settings/base.py`, `settings/dev.py`, `settings/prod.py`). O roadmap prevê o split na TASK 5.1.1 ("Settings por Ambiente"), sem nenhum item marcado.

### Carregamento de variáveis de ambiente

- Biblioteca: `python-dotenv` 1.2.2
- Chamada: `load_dotenv(BASE_DIR / ".env")` — [config/settings.py:9](django_version/config/settings.py#L9)
- Arquivo lido: `django_version/.env` (existe no host, ignorado pelo git — `git ls-files | grep '\.env'` retorna somente `django_version/.env.example`)
- Template: [django_version/.env.example](django_version/.env.example), 10 linhas, 6 variáveis (`SECRET_KEY`, `DEBUG`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`)
- No container, `docker-compose.yml:29-30` também passa `env_file: .env` ao serviço `web`

---

## 4. MODELS

### Contagem

**6 models concretos** + **2 bases abstratas**. Obtido por introspecção do registry Django dentro do container:

```
docker compose exec -T web python -c "from django.apps import apps; ..."
```

### Detalhamento

| Model | Arquivo | Tabela | Campos concretos | M2M | Relacionamentos |
|---|---|---|---|---|---|
| `BaseUser` *(abstract)* | [accounts/models/base.py:151](django_version/accounts/models/base.py#L151) | — (sem tabela) | 6 declarados + herdados de `AbstractBaseUser` | 0 | nenhum |
| `Freelancer` | [accounts/models/freelancer.py:21](django_version/accounts/models/freelancer.py#L21) | `freelancers` | **10** | 0 | reverso `profile` ← `FreelancerProfile` (OneToOneRel) |
| `Client` | [accounts/models/client.py:11](django_version/accounts/models/client.py#L11) | `clients` | **9** | 0 | reverso `profile` ← `ClientProfile` (OneToOneRel) |
| `StaffUser` | [accounts/models/staff_user.py:20](django_version/accounts/models/staff_user.py#L20) | `staff_users` | **9** | 0 | nenhum. É o `AUTH_USER_MODEL` |
| `Profile` *(abstract)* | [profiles/models/base.py:18](django_version/profiles/models/base.py#L18) | — (sem tabela) | 3 (`bio`, `created_at`, `updated_at`) | 0 | nenhum |
| `Skill` | [profiles/models/skill.py:19](django_version/profiles/models/skill.py#L19) | `skills` | **3** (`id`, `name`, `category`) | 0 | alvo de 2 M2M (`FreelancerProfile.skills`, `ClientProfile.interests`) |
| `FreelancerProfile` | [profiles/models/freelancer_profile.py:23](django_version/profiles/models/freelancer_profile.py#L23) | `freelancer_profiles` | **8** | **1** | `user` → `OneToOneField(Freelancer, on_delete=PROTECT, related_name="profile")`; `skills` → `ManyToManyField(Skill, blank=True)` |
| `ClientProfile` | [profiles/models/client_profile.py:22](django_version/profiles/models/client_profile.py#L22) | `client_profiles` | **8** | **1** | `user` → `OneToOneField(Client, on_delete=PROTECT, related_name="profile")`; `interests` → `ManyToManyField(Skill, blank=True)` |

**Totais de relacionamentos:** 2 `OneToOneField` (ambos `on_delete=PROTECT`), 2 `ManyToManyField`, **0 `ForeignKey`**.

### `Meta`

Todos os 6 models concretos e as 2 abstratas declaram `class Meta`.

| Model | Conteúdo do `Meta` |
|---|---|
| `BaseUser` | `abstract=True`, `verbose_name`, `verbose_name_plural`, `ordering=["-created_at"]` |
| `Freelancer` | herda `BaseUser.Meta`; `db_table="freelancers"`; `CheckConstraint` `freelancer_no_inactive_available` |
| `Client` | herda `BaseUser.Meta`; `db_table="clients"` |
| `StaffUser` | `Meta` próprio (não herda); `db_table="staff_users"`; `CheckConstraint` `staffuser_active_no_staff_status` |
| `Profile` | `abstract=True`, `ordering=["-created_at"]` |
| `Skill` | `db_table="skills"`, `ordering=["category","name"]`; `UniqueConstraint(Lower("name"))` `skill_unique_name_case_insensitive` |
| `FreelancerProfile` | herda `Profile.Meta`; `db_table="freelancer_profiles"` |
| `ClientProfile` | herda `Profile.Meta`; `db_table="client_profiles"` |

**3 constraints de banco no total**, confirmadas por `m._meta.constraints` no registry.

### `__str__` e `__repr__`

| Model | `__str__` | `__repr__` |
|---|---|---|
| `BaseUser` | `base.py:235` — `"{user_type.capitalize()} (id=...)"` | `base.py:244` — `"{ClassName} (id=...)"` |
| `Freelancer` | herdado | `freelancer.py:65` — inclui `is_available` |
| `Client` | herdado | herdado |
| `StaffUser` | herdado | herdado |
| `Profile` | `base.py:62` | `base.py:71` |
| `Skill` | `skill.py:81` — retorna `self.name` | `skill.py:90` — inclui `id`, `name`, `category` |
| `FreelancerProfile` | herdado | `freelancer_profile.py:89` — inclui `user_id`, `hourly_rate` |
| `ClientProfile` | herdado | `client_profile.py:90` — inclui `user_id`, `max_budget` |

Nenhum `__str__`/`__repr__` de model de usuário expõe `email` ou `name` — política registrada em [.claude/rules/conventions.md](.claude/rules/conventions.md) ("GDPR logging policy"). `Skill.__str__` retorna o nome, que não é PII.

### `property`

1 no total: `BaseUser.user_type` — [accounts/models/base.py:225-233](django_version/accounts/models/base.py#L225-L233).

### Managers customizados

1: `BaseUserManager(DjangoBaseUserManager)` — [accounts/models/base.py:29](django_version/accounts/models/base.py#L29), com `create_user()` e `create_superuser()`. Declarado apenas em `BaseUser` (`objects = BaseUserManager()`, linha 217); nenhum model concreto o redeclara (`grep 'objects =' accounts/models/` → única ocorrência).

`create_user()` chama `full_clean()` antes de `save()` ([base.py:91](django_version/accounts/models/base.py#L91)) — comportamento que o Django não faz por padrão.

### Validadores

3 funções em [accounts/validators/user_validators.py](django_version/accounts/validators/user_validators.py) (181 linhas):

| Função | Linha | Codes emitidos |
|---|---|---|
| `validate_email` | 14 | `empty_email`, `invalid_email` |
| `validate_user_name` | 61 | `empty_name`, `name_too_short`, `name_too_long` |
| `validate_strong_password` | 104 | `password_too_short`, `password_contains_whitespace`, `password_only_digits`, `password_missing_lowercase`, `password_missing_uppercase`, `password_no_special_char` |

Ligados aos campos via `validators=[...]` em `BaseUser.email` (linha 177) e `BaseUser.name` (linha 184). `validate_strong_password` não é registrado em nenhum campo — é chamado explicitamente em `create_user()` ([base.py:76](django_version/accounts/models/base.py#L76)).

Um validador Django built-in em uso: `MaxLengthValidator(500)` em `Profile.bio` ([profiles/models/base.py:39](django_version/profiles/models/base.py#L39)).

### Métodos `clean()` e códigos de invariante

6 `clean()` implementados; 10 códigos distintos:

| Arquivo:linha | Codes |
|---|---|
| [accounts/models/base.py:278](django_version/accounts/models/base.py#L278) | `invalid_staff_privileges`, `superuser_without_staff` |
| [accounts/models/freelancer.py:77](django_version/accounts/models/freelancer.py#L77) | `freelancer_inactive_available` |
| [accounts/models/staff_user.py:61](django_version/accounts/models/staff_user.py#L61) | `staffuser_active_without_staff` |
| [profiles/models/skill.py:103](django_version/profiles/models/skill.py#L103) | `skill_name_empty`, `skill_name_duplicate` |
| [profiles/models/freelancer_profile.py:127](django_version/profiles/models/freelancer_profile.py#L127) | `hourly_rate_not_positive`, `profile_for_inactive_account` |
| [profiles/models/client_profile.py:128](django_version/profiles/models/client_profile.py#L128) | `company_name_empty`, `max_budget_not_positive`, `profile_for_inactive_account` |

Nota: `.claude/rules/conventions.md` lista os códigos estabelecidos mas **não inclui `profile_for_inactive_account`** — a tarefa T060 de `specs/001-profiles-admin-panel/tasks.md`, que adicionaria essa entrada, está desmarcada (ver seção 13).

### Migrations

**14 arquivos** (`find django_version -path '*/migrations/*.py' | grep -v __init__ | wc -l`), 404 linhas somando os `__init__.py`.

| App | Arquivos |
|---|---|
| `accounts` (7) | `0001_initial`, `0002_alter_staffuser_is_staff`, `0003_alter_freelancer_options`, `0004_alter_client_options`, `0005_alter_staffuser_is_staff`, `0006_freelancer_freelancer_no_inactive_available`, `0007_staffuser_staffuser_active_no_staff_status` |
| `profiles` (7) | `0001_initial`, `0002_seed_skills`, `0003_freelancerprofile`, `0004_alter_freelancerprofile_bio`, `0005_alter_freelancerprofile_options_and_more`, `0006_clientprofile`, `0007_skill_skill_unique_name_case_insensitive` |

`0002_seed_skills` é uma data migration com **30 skills** (`grep -c '{"name"'`), distribuídas em 8 TECHNOLOGY, 8 DESIGN, 7 WRITING, 7 MARKETING. Usa `bulk_create(ignore_conflicts=True)` sem `full_clean()` — decisão registrada em [ARCHITECTURE.md](ARCHITECTURE.md) ("Skill Seed — bulk_create Without clean() Validation"). Como `pytest.ini` roda com `--no-migrations`, essa migration **não executa nos testes**.

**Verificação de drift:** `docker compose exec -T web python manage.py makemigrations --check --dry-run` → **"No changes detected"** (exit 0). Não há alteração de model pendente de migration.

---

## 5. VIEWS E ROTAS

### Views

| Tipo | Quantidade | Evidência |
|---|---|---|
| Function-based views escritas | **0** | — |
| Class-based views escritas | **0** | — |

[accounts/views.py](django_version/accounts/views.py) e [profiles/views.py](django_version/profiles/views.py) têm **3 linhas cada**, com conteúdo idêntico ao gerado por `django-admin startapp`:

```python
from django.shortcuts import render

# Create your views here.
```

**Ambos são boilerplate não modificado.** Nenhuma view é referenciada em nenhum `urls.py`.

### Rotas

`urlpatterns` declarado pelo projeto — [config/urls.py:21-23](django_version/config/urls.py#L21-L23):

| Caminho | Métodos | View responsável | Arquivo |
|---|---|---|---|
| `admin/` | delegado | `admin.site.urls` (`django.contrib.admin`) | [config/urls.py:22](django_version/config/urls.py#L22) |

**1 entrada declarada.** Nenhuma rota própria do projeto. O restante do arquivo (linhas 1-16) é o docstring gerado por `django-admin startproject`, não modificado.

`admin.site.urls` resolve para **40 padrões de URL**, todos gerados pelo Django a partir dos `ModelAdmin` registrados (contagem obtida percorrendo `django.urls.get_resolver()` dentro do container). Nenhum foi escrito manualmente:

- 8 do `AdminSite` (`admin/`, `login/`, `logout/`, `password_change/`, `password_change/done/`, `autocomplete/`, `jsi18n/`, `r/<content_type_id>/<object_id>/`)
- 6 por model registrado × 5 models registrados (`auth.Group`, `accounts.Freelancer`, `accounts.Client`, `accounts.StaffUser`, `profiles.Skill`) = 30 (`changelist`, `add/`, `<id>/history/`, `<id>/delete/`, `<id>/change/`, `<id>/`)
- 2 catch-all (`^(?P<app_label>auth|accounts|profiles)/$` e `(?P<url>.*)$`)

### DRF

**NÃO EXISTE.** Não há serializers, viewsets, generic views, permission classes, authentication classes, paginação ou filtros de DRF. Nenhum arquivo `serializers.py` ou `permissions.py` existe (`find django_version -name 'serializers.py' -o -name 'permissions.py'` → vazio). O pacote não está instalado (ver seção 2d).

Existem 2 filtros, mas do Django Admin, não do DRF:

- `HasProfileFilter(admin.SimpleListFilter)` — [accounts/admin.py:176](django_version/accounts/admin.py#L176)
- `SkillInUseFilter(admin.RelatedOnlyFieldListFilter)` — [accounts/admin.py:218](django_version/accounts/admin.py#L218)

Paginação: `list_per_page = 25` nos 4 admins registrados — funcionalidade do admin, não do DRF.

---

## 6. ADMIN

Dois arquivos: [accounts/admin.py](django_version/accounts/admin.py) (718 linhas) e [profiles/admin.py](django_version/profiles/admin.py) (120 linhas).

### Models registrados (4)

| Model | Classe admin | Decorator | Arquivo |
|---|---|---|---|
| `Freelancer` | `FreelancerAdmin(ProfilePresenceMixin, StatusBadgeMixin, BaseAccountAdmin)` | `@admin.register(Freelancer)` | [accounts/admin.py:325](django_version/accounts/admin.py#L325) |
| `Client` | `ClientAdmin(ProfilePresenceMixin, StatusBadgeMixin, BaseAccountAdmin)` | `@admin.register(Client)` | [accounts/admin.py:513](django_version/accounts/admin.py#L513) |
| `StaffUser` | `StaffUserAdmin(BaseAccountAdmin)` | `@admin.register(StaffUser)` | [accounts/admin.py:586](django_version/accounts/admin.py#L586) |
| `Skill` | `SkillAdmin(admin.ModelAdmin)` | `@admin.register(Skill)` | [profiles/admin.py:22](django_version/profiles/admin.py#L22) |

`FreelancerProfile` e `ClientProfile` **não são registrados** como models próprios — aparecem apenas como inlines. `auth.Group` aparece no admin por vir de `django.contrib.auth`, sem classe do projeto.

### Classes não registradas (base e mixins)

| Classe | Linha | Papel |
|---|---|---|
| `BaseAccountAdmin(admin.ModelAdmin)` | [accounts/admin.py:41](django_version/accounts/admin.py#L41) | `has_delete_permission=False`, `save_model`, `created_at_display` |
| `ProfileInlineForm(forms.ModelForm)` | [accounts/admin.py:81](django_version/accounts/admin.py#L81) | Reposiciona erros de campos ocultos |
| `BaseProfileInline(admin.StackedInline)` | [accounts/admin.py:105](django_version/accounts/admin.py#L105) | Base dos dois inlines |
| `StatusBadgeMixin` | [accounts/admin.py:151](django_version/accounts/admin.py#L151) | `status_badge` |
| `HasProfileFilter(admin.SimpleListFilter)` | [accounts/admin.py:176](django_version/accounts/admin.py#L176) | Filtro "com/sem perfil" |
| `SkillInUseFilter(admin.RelatedOnlyFieldListFilter)` | [accounts/admin.py:218](django_version/accounts/admin.py#L218) | Filtro por skill em uso |
| `ProfilePresenceMixin` | [accounts/admin.py:241](django_version/accounts/admin.py#L241) | `get_queryset` com `Exists(...)` + `profile_badge` |

### Customizações por admin

**`FreelancerAdmin`** ([accounts/admin.py:325-469](django_version/accounts/admin.py#L325-L469))

- `list_display`: `id`, `name`, `email`, `status_badge`, `availability_badge`, `profile_badge`, `created_at_display`
- `list_display_links`: `name`, `email`
- `list_filter`: `is_active`, `is_available`, `HasProfileFilter`, `("profile__skills", SkillInUseFilter)`, `created_at`
- `search_fields`: `name`, `email` · `ordering`: `-created_at` · `list_per_page`: 25
- `readonly_fields`: `created_at`, `last_login`
- `fieldsets`: 3 grupos — sem título (`name`, `email`); "Account Status" (`is_active`, `is_available`); "Important Dates" (`created_at`, `last_login`, `collapse`)
- **actions (3):** `activate_accounts` (`.update()` em bloco), `set_available` (loop com `obj.clean()`, pula inativos), `set_unavailable` (`.update()` em bloco)
- métodos de display: `availability_badge` (`format_html`)

**`ClientAdmin`** ([accounts/admin.py:513-583](django_version/accounts/admin.py#L513-L583))

- `list_display`: `name`, `email`, `status_badge`, `profile_badge`, `created_at_display`
- `list_filter`: `is_active`, `HasProfileFilter`, `("profile__interests", SkillInUseFilter)`, `created_at`
- `search_fields`: `name`, `email` · `ordering`: `-created_at` · `list_per_page`: 25
- `readonly_fields`: `created_at`, `last_login`
- `fieldsets`: 3 grupos
- **actions (1):** `activate_accounts`

**`StaffUserAdmin`** ([accounts/admin.py:586-718](django_version/accounts/admin.py#L586-L718))

- `list_display`: `name`, `email`, `is_active`, `is_staff`, `created_at_display` (colunas cruas, sem badge)
- `list_filter`: `is_active`, `created_at` · `search_fields`: `name`, `email` · `ordering`: `-created_at` · `list_per_page`: 25
- `readonly_fields`: `created_at`, `last_login`, `is_superuser`
- `fieldsets`: 4 grupos, incluindo "Administrative" (`is_staff`, `is_superuser`, `collapse`)
- **actions (2):** `activate_accounts` (loop com `obj.clean()`, pula não-staff), `deactivate_accounts` (`.update()` em bloco)
- `get_readonly_fields` — adiciona `is_staff` a readonly quando `request.user.is_superuser` é falso

**`SkillAdmin`** ([profiles/admin.py:22-120](django_version/profiles/admin.py#L22-L120))

- `list_display`: `name`, `category` · `list_display_links`: `name` · `list_filter`: `category`
- `search_fields`: `name` · `ordering`: `category`, `name` · `list_per_page`: 25
- `fieldsets`: 1 grupo sem título (`name`, `category`)
- **actions:** nenhuma declarada
- `get_deleted_objects()` sobrescrito — bloqueia remoção enquanto algum perfil referenciar a skill, contando `FreelancerProfile` + `ClientProfile` distintos ([profiles/admin.py:81-99](django_version/profiles/admin.py#L81-L99))
- É o **único** admin que permite exclusão — os outros três herdam `has_delete_permission=False` de `BaseAccountAdmin`

### Inlines

**2 inlines, ambos `StackedInline`** (nenhum `TabularInline` no projeto — `grep -rn 'TabularInline'` → sem resultado):

| Inline | Tipo | Model | Anexado a | Linha |
|---|---|---|---|---|
| `FreelancerProfileInline(BaseProfileInline)` | `StackedInline` | `FreelancerProfile` | `FreelancerAdmin` | [accounts/admin.py:284](django_version/accounts/admin.py#L284) |
| `ClientProfileInline(BaseProfileInline)` | `StackedInline` | `ClientProfile` | `ClientAdmin` | [accounts/admin.py:472](django_version/accounts/admin.py#L472) |

Configuração comum em `BaseProfileInline` ([accounts/admin.py:105-148](django_version/accounts/admin.py#L105-L148)): `form=ProfileInlineForm`, `extra=1`, `max_num=1`, `can_delete=False`, `readonly_fields=("created_at","updated_at")`, `has_delete_permission=False`, `formfield_for_dbfield` que remove o controle "adicionar relacionado" de todo campo de relação.

`FreelancerProfileInline` usa `filter_horizontal=("skills",)` e 4 fieldsets. `ClientProfileInline` usa `filter_horizontal=("interests",)` e 4 fieldsets. `StaffUserAdmin` não tem inlines.

### Formulários customizados no admin

**1:** `ProfileInlineForm(forms.ModelForm)` — [accounts/admin.py:81-102](django_version/accounts/admin.py#L81-L102). Sobrescreve `full_clean()` para mover erros de campos com widget oculto para o nível do formulário. Usado pelos dois inlines via `BaseProfileInline.form`.

Nenhum admin declara `form = ` próprio no nível de `ModelAdmin`.

---

## 7. TESTES

### Contagem exata

```
$ docker compose exec -T web pytest --collect-only -q
...
========================= 304 tests collected in 0.33s =========================
```

**304 testes coletados.**

### Distribuição por arquivo

Obtido com `pytest --collect-only -qq | grep '::' | sed 's/::.*//' | sort | uniq -c`:

| Arquivo | Testes |
|---|---|
| [accounts/tests/models/test_base.py](django_version/accounts/tests/models/test_base.py) | 50 |
| [accounts/tests/admin/test_freelancer_profile_inline.py](django_version/accounts/tests/admin/test_freelancer_profile_inline.py) | 28 |
| [accounts/tests/admin/test_client_profile_inline.py](django_version/accounts/tests/admin/test_client_profile_inline.py) | 27 |
| [profiles/tests/models/test_client_profile.py](django_version/profiles/tests/models/test_client_profile.py) | 26 |
| [profiles/tests/models/test_freelancer_profile.py](django_version/profiles/tests/models/test_freelancer_profile.py) | 25 |
| [profiles/tests/admin/test_skill_admin.py](django_version/profiles/tests/admin/test_skill_admin.py) | 24 |
| [profiles/tests/models/test_skill.py](django_version/profiles/tests/models/test_skill.py) | 24 |
| [accounts/tests/admin/test_account_list_profile.py](django_version/accounts/tests/admin/test_account_list_profile.py) | 18 |
| [accounts/tests/admin/test_admin.py](django_version/accounts/tests/admin/test_admin.py) | 18 |
| [accounts/tests/validators/test_validate_email.py](django_version/accounts/tests/validators/test_validate_email.py) | 15 |
| [accounts/tests/models/test_freelancer.py](django_version/accounts/tests/models/test_freelancer.py) | 12 |
| [accounts/tests/validators/test_validate_password.py](django_version/accounts/tests/validators/test_validate_password.py) | 11 |
| [accounts/tests/models/test_staff_user.py](django_version/accounts/tests/models/test_staff_user.py) | 9 |
| [accounts/tests/models/test_client.py](django_version/accounts/tests/models/test_client.py) | 6 |
| [accounts/tests/validators/test_validate_name.py](django_version/accounts/tests/validators/test_validate_name.py) | 6 |
| [profiles/tests/models/test_base.py](django_version/profiles/tests/models/test_base.py) | 5 |
| **Total** | **304** |

Por diretório: `accounts/tests/` = 200 · `profiles/tests/` = 104.
Por categoria: models = 157 · admin = 115 · validators = 32.

**Linhas de teste:** 4330 (`find ... -path '*/tests/*.py' | xargs wc -l`). **Linhas de produção** (sem testes e sem migrations): 2507. Razão teste:produção = 1,73:1.

### Testes unitários × integração

`pytest.ini:14-16` declara dois markers:

```ini
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests that need external services
```

`grep -rn 'pytest.mark.slow\|pytest.mark.integration' django_version/` → **nenhum resultado**. Os dois markers estão declarados e **não são usados por nenhum teste**. Não há separação formal entre unitários e integração.

A separação de fato é por diretório (`tests/models/`, `tests/admin/`, `tests/validators/`) e por acesso a banco (`@pytest.mark.django_db`), não por marker.

### Cobertura

**NÃO EXISTE** configuração de cobertura em `django_version/`:

- `pytest-cov` e `coverage` não estão em [django_version/requirements.txt](django_version/requirements.txt)
- `pip list` no container não retorna nenhum dos dois
- `pytest.ini` não tem `--cov` em `addopts`
- Não existe `.coveragerc` nem seção `[coverage:*]` em nenhum arquivo de config

Percentual de cobertura: **NÃO VERIFICADO — `pytest-cov` não está instalado e a auditoria é somente-leitura (instalar o pacote alteraria o ambiente).**

Observação: [oop_version/requirements.txt](oop_version/requirements.txt) **tem** `coverage==7.13.0` e `pytest-cov==7.0.0`, e existe um arquivo `oop_version/.coverage` no disco (não rastreado). A ferramenta de cobertura existia na versão fechada e não foi levada para a versão ativa.

### Fixtures e factories

**`factory_boy` NÃO EXISTE** (ausente de `requirements.txt` e de `pip list`). O roadmap prevê sua introdução na TASK 3.5.1, não iniciada.

Dois `conftest.py`, com 20 fixtures no total:

**[accounts/tests/conftest.py](django_version/accounts/tests/conftest.py)** (136 linhas, 9 fixtures): `valid_user_data`, `valid_freelancer_data`, `valid_client_data`, `freelancer_user`, `client_user`, `admin_site_client`, `skill`, `freelancer_profile`, `client_profile`.

**[profiles/tests/conftest.py](django_version/profiles/tests/conftest.py)** (192 linhas, 11 fixtures + 1 classe): classe `UnimplementedProfile(Profile)` (subclasse concreta que deliberadamente não implementa `get_display_info`), `unimplemented_profile`, `valid_freelancer_data`, `freelancer_user`, `valid_freelancer_profile_data`, `freelancer_profile`, `skill`, `valid_client_data`, `client_user`, `valid_client_profile_data`, `client_profile`.

Fixtures do Django/pytest-django em uso: `db`, `client` (test client), `RequestFactory`, `django_assert_num_queries`, `FallbackStorage`.

**Duplicação:** `freelancer_user`, `client_user`, `skill`, `freelancer_profile` e `client_profile` existem nos dois `conftest.py`, com implementações independentes.

### Testes marcados como skip, xfail ou comentados

```
$ grep -rn 'pytest.mark.skip\|pytest.mark.xfail\|@skip\|@unittest.skip\|pytest.skip\|pytest.xfail' --include='*.py' django_version/
(nenhum resultado)
```

**NENHUM.** Zero testes desabilitados, zero `xfail`, zero blocos de teste comentados.

### Comando exato para rodar a suíte

```bash
cd django_version
docker compose exec web pytest
```

Flags ativas por `pytest.ini:7-12`: `--reuse-db --strict-markers --no-migrations -v --tb=short`.
Configuração: `DJANGO_SETTINGS_MODULE = config.settings`.

### Resultado da execução

```
$ docker compose exec -T web pytest
============================= 304 passed in 11.36s =============================
```

**304 passaram, 0 falharam, 0 erros, 0 warnings reportados.** Segunda execução: `304 passed in 10.94s`.

---

## 8. DOCKER

### Arquivos

| Arquivo | Linhas |
|---|---|
| [django_version/Dockerfile](django_version/Dockerfile) | 31 |
| [django_version/docker-compose.yml](django_version/docker-compose.yml) | 42 |
| [django_version/.dockerignore](django_version/.dockerignore) | 26 |

Não existe `Dockerfile` nem `docker-compose.yml` na raiz do monorepo nem em `oop_version/`.

### Imagens base

| Imagem | Versão | Arquivo |
|---|---|---|
| `python` | `3.14.6-slim` | [Dockerfile:2](django_version/Dockerfile#L2) |
| `postgres` | `17.10` | [docker-compose.yml:5](django_version/docker-compose.yml#L5) |

Ambas com patch fixado (commit "fix(infra): pin PostgreSQL and Python patch versions for reproducibility", 2026-07-21).

### Serviços do compose

`name: skillbridge` ([docker-compose.yml:1](django_version/docker-compose.yml#L1)).

| Serviço | Imagem/build | Portas | Volumes | Healthcheck | depends_on |
|---|---|---|---|---|---|
| `db` | `postgres:17.10` | `5433:5432` | `postgres_data:/var/lib/postgresql/data` | `pg_isready -U $DB_USER -d $DB_NAME`, interval 5s, timeout 5s, retries 5 | — |
| `web` | `build: .` | `8000:8000` | `.:/app` (bind mount) | **nenhum** | `db` com `condition: service_healthy` |

Rede: `skillbridge_network`, driver `bridge`. Volume nomeado: `postgres_data`.
`web` recebe `env_file: .env`; `db` recebe `POSTGRES_DB/USER/PASSWORD` por interpolação `${...}` do shell/`.env`.

### Características do Dockerfile

| Característica | Estado | Evidência |
|---|---|---|
| Build multi-stage | **NÃO** — um único `FROM` | [Dockerfile:2](django_version/Dockerfile#L2); `grep -c '^FROM' Dockerfile` = 1 |
| Usuário não-root | **NÃO** — nenhuma instrução `USER`; roda como root | `grep 'USER' Dockerfile` → sem resultado |
| `HEALTHCHECK` no Dockerfile | **NÃO** | `grep 'HEALTHCHECK' Dockerfile` → sem resultado |
| Healthcheck do serviço `web` no compose | **NÃO** — apenas `db` tem | [docker-compose.yml:14-18](django_version/docker-compose.yml#L14-L18) |
| Cache de camadas | `COPY requirements.txt .` antes de `COPY . .` | [Dockerfile:21-25](django_version/Dockerfile#L21-L25) |
| `ENV` de Python | `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1` | [Dockerfile:5-8](django_version/Dockerfile#L5-L8) |
| Limpeza de apt | `rm -rf /var/lib/apt/lists/*` | [Dockerfile:18](django_version/Dockerfile#L18) |
| `CMD` | `python manage.py runserver 0.0.0.0:8000` — servidor de desenvolvimento | [Dockerfile:31](django_version/Dockerfile#L31) |

O `CMD` do Dockerfile é sobrescrito pelo `command:` do compose ([docker-compose.yml:24](django_version/docker-compose.yml#L24)), que é idêntico. Não há servidor WSGI de produção (gunicorn/uvicorn) instalado nem configurado.

O `.dockerignore` exclui `__pycache__/`, `*.pyc/pyo/pyd`, `.Python`, `.venv/`, `venv/`, `env/`, `.env`, `.git/`, `.gitignore`, `.pytest_cache/`, `htmlcov/`, `.coverage`, `.DS_Store`.

### Escrito à mão ou copiado de template? — **avaliação, não fato verificado**

Minha avaliação é de **arquivo escrito à mão, não copiado de um template genérico**. Os indícios que sustentam essa leitura:

1. Os 7 comentários do `Dockerfile` explicam a intenção de cada bloco em prosa própria ("Prevents Python from writing .pyc files", "Install dependencies first (better Docker cache usage)"), em vez dos cabeçalhos padronizados que templates costumam trazer.
2. As dependências de sistema instaladas (`libpq-dev`, `libjpeg-dev`, `zlib1g-dev`) correspondem exatamente às dependências Python do projeto: `psycopg` e `pillow`. Um template genérico não instalaria `libjpeg-dev`/`zlib1g-dev`.
3. O compose usa `name: skillbridge` e a porta `5433:5432` — escolha específica, documentada em [ARCHITECTURE.md](ARCHITECTURE.md) como acesso externo via DBeaver.
4. As três omissões da tabela acima (multi-stage, usuário não-root, healthcheck no `web`) são justamente os itens que templates prontos de produção incluem por padrão. A ausência delas aponta para construção incremental a partir do mínimo necessário.

Isso é uma leitura de indícios. **Não é verificável por comando.**

---

## 9. CI/CD — GITHUB ACTIONS

### Arquivos

`ls .github/workflows/` → **1 arquivo**: [ci.yml](.github/workflows/ci.yml), 52 linhas, 1094 bytes.

### Workflow `CI`

| Item | Valor | Linha |
|---|---|---|
| `name` | `CI` | [1](.github/workflows/ci.yml#L1) |
| Gatilho (`on:`) | `push` em `branches: ["**"]` — todo push, em qualquer branch | [3-5](.github/workflows/ci.yml#L3-L5) |
| Jobs | **1**: `test` | [8](.github/workflows/ci.yml#L8) |
| Runner | `ubuntu-latest` | [9](.github/workflows/ci.yml#L9) |
| `defaults.run.working-directory` | `django_version` | [11-13](.github/workflows/ci.yml#L11-L13) |
| Service | `postgres:17.10`, porta `5432:5432`, healthcheck `pg_isready` (interval 10s, timeout 5s, retries 5) | [15-28](.github/workflows/ci.yml#L15-L28) |

**Passos (4):**

1. `Checkout code` — `actions/checkout@v4`
2. `Set up Python` — `actions/setup-python@v5`, `python-version: "3.14.6"`
3. `Install dependencies` — `pip install -r requirements.txt`
4. `Run tests` — `pytest`

### O que o pipeline faz de fato

| Etapa | Presente? |
|---|---|
| Roda testes | **SIM** — `pytest` (passo 4) |
| Roda linter | **NÃO** — nenhum passo de lint |
| Roda formatter check | **NÃO** |
| Type checking | **NÃO** |
| Cobertura | **NÃO** |
| Build de imagem Docker | **NÃO** — o CI não usa Docker; instala com `pip` no runner |
| Push de imagem | **NÃO** |
| Deploy | **NÃO** — não há job de deploy nem workflow de CD |
| Cache de dependências | **NÃO** — `actions/setup-python` sem `cache:` |
| Matriz de versões | **NÃO** — uma única versão de Python |

O pipeline é **exclusivamente de testes**. Não existe CD. A TASK 5.2.3 do roadmap ("CD no GitHub Actions") não tem nenhum item marcado.

### Datas do workflow

`git log --reverse --date=short -- .github/workflows/`:

- **Primeiro commit do arquivo: 2026-03-24** — "feat(ci): add GitHub Actions workflow with PostgreSQL service"
- Último commit: 2026-07-21 — "fix(infra): pin PostgreSQL and Python patch versions for reproducibility"

Apenas 2 commits tocaram o diretório em ~5 meses.

### Histórico de execuções

Obtido via `curl https://api.github.com/repos/thaisdMM/skillbridge/actions/runs?per_page=100` (repositório público, sem autenticação):

| Métrica | Valor |
|---|---|
| Total de execuções | **26** |
| Concluídas com sucesso | **25** |
| Falhas | **1** |
| Em andamento / canceladas | 0 (todas com `status: completed`) |
| Primeira execução | 2026-03-24T16:50:11Z |
| Última execução | 2026-08-09T15:56:39Z (`success`, branch `feature/django-refactor`) |
| **Data da última (e única) falha** | **2026-08-07T12:04:17Z**, branch `feature/django-refactor` |

Taxa de sucesso: 25/26. Todas as execuções recentes ocorreram em `feature/django-refactor`.

---

## 10. QUALIDADE E FERRAMENTAS

### Linter / formatter

**NENHUM configurado no repositório.**

`ls -a` na raiz e em `django_version/` filtrado por `ruff|black|flake8|isort|mypy|pyright|pre-commit|setup.cfg|pyproject|tox|editorconfig` → nenhum resultado nos dois diretórios.

- `.ruff.toml` / `ruff.toml` — **NÃO EXISTE**
- `pyproject.toml` — **NÃO EXISTE**
- `.flake8` / `setup.cfg` / `tox.ini` — **NÃO EXISTEM**
- `.isort.cfg` — **NÃO EXISTE**
- `.editorconfig` — **NÃO EXISTE**

A única referência a formatação está em [.vscode/settings.json](.vscode/settings.json), que **não é rastreado pelo git** (`git check-ignore -v .vscode/settings.json` → ignorado por `.gitignore:30`). Nele:

```json
"[python]": {
  "editor.defaultFormatter": "ms-python.black-formatter",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": { "source.organizeImports": "explicit" }
}
```

Ou seja: a formatação depende de uma extensão do editor de uma máquina, não é reproduzível, não está versionada e não é verificada no CI. `black` não está em `requirements.txt` nem instalado no container.

### pre-commit

**NÃO EXISTE.** `ls .pre-commit-config.yaml` → não encontrado, na raiz e em `django_version/`.

### Type checking

**NÃO EXISTE.** `mypy` e `pyright` não estão em `requirements.txt`, não estão instalados no container e não têm arquivo de configuração. Nenhum passo de type check no CI.

### Uso de type hints no código

Medido por AST (`ast.walk` sobre todos os `.py` fora de `.venv`, `__pycache__` e `migrations/`), executado dentro do container:

| Conjunto | Arquivos | Funções/métodos | Com anotação de retorno | % | Classes | Com docstring |
|---|---|---|---|---|---|---|
| Produção | 27 | 54 | **51** | **94%** | 33 | 54 (100%) |
| Testes | 25 | 303 | **303** | **100%** | 2 | 303 (100%) |

**Classificação: alto.** 354 de 357 funções do projeto declaram tipo de retorno.

**As 3 funções de produção sem anotação de retorno** — todas em código gerado por scaffold:

- [django_version/manage.py:7](django_version/manage.py#L7) — `main` (gerado por `django-admin startproject`)
- [django_version/accounts/apps.py:8](django_version/accounts/apps.py#L8) — `ready`
- [django_version/profiles/apps.py:8](django_version/profiles/apps.py#L8) — `ready`

Exemplos de arquivos com anotação em todas as assinaturas: [accounts/models/base.py](django_version/accounts/models/base.py) (`create_user(self, email: str, name: str, password: str | None = None, **extra_fields: Any) -> BaseUser`), [accounts/admin.py](django_version/accounts/admin.py) (`get_deleted_objects`, `queryset`, `formfield_for_dbfield` todos anotados), [accounts/validators/user_validators.py](django_version/accounts/validators/user_validators.py) (`(value: str) -> None` nas três funções).

Sintaxe usada: união com `|` (`str | None`, `Freelancer | None`), genéricos nativos (`dict[str, str]`, `tuple[str, ...]`, `QuerySet[BaseUser]`), sem `from __future__ import annotations` e sem `typing.Optional`/`List`/`Dict`.

---

## 11. SEGURANÇA E AUTENTICAÇÃO

### Mecanismo de autenticação

| Item | Valor | Arquivo |
|---|---|---|
| `AUTH_USER_MODEL` | `"accounts.StaffUser"` | [config/settings.py:40](django_version/config/settings.py#L40) |
| `USERNAME_FIELD` | `"email"` | [accounts/models/base.py:213](django_version/accounts/models/base.py#L213) |
| `REQUIRED_FIELDS` | `["name"]` | [accounts/models/base.py:215](django_version/accounts/models/base.py#L215) |
| Classe base | `AbstractBaseUser` (não `AbstractUser`) | [accounts/models/base.py:151](django_version/accounts/models/base.py#L151) |
| Backend de autenticação | Padrão do Django (`AUTHENTICATION_BACKENDS` não é declarado em `settings.py`) | — |
| Middleware de auth | `django.contrib.auth.middleware.AuthenticationMiddleware` | [config/settings.py:47](django_version/config/settings.py#L47) |
| Sessões | `django.contrib.sessions` + `SessionMiddleware` | [config/settings.py:32,44](django_version/config/settings.py#L32) |
| JWT / Token / OAuth | **NÃO EXISTE** — nenhum pacote de auth por token instalado | — |

`has_perm()` retorna `is_active and is_superuser`; `has_module_perms()` retorna `is_active and is_staff` — [accounts/models/base.py:253-276](django_version/accounts/models/base.py#L253-L276). Não há sistema de permissões granular por objeto ou grupo implementado pelo projeto (`django.contrib.auth.Group` está disponível por vir do Django).

A única superfície autenticada é o Django Admin (seção 5). Não há endpoints públicos de login de API.

### Hash de senha

[config/settings.py:103-106](django_version/config/settings.py#L103-L106):

```python
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
```

Primário: **Argon2** (`argon2-cffi==25.1.0`). Fallback: PBKDF2. Os parâmetros do Argon2 não são customizados — os defaults do `Argon2PasswordHasher` do Django 6.0.7 são usados.

`AUTH_PASSWORD_VALIDATORS` ([config/settings.py:92-99](django_version/config/settings.py#L92-L99)) declara **2 de 4** validadores padrão do Django: `UserAttributeSimilarityValidator` e `CommonPasswordValidator`. `MinimumLengthValidator` e `NumericPasswordValidator` **não estão presentes** — as regras equivalentes existem em `validate_strong_password` ([user_validators.py:104](django_version/accounts/validators/user_validators.py#L104)), que é chamada em `create_user()` mas **não é registrada em `AUTH_PASSWORD_VALIDATORS`** nem em `validators=[...]` de nenhum campo. Consequência: caminhos que não passam por `create_user()` (por exemplo, o formulário de troca de senha do admin) não aplicam `validate_strong_password`.

Senhas no admin: `save_model` chama `set_unusable_password()` quando o campo está vazio ([accounts/admin.py:61-73](django_version/accounts/admin.py#L61-L73)); nenhum dos fieldsets dos 3 admins de conta expõe o campo `password`.

### Tratamento de segredos

| Segredo | Como é tratado | Arquivo |
|---|---|---|
| `SECRET_KEY` | `os.getenv("SECRET_KEY")`, com `raise ValueError` se ausente — sem valor default hardcoded | [config/settings.py:16-18](django_version/config/settings.py#L16-L18) |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD` | `os.getenv(...)` sem default | [config/settings.py:78-80](django_version/config/settings.py#L78-L80) |
| `DB_HOST`, `DB_PORT` | `os.getenv` com defaults `"localhost"` e `"5432"` | [config/settings.py:81-82](django_version/config/settings.py#L81-L82) |
| Arquivo `.env` | Existe no host, **não rastreado** — `git ls-files \| grep '\.env'` retorna somente `django_version/.env.example` | — |
| `.env` no Docker | Excluído do build por [.dockerignore:14](django_version/.dockerignore#L14); injetado em runtime via `env_file` | — |
| `SECRET_KEY` no CI | `${{ secrets.SECRET_KEY }}` | [ci.yml:31](.github/workflows/ci.yml#L31) |
| Credenciais de DB no CI | **Em texto claro no YAML** (`skillbridge_user` / `skillbridge_pass`) | [ci.yml:19-21,32-34](.github/workflows/ci.yml#L19-L21) |

Nenhum segredo foi encontrado hardcoded no código-fonte Python.

### Configurações sensíveis

| Setting | Valor | Linha |
|---|---|---|
| `DEBUG` | `os.getenv("DEBUG", "False") == "True"` — default `False` | [16-21](django_version/config/settings.py#L21) |
| `ALLOWED_HOSTS` | **`[]`** — lista vazia | [23](django_version/config/settings.py#L23) |
| `SECURE_SSL_REDIRECT` | **NÃO DECLARADO** | — |
| `SESSION_COOKIE_SECURE` | **NÃO DECLARADO** | — |
| `CSRF_COOKIE_SECURE` | **NÃO DECLARADO** | — |
| `SECURE_HSTS_SECONDS` | **NÃO DECLARADO** | — |
| `SECURE_PROXY_SSL_HEADER` | **NÃO DECLARADO** | — |
| `X_FRAME_OPTIONS` | **NÃO DECLARADO** (`XFrameOptionsMiddleware` está ativo com o default `DENY` do Django) | [49](django_version/config/settings.py#L49) |
| `STATIC_ROOT` | **NÃO DECLARADO** (só `STATIC_URL = "static/"`) | [123](django_version/config/settings.py#L123) |
| `MEDIA_URL` / `MEDIA_ROOT` | **NÃO DECLARADOS** | — |
| `LANGUAGE_CODE` | `"en-us"` · `TIME_ZONE` `"UTC"` · `USE_I18N` `True` · `USE_TZ` `True` | [111-117](django_version/config/settings.py#L111-L117) |

`ALLOWED_HOSTS = []` com `DEBUG=True` permite `localhost`/`127.0.0.1` (comportamento do Django); com `DEBUG=False` recusaria todo host. Não há configuração de produção (o roadmap prevê isso na TASK 5.1.2, "Security Checklist", sem itens marcados).

### GDPR / logging

`LOGGING` em [config/settings.py:127-180](django_version/config/settings.py#L127-L180): loggers `accounts`, `profiles`, `jobs` em `DEBUG`; `django` em `INFO`; `django.db.backends` em `DEBUG` se `DEBUG` senão `INFO`; handler único de console; formatter `verbose`.

Verificação de PII nos logs — inspeção de todas as chamadas `logger.*` nos arquivos de produção: nenhuma interpola `email`, `name`, `password` ou o valor sendo validado. Os validadores logam comprimento (`len(name_stripped)`, `len(value)`), nunca o valor. `create_user` loga `user.id` ([base.py:94](django_version/accounts/models/base.py#L94)). `SkillAdmin._in_use_summary` reporta apenas a contagem de perfis, nunca os perfis ([profiles/admin.py:101-120](django_version/profiles/admin.py#L101-L120)).

**Ressalva:** `django.db.backends` em nível `DEBUG` (ativo quando `DEBUG=True`) imprime **todo SQL executado, com parâmetros**. Foi observado diretamente na saída do `manage.py makemigrations --check` durante esta auditoria. Em um banco com dados reais, isso colocaria valores de colunas — incluindo `email` e `name` — no console. A proteção contra isso é `DEBUG=False`, não a política de logging da aplicação.

Nenhum middleware de auditoria de acesso a dados existe (as TASKs 3.4.1–3.4.3 do roadmap, "GDPR Compliance — Logging de Acesso", não têm itens marcados).

---

## 12. SPEC-DRIVEN DEVELOPMENT

### Ferramental

GitHub Spec Kit instalado em [.specify/](.specify/): `feature.json`, `init-options.json`, `integration.json`, `integrations/` (2 manifests), `memory/` (constitution), `scripts/`, `templates/` (5 templates), `workflows/workflow-registry.json`.

10 skills `speckit-*` em [.claude/skills/](.claude/skills/): `analyze`, `checklist`, `clarify`, `constitution`, `converge`, `implement`, `plan`, `specify`, `tasks`, `taskstoissues`.

**Constituição do projeto:** [.specify/memory/constitution.md](.specify/memory/constitution.md), versão **1.1.0** (bump de 1.0.0 em 2026-08-09, registrado no Sync Impact Report do próprio arquivo). Contém no mínimo 10 princípios numerados (o Princípio X, "Deactivate, Never Delete", é o alterado no último bump).

### Specs existentes

**1 spec**, em [specs/001-profiles-admin-panel/](specs/001-profiles-admin-panel/) — **4321 linhas em 12 arquivos**:

| Arquivo | Linhas |
|---|---|
| `tasks.md` | 726 |
| `plan_phase-10-remediation_2026-08-06.md` | 910 |
| `spec.md` | 387 |
| `research.md` | 386 |
| `contracts/admin-surface.md` | 309 |
| `plan.md` | 301 |
| `handoff-phase-5.md` | 290 |
| `handoff-phase-4.md` | 255 |
| `data-model.md` | 232 |
| `quickstart.md` | 210 |
| `handoff-phase-10-remediation.md` | 180 |
| `checklists/requirements.md` | 135 |

### Status da spec 001 — Profiles Admin Panel

| Item | Valor | Origem |
|---|---|---|
| Criada | 2026-07-27 | `spec.md:5` |
| Primeiro commit da spec | 2026-08-01 — "docs(spec-kit): add Profiles Admin Panel feature specification" | `git log --reverse -- specs/` |
| Campo `**Status**` em `spec.md:7` | **`Draft`** | `spec.md:7` |
| Branch git dedicada | **NÃO EXISTE** — `spec.md:3` registra: "no git branch was created by this command — current branch is `feature/django-refactor`" | `spec.md:3` |
| Checklist de qualidade | **16/16 marcados, 0 pendentes** | `checklists/requirements.md` |
| Tasks | **79 marcados, 8 pendentes** (87 no total) | `grep -c` em `tasks.md` |

**Status real: EM ANDAMENTO.** Fases 1 a 8 e as fases adicionais 5.1 e 10 estão com todas as tarefas marcadas. A **Fase 9 (Polish & Cross-Cutting Concerns)** está inteiramente pendente — as 8 tarefas desmarcadas são exatamente T060 a T067 (listadas na seção 13).

O campo `**Status**` do `spec.md` continua `Draft` embora 79 de 87 tarefas estejam concluídas — o campo não foi atualizado.

### Fronteira entre código manual e código produzido no fluxo de spec

O diretório `specs/` entrou no repositório em **2026-08-01**. Data de criação de cada arquivo obtida com `git log --reverse --diff-filter=A` por arquivo.

#### (A) Escrito manualmente, ANTES de existir qualquer spec (até 2026-07-31)

Todos os arquivos abaixo foram criados fora do fluxo de SDD:

| Data | Arquivos |
|---|---|
| 2026-02-12 | `config/__init__.py`, `config/asgi.py`, `config/settings.py`, `config/urls.py`, `config/wsgi.py`, `manage.py` |
| 2026-02-13 | `accounts/{__init__,admin,apps,views}.py`, `accounts/models/{__init__,base,client,freelancer}.py`, `accounts/services/__init__.py`, `accounts/tests/__init__.py`, `accounts/validators/__init__.py`, `accounts/migrations/__init__.py` |
| 2026-02-16 | `accounts/validators/user_validators.py`, `accounts/tests/validators/test_validate_email.py` |
| 2026-03-01 | `accounts/tests/validators/test_validate_name.py`, `test_validate_password.py` |
| 2026-03-21 | `accounts/migrations/0001_initial.py`, `accounts/tests/conftest.py`, `accounts/tests/models/test_base.py` |
| 2026-03-27 | `accounts/tests/models/test_client.py`, `test_freelancer.py` |
| 2026-04-05 | `accounts/models/staff_user.py` |
| 2026-05-22 | `accounts/migrations/0002_alter_staffuser_is_staff.py` |
| 2026-05-24 | `profiles/{__init__,admin,apps,views}.py`, `profiles/models/{__init__,base}.py`, `profiles/tests/{__init__,conftest}.py`, `profiles/tests/models/test_base.py`, `profiles/migrations/__init__.py` |
| 2026-05-25 | `profiles/models/skill.py` |
| 2026-05-26 | `profiles/migrations/0001_initial.py`, `0002_seed_skills.py`, `profiles/tests/models/test_skill.py` |
| 2026-05-27 | `profiles/models/freelancer_profile.py` |
| 2026-05-31 | `profiles/migrations/0003_freelancerprofile.py`, `profiles/tests/models/test_freelancer_profile.py` |
| 2026-06-21 | `accounts/migrations/0003_alter_freelancer_options.py`, `0004_alter_client_options.py` |
| 2026-06-22 | `accounts/tests/models/test_staff_user.py` |
| 2026-06-24 | `accounts/migrations/0005…`, `0006_freelancer_freelancer_no_inactive_available.py`, `accounts/tests/admin/test_admin.py` |
| 2026-07-05 | `accounts/migrations/0007_staffuser_staffuser_active_no_staff_status.py` |
| 2026-07-10 / 07-11 | `profiles/migrations/0004_alter_freelancerprofile_bio.py`, `0005_alter_freelancerprofile_options_and_more.py` |
| 2026-07-17 | `profiles/models/client_profile.py`, `profiles/migrations/0006_clientprofile.py` |
| 2026-07-31 | `profiles/tests/models/test_client_profile.py` |

**Total: 55 arquivos** — todo o app `accounts` (models, validadores, manager, admin de contas na sua forma original), todos os 6 models de `profiles`, 13 das 14 migrations, e a maior parte da suíte de testes.

#### (B) Criado DENTRO do fluxo da spec 001 (a partir de 2026-08-01)

`git log --diff-filter=A --since=2026-08-01 -- django_version/`:

| Data | Arquivo | Tarefas da spec |
|---|---|---|
| 2026-08-01 | [profiles/tests/admin/__init__.py](django_version/profiles/tests/admin/__init__.py) | Fase 3 (US1) |
| 2026-08-01 | [profiles/tests/admin/test_skill_admin.py](django_version/profiles/tests/admin/test_skill_admin.py) — 368 linhas, 24 testes | Fase 3 (US1) |
| 2026-08-04 | [accounts/tests/admin/test_client_profile_inline.py](django_version/accounts/tests/admin/test_client_profile_inline.py) — 424 linhas, 27 testes | Fase 5 (US3) |
| 2026-08-04 | [accounts/tests/admin/test_freelancer_profile_inline.py](django_version/accounts/tests/admin/test_freelancer_profile_inline.py) — 448 linhas, 28 testes | Fase 4 (US2) |
| 2026-08-06 | [profiles/migrations/0007_skill_skill_unique_name_case_insensitive.py](django_version/profiles/migrations/0007_skill_skill_unique_name_case_insensitive.py) | Fase 10, T074/T075 |
| 2026-08-09 | [accounts/tests/admin/test_account_list_profile.py](django_version/accounts/tests/admin/test_account_list_profile.py) — 344 linhas, 18 testes | Fases 7 e 8 (US5, US6) |

Um arquivo foi criado e removido dentro do fluxo: `accounts/tests/admin/test_profile_inlines.py`, adicionado em 2026-08-02 e deletado em 2026-08-04, quando foi dividido nos dois arquivos por perfil.

**Total criado no fluxo de spec: 6 arquivos (5 de teste + 1 migration), 1584 linhas de teste, 97 testes** — 32% dos 304 testes da suíte.

#### (C) Modificado DENTRO do fluxo da spec 001 (arquivos que já existiam)

`git log --name-only --since=2026-07-27 -- django_version/` (a spec foi datada 2026-07-27; os commits começam em 2026-08-01):

| Arquivo | Natureza da alteração |
|---|---|
| [accounts/admin.py](django_version/accounts/admin.py) | Recebeu `ProfileInlineForm`, `BaseProfileInline`, `FreelancerProfileInline`, `ClientProfileInline`, `HasProfileFilter`, `SkillInUseFilter`, `ProfilePresenceMixin` e as entradas correspondentes de `list_display`/`list_filter`/`inlines` |
| [profiles/admin.py](django_version/profiles/admin.py) | `SkillAdmin.get_deleted_objects`, `_count_referring_profiles`, `_in_use_summary` |
| [profiles/models/skill.py](django_version/profiles/models/skill.py) | Regra de duplicata case-insensitive em `clean()` + `UniqueConstraint(Lower("name"))` no `Meta` |
| [profiles/models/freelancer_profile.py](django_version/profiles/models/freelancer_profile.py) | `profile_for_inactive_account` em `clean()` + `_get_account()` |
| [profiles/models/client_profile.py](django_version/profiles/models/client_profile.py) | `profile_for_inactive_account` em `clean()` + `_get_account()` |
| [accounts/tests/conftest.py](django_version/accounts/tests/conftest.py) | Fixtures `admin_site_client`, `skill`, `freelancer_profile`, `client_profile` |
| [profiles/tests/conftest.py](django_version/profiles/tests/conftest.py) | Fixtures de perfil de cliente |
| [accounts/tests/admin/test_admin.py](django_version/accounts/tests/admin/test_admin.py), [profiles/tests/models/test_skill.py](django_version/profiles/tests/models/test_skill.py), [profiles/tests/models/test_client_profile.py](django_version/profiles/tests/models/test_client_profile.py), [profiles/tests/models/test_freelancer_profile.py](django_version/profiles/tests/models/test_freelancer_profile.py) | Testes acrescentados/ajustados |

**18 commits** tocaram `django_version/` no período da spec.

#### Resumo da fronteira

- **Fundação (accounts + models de profiles + validadores + manager + admin de contas original): manual, fevereiro a julho de 2026.**
- **Camada de administração de perfis (inlines, filtros, badges, regra case-insensitive de skill, guarda de remoção de skill, invariante de conta inativa) e os 97 testes que a cobrem: produzida no fluxo da spec 001, agosto de 2026.**

Não há outra spec. Nenhum código anterior a 2026-08-01 passou por fluxo de SDD.

---

## 13. O QUE NÃO ESTÁ PRONTO

### 13.1 Marcadores `TODO`, `FIXME`, `HACK`, `XXX` no código

```
$ grep -rn -E '\b(TODO|FIXME|HACK|XXX)\b' --include='*.py' --include='*.yml' --include='*.ini' \
    --include='Dockerfile' django_version/ .github/
(nenhum resultado)
```

**ZERO marcadores no código do projeto.** As 4 ocorrências no repositório inteiro estão em templates do ferramental Spec Kit (`.claude/skills/speckit-constitution/SKILL.md:73` e `:123`, `.claude/skills/speckit-analyze/SKILL.md:133`, `.claude/skills/speckit-clarify/SKILL.md:124`), não em código nem em documentação do projeto.

Uma pendência formal existe fora do código: o Sync Impact Report de [.specify/memory/constitution.md](.specify/memory/constitution.md) lista "Follow-up TODOs: the two ARCHITECTURE.md lines above" (linhas 825 e 951 daquele arquivo). Verificando [ARCHITECTURE.md:828](ARCHITECTURE.md#L828) e [ARCHITECTURE.md:951](ARCHITECTURE.md#L951), ambas já carregam a exceção do `Skill` com o link para o ADR. O follow-up foi resolvido e **a anotação na constituição não foi atualizada**.

### 13.2 Backlog do roadmap — sprints e tasks

Fonte: [docs/ROADMAP_SKILLBRIDGE.md](docs/ROADMAP_SKILLBRIDGE.md), 2014 linhas. O status abaixo é o marcador do próprio cabeçalho quando existe, mais o estado dos checkboxes dentro de cada task, computado por script. Conforme pedido, os itens internos das tasks não são listados.

**FASE 1: FUNDAÇÃO**

| Sprint / Task | Status |
|---|---|
| SPRINT 1.1 — Setup & Infraestrutura Base | — |
| TASK 1.1.1 — Ambiente & Database ✅ CONCLUÍDA | todos os checkboxes marcados |
| TASK 1.1.2 — Docker | todos marcados |
| TASK 1.1.3 — GitHub Actions CI | todos marcados |
| TASK 1.1.4 — README Inicial em Inglês | todos marcados |
| TASK 1.1.5 — accounts/ `user_validators.py` ✅ CONCLUÍDA | todos marcados |
| SPRINT 1.2 — Completar accounts/ | — |
| TASK 1.2.1 — `base.py` BaseUser + BaseUserManager ✅ CONCLUÍDA | todos marcados |
| TASK 1.2.2 — `freelancer.py` ✅ CONCLUÍDA | todos marcados |
| TASK 1.2.3 — `client.py` ✅ CONCLUÍDA | todos marcados |
| TASK 1.2.4 — `staff_user.py` ✅ CONCLUÍDA | todos marcados |
| TASK 1.2.5 — `admin.py` Django Admin ✅ CONCLUÍDA | todos marcados |
| TASK 1.2.6 — AUTH_USER_MODEL & reset de migrações ✅ CONCLUÍDA | todos marcados |

**FASE 2: PROFILES & JOBS**

| Sprint / Task | Status |
|---|---|
| SPRINT 2.1 — App profiles/ | — |
| TASK 2.1.1 — Criar app profiles/ e estrutura ✅ CONCLUÍDA | todos marcados |
| TASK 2.1.2 — `base.py` Profile Abstract Base ✅ CONCLUÍDA | todos marcados |
| TASK 2.1.3a — `skill.py` Skill ✅ CONCLUÍDA | todos marcados |
| TASK 2.1.3b — Testes Skill + Seed ✅ CONCLUÍDA | todos marcados |
| TASK 2.1.4 — `freelancer_profile.py` ✅ CONCLUÍDA | todos marcados |
| TASK 2.1.5a — `client_profile.py` ✅ CONCLUÍDA | todos marcados |
| **TASK 2.1.5b — Testes ClientProfile** | **nenhum checkbox marcado** |
| **TASK 2.1.6 — Migrations & Admin profiles/** | **nenhum checkbox marcado** |
| SPRINT 2.2 — App jobs/ | — |
| **TASK 2.2.1 — Criar app jobs/ e estrutura** | **nenhum marcado** |
| **TASK 2.2.2 — Job Model** | **nenhum marcado** |
| **TASK 2.2.3 — Proposal Model** | **nenhum marcado** |
| **TASK 2.2.X — SDD Tooling Decision Checkpoint (PROCESS GATE)** | **nenhum marcado** |
| **TASK 2.2.4 — StatusHistory Model** | **nenhum marcado** |
| SPRINT 2.3 — Services Layer | — |
| **TASK 2.3.1 — JobService** | **nenhum marcado** |
| **TASK 2.3.2 — ProposalService** | **nenhum marcado** |
| SPRINT 2.4 — Admin Avançado | — |
| **TASK 2.4.1 — Admin jobs/** | **nenhum marcado** |

Observação: as TASKs 2.1.5b e 2.1.6 estão desmarcadas no roadmap, mas [profiles/tests/models/test_client_profile.py](django_version/profiles/tests/models/test_client_profile.py) (26 testes) e [profiles/admin.py](django_version/profiles/admin.py) existem e passam. O roadmap não foi atualizado para esses dois itens.

**FASE 3: API REST — nenhum item marcado em nenhuma task**

| Sprint / Task |
|---|
| SPRINT 3.1 — DRF Setup: TASK 3.1.1 (Instalação e Configuração), TASK 3.1.2 (JWT Endpoints) |
| SPRINT 3.2 — Serializers: TASK 3.2.X (Relocate input normalization ⏳ DEFERRED), TASK 3.2.1 (User Serializers), TASK 3.2.2 (Profile Serializers), TASK 3.2.3 (Job/Proposal Serializers) |
| SPRINT 3.3 — ViewSets e Permissions: TASK 3.3.1 (Custom Permissions), TASK 3.3.2 (User ViewSets), TASK 3.3.3 (Job ViewSets), TASK 3.3.4 (Proposal ViewSets) |
| SPRINT 3.4 — GDPR Compliance: TASK 3.4.1 (Estrutura de Logging), TASK 3.4.2 (Data Access Middleware), TASK 3.4.3 (Security Events Logging) |
| SPRINT 3.5 — Testes de API: TASK 3.5.1 (Factory Boy Setup), TASK 3.5.2 (Testes de Autenticação), TASK 3.5.3 (Testes de Permissions) |
| SPRINT 3.6 — Swagger: TASK 3.6.1 (drf-spectacular Setup) |

**FASE 4: FRONTEND — nenhum item marcado**

| Sprint / Task |
|---|
| SPRINT 4.1 — Templates Funcionais: TASK 4.1.1 (Base e Autenticação), TASK 4.1.2 (Job Listings), TASK 4.1.3 (Proposal Flow) |
| SPRINT 4.2 — Upload e Static Files: TASK 4.2.1 (Static Files), TASK 4.2.2 (Upload de Foto de Perfil) |

**FASE 5: DEPLOY & PORTFÓLIO — nenhum item marcado, exceto 2 de 34 na TASK 5.4.2**

| Sprint / Task | Status |
|---|---|
| SPRINT 5.1 — Preparação para Produção: TASK 5.1.1 (Settings por Ambiente), TASK 5.1.2 (Security Checklist), TASK 5.1.3 (Testes em Modo Produção) | nenhum marcado |
| SPRINT 5.2 — Deploy Railway ou Render: TASK 5.2.1 (Preparar Deploy), TASK 5.2.2 (Deploy Inicial), TASK 5.2.3 (CD no GitHub Actions) | nenhum marcado |
| SPRINT 5.3 — Documentação Final: TASK 5.3.1 (README Profissional Final), TASK 5.3.2 (Code Quality Final) | sem checkboxes / nenhum marcado |
| SPRINT 5.4 — Apresentação Portfólio: TASK 5.4.1 (Demo Video), TASK 5.4.2 (LinkedIn + Portfolio) | sem checkboxes / **2 de 34 marcados** |

**Resumo:** 12 sprints e 45 tasks no roadmap. **19 tasks com todos os itens marcados** (Fases 1 e 2.1 parcial); **26 tasks sem nenhum item marcado**, cobrindo o app `jobs`, a camada de services, toda a API REST, todo o frontend e todo o deploy.

### 13.3 Tarefas pendentes da spec 001

As 8 tarefas desmarcadas em [specs/001-profiles-admin-panel/tasks.md](specs/001-profiles-admin-panel/tasks.md), todas da Fase 9:

| ID | Linha | O que falta |
|---|---|---|
| T060 | 402 | Adicionar `profile_for_inactive_account` à lista *Established invariants* de `.claude/rules/conventions.md` |
| T061 | 403 | Registrar como ADR em `docs/adr/` o estreitamento de FR-021 para as telas de skill |
| T062 | 404 | Adicionar arquivo a `docs/tech_debt/` sobre as telas standalone de perfil adiadas |
| T063 | 405 | Revisar `accounts/admin.py` e `profiles/admin.py` contra o *Code standards* das convenções |
| T064 | 406 | Confirmar ausência de PII nas novas chamadas `logger.error` dos dois arquivos de perfil |
| T065 | 407 | Rodar a suíte completa e comparar com o baseline T004 |
| T066 | 408 | Rodar `makemigrations --check --dry-run` e confirmar "No changes detected" |
| T067 | 409 | Percorrer o `quickstart.md` manual, seções A–F |

Nesta auditoria, T065 e T066 foram executados de fato e ambos passariam (304 passed; "No changes detected"), mas os checkboxes seguem desmarcados.

O campo `**Status**` de `spec.md:7` continua `Draft`, com 79 de 87 tarefas concluídas.

### 13.4 Funcionalidades iniciadas e não terminadas

| Item | Estado | Evidência |
|---|---|---|
| **Camada de serviços de `accounts`** | Diretório [accounts/services/](django_version/accounts/services/) existe com apenas `__init__.py` **vazio** (0 bytes). Nenhum serviço implementado. `profiles/` não tem diretório equivalente. | `git ls-files` + teste de arquivo vazio |
| **App `jobs`** | Logger `jobs` configurado em [config/settings.py:159-163](django_version/config/settings.py#L159-L163), mas o app **não existe** e não está em `INSTALLED_APPS`. Configuração órfã. | `ls django_version/jobs` → não existe |
| **`AppConfig.ready()`** | Ambos ([accounts/apps.py:8](django_version/accounts/apps.py#L8), [profiles/apps.py:8](django_version/profiles/apps.py#L8)) têm docstring descrevendo registro de signals e validadores, e corpo `pass`. Nenhum signal existe no projeto. | leitura direta |
| **Normalização de input na camada serializer** | TASK 3.2.X do roadmap, marcada `⏳ DEFERRED (DRF)`. [ARCHITECTURE.md](ARCHITECTURE.md) ("User Input Normalization") registra que os `.strip()` em `validate_email`, `validate_user_name` e o `name.strip()` de `create_user` estão na camada errada e aguardam o DRF. | ARCHITECTURE.md, roadmap |
| **`validate_strong_password` fora de `AUTH_PASSWORD_VALIDATORS`** | A função existe e é testada (11 testes), mas só é acionada por `create_user()`. Não está registrada em `AUTH_PASSWORD_VALIDATORS` nem em `validators=[...]` de nenhum campo. | seção 11 |
| **`pillow` sem consumidor** | Declarado em `requirements.txt`, instalado no container, sem nenhum `ImageField`/`FileField`/`import PIL` no código. | seção 2b |
| **Markers `slow` e `integration`** | Declarados em `pytest.ini:14-16`, usados por 0 testes. | seção 7 |
| **`docs/plan/`** | Diretório **vazio** — único diretório vazio do repositório fora de `.git`/`.venv`. | `find . -type d -empty` |
| **Painel de profiles ausente da branch default** | `origin/main` está 61 commits atrás. Lá, `profiles/admin.py` ainda é o scaffold de 3 linhas e `accounts/admin.py` não tem inlines, badges nem filtros. Os models de profiles estão presentes desde o merge do PR #4 (2026-07-17); o painel, não. | seção 1 |
| **8 commits locais não enviados** | `git status -sb` → `[ahead 8]`. Parte do que esta auditoria mediu não existe em nenhuma branch remota. | seção 1 |
| **Ref local `main` parado** | `main` local está em `329d1f1` (2026-03-25), sem atualização após o merge feito na interface do GitHub. Não afeta o código; afeta quem medir divergência usando o ref local. | seção 1 |
| **`.claude/rules/sdd-workflow.md `** | Nome de arquivo rastreado **com espaço no final**. | `git ls-files .claude/rules/` |

### 13.5 Views, models ou endpoints que existem mas não são usados

| Item | Situação |
|---|---|
| [accounts/views.py](django_version/accounts/views.py) | 3 linhas, boilerplate do `startapp`, `render` importado e não usado, nenhuma view. Não referenciado em nenhum `urls.py`. |
| [profiles/views.py](django_version/profiles/views.py) | Idem, conteúdo idêntico. |
| `Client.profile` / `Freelancer.profile` (acessores reversos) | São usados — pelos filtros `profile__isnull`, `profile__skills`, `profile__interests` e por `ProfilePresenceMixin.get_queryset`. |
| Models não usados | **Nenhum.** Os 6 models concretos estão registrados no admin, referenciados em relacionamentos ou cobertos por testes. |
| Endpoints não usados | Não aplicável — não existe endpoint próprio (seção 5). |

### 13.6 Arquivos vazios ou apenas com scaffold

**Arquivos rastreados com 0 bytes (11 em `django_version/`):**

`accounts/__init__.py`, `accounts/migrations/__init__.py`, `accounts/services/__init__.py`, `accounts/tests/__init__.py`, `accounts/tests/admin/__init__.py`, `accounts/tests/models/__init__.py`, `accounts/tests/validators/__init__.py`, `config/__init__.py`, `profiles/__init__.py`, `profiles/migrations/__init__.py`, `profiles/tests/admin/__init__.py`.

Dez desses são `__init__.py` de pacote, normais em Python. **`accounts/services/__init__.py` é o único que marca um diretório sem nenhum outro conteúdo.**

Em `oop_version/` (fechado): 10 arquivos vazios, incluindo `src/main.py` (0 bytes) e os `__init__.py` de `src/services/` e `src/storage/`, ambos diretórios sem outro arquivo.

**Arquivos com scaffold não modificado (gerados por `django-admin`):**

| Arquivo | Linhas | Origem |
|---|---|---|
| [accounts/views.py](django_version/accounts/views.py) | 3 | `startapp` — inalterado |
| [profiles/views.py](django_version/profiles/views.py) | 3 | `startapp` — inalterado |
| [config/asgi.py](django_version/config/asgi.py) | 16 | `startproject` — inalterado |
| [config/wsgi.py](django_version/config/wsgi.py) | 16 | `startproject` — inalterado |
| [manage.py](django_version/manage.py) | 22 | `startproject` — inalterado |
| [config/urls.py](django_version/config/urls.py) | 23 | `startproject` — apenas o docstring de 16 linhas é boilerplate; `urlpatterns` tem 1 entrada adicionada |

**Parcialmente modificados:** [accounts/apps.py](django_version/accounts/apps.py) e [profiles/apps.py](django_version/profiles/apps.py) — o `verbose_name` e o método `ready()` com docstring foram acrescentados ao scaffold, mas `ready()` tem corpo `pass`.

**Não existe** `accounts/models.py` nem `profiles/models.py` (o scaffold padrão) — foram substituídos por pacotes `models/`. Também não existem `accounts/tests.py`/`profiles/tests.py` (substituídos por pacotes `tests/`).

### 13.7 Erros ao rodar a suíte

```
$ docker compose exec -T web pytest
============================= 304 passed in 11.36s =============================
```

**Nenhum erro. Nenhuma falha. Nenhum warning. Nenhum teste skipped ou xfailed.** Duas execuções consecutivas, ambas com 304 passed (11.36s e 10.94s).

`makemigrations --check --dry-run` → "No changes detected", exit 0.

### 13.8 Divergências entre documentação e código

Todas verificadas nesta auditoria:

1. `django_version/README.md:16` declara Django 6.0.3; `requirements.txt:5` fixa 6.0.7.
2. `django_version/README.md:3` — badge com `actionsZ/workflows` no link.
3. `django_version/README.md:7,47` linkam `./ARCHITECTURE.md`, que não existe em `django_version/`.
4. `django_version/README.md:91` cita `ROADMAP.md`, arquivo que não existe.
5. Nenhum README menciona o app `profiles`, seus 4 models ou seus 104 testes.
6. `.claude/rules/conventions.md` não lista o code `profile_for_inactive_account` entre os *Established invariants* (spec T060 pendente).
7. O Sync Impact Report da constituição lista follow-up TODOs para `ARCHITECTURE.md` que já foram aplicados.
8. `spec.md:7` diz `Status: Draft` com 79/87 tarefas concluídas.
9. Roadmap: TASKs 2.1.5b e 2.1.6 desmarcadas, embora o código e os testes correspondentes existam e passem.
10. `.gitignore` usa `oop-version/` e `django-version/` (hífen) enquanto os diretórios são `oop_version/` e `django_version/` (underscore). As regras das linhas 10-11, 20-23 e 26-27 não correspondem a nenhum caminho real. `.venv/` acaba ignorado pelo `.gitignore` gerado dentro do próprio venv (`git check-ignore -v django_version/.venv/` → `django_version/.venv/.gitignore:2`), não pela regra da raiz.

---

## 14. RANKING DE COMPLEXIDADE

Critério: tamanho em linhas (`wc -l`), quantidade de classes e funções (contagem por AST), e profundidade de lógica (herança múltipla, sobrescrita de hooks do framework, ramificação condicional). Contagens obtidas por comando; a ordem é minha leitura combinada dos três eixos.

### 1. [django_version/accounts/admin.py](django_version/accounts/admin.py) — 718 linhas

O maior arquivo de produção do projeto, com folga (2,3× o segundo). Concentra 10 classes: 1 base não registrada (`BaseAccountAdmin`), 1 `ModelForm` (`ProfileInlineForm`), 1 base de inline (`BaseProfileInline`), 2 mixins (`StatusBadgeMixin`, `ProfilePresenceMixin`), 2 filtros customizados (`HasProfileFilter`, `SkillInUseFilter`), 2 inlines concretos e 3 `ModelAdmin` registrados. Os dois admins de conta usam herança tripla (`ProfilePresenceMixin, StatusBadgeMixin, BaseAccountAdmin`), com a ordem das bases importando para a resolução de `super().get_queryset()`. Sobrescreve 5 hooks do framework (`has_delete_permission`, `save_model`, `formfield_for_dbfield`, `get_queryset`, `get_readonly_fields`, `full_clean` do form) e implementa 6 actions em massa, três delas com loop de validação por objeto e mensagens pluralizadas via `ngettext`.

### 2. [django_version/accounts/models/base.py](django_version/accounts/models/base.py) — 313 linhas

O núcleo de autenticação. Define `BaseUserManager` (com `create_user` e `create_superuser`, encadeando 3 validadores customizados, normalização, hashing e `full_clean()` explícito antes do `save()`) e o model abstrato `BaseUser` (6 campos, `USERNAME_FIELD`, `has_perm`, `has_module_perms`, a property `user_type` e um `clean()` com duas invariantes que se ramificam pelo tipo da subclasse concreta). Todo model de usuário do projeto herda daqui; a substituição de `AUTH_USER_MODEL` depende deste arquivo.

### 3. [django_version/profiles/models/client_profile.py](django_version/profiles/models/client_profile.py) — 207 linhas

Model concreto de perfil de cliente. 4 campos próprios (incluindo um `OneToOneField(PROTECT)` e um `ManyToManyField`), `get_display_info()` que resolve a relação M2M, `_get_account()` que lê a instância em memória em vez do banco (para enxergar o `is_active` submetido no formset do admin antes da gravação), e um `clean()` com 3 ramos de invariante e 3 codes distintos. É o arquivo de model com mais condicionais.

### 4. [django_version/profiles/models/freelancer_profile.py](django_version/profiles/models/freelancer_profile.py) — 195 linhas

Estrutura equivalente ao anterior para o lado freelancer: 5 campos próprios, `OneToOneField(Freelancer, PROTECT)`, `ManyToManyField(Skill)`, `get_display_info()`, `_get_account()` e `clean()` com 2 ramos (`hourly_rate_not_positive`, `profile_for_inactive_account`). Contém a nota explícita sobre por que a regra de mínimo-uma-skill **não** pode viver em `clean()`.

### 5. [django_version/accounts/validators/user_validators.py](django_version/accounts/validators/user_validators.py) — 181 linhas

Três funções puras, sem dependência de model, que produzem **11 dos códigos de erro** do projeto. `validate_strong_password` sozinha tem 6 ramos condicionais sequenciais, cada um com seu code — o maior número de saídas distintas de qualquer função do projeto. É o arquivo mais denso em regra de negócio por linha e o mais reutilizável (chamado por campos de model via `validators=[...]` e diretamente pelo manager).

> **Menção fora do ranking de produção:** [django_version/accounts/tests/models/test_base.py](django_version/accounts/tests/models/test_base.py), com 503 linhas e 50 testes, é o maior arquivo `.py` do projeto depois de `accounts/admin.py` e cobre o item 2 desta lista.

---

## 15. TABELA DE NÚMEROS VERIFICÁVEIS

| Métrica | Valor | Como foi obtido |
|---|---|---|
| Commits totais | **245** | `git rev-list --count HEAD` |
| Commits em todas as branches | 246 | `git rev-list --count --all` |
| Data do primeiro commit | **2025-12-20 15:54:29 +0100** | `git log --reverse --format='%ad' --date=iso \| head -1` |
| Data do último commit | 2026-08-09 19:31:29 +0200 | `git log -1 --format='%ad' --date=iso` |
| Branches (locais + remotas) | 2 + 2 | `git branch -a` |
| Divergência `origin/main` → `feature/django-refactor` | **1 / 61** (o "1" é o commit de merge do PR #4) | `git rev-list --left-right --count origin/main...feature/django-refactor` |
| HEAD de `origin/main` | `c149ae0`, 2026-07-17T16:04:15Z | API GitHub `/branches/main`, SHA idêntico ao ref local de rastreamento |
| Commits locais não enviados | **8** | `git rev-list --left-right --count origin/feature/django-refactor...HEAD` → `0  8` |
| Funções `def test_` — `origin/main` vs `HEAD` | 137 / 272 | `git show $REF:$f \| grep -c '^def test_'` sobre cada arquivo de teste dos dois refs |
| Arquivos rastreados no repositório | 186 | `git ls-files \| wc -l` |
| **Models concretos** | **6** | introspecção do registry Django no container |
| Models abstratos | 2 | `_meta.abstract` |
| Relacionamentos (`OneToOne` / `M2M` / `FK`) | 2 / 2 / **0** | `_meta.fields` + `_meta.many_to_many` |
| Constraints de banco | 3 | `_meta.constraints` |
| **Migrations** | **14** | `find django_version -path '*/migrations/*.py' \| grep -v __init__ \| wc -l` |
| Skills no seed | 30 | `grep -c '{"name"' profiles/migrations/0002_seed_skills.py` |
| **Endpoints (urlpatterns declarados pelo projeto)** | **1** (`admin/`) | leitura de `config/urls.py` |
| Endpoints (padrões de URL resolvidos, todos do `django.contrib.admin`) | 40 | percurso de `django.urls.get_resolver()` no container |
| Endpoints de API própria | **0** | — |
| Function-based views escritas | 0 | leitura de `accounts/views.py`, `profiles/views.py` |
| Class-based views escritas | 0 | idem |
| Models registrados no admin | 4 | `grep '@admin.register'` |
| Inlines (`StackedInline` / `TabularInline`) | 2 / **0** | `grep 'StackedInline\|TabularInline'` |
| **Testes coletados** | **304** | `docker compose exec -T web pytest --collect-only -q` |
| Testes que passam | **304** | `docker compose exec -T web pytest` → "304 passed in 11.36s" |
| Testes que falham / erram | 0 / 0 | idem |
| Testes skip / xfail | 0 / 0 | `grep -rn 'pytest.mark.skip\|pytest.mark.xfail'` → nenhum |
| Arquivos de teste | 16 (+ 2 `conftest.py`) | `pytest --collect-only -qq \| sed \| uniq -c` |
| Fixtures em `conftest.py` | 20 | `grep -c '@pytest.fixture'` nos dois arquivos |
| **Cobertura (%)** | **NÃO VERIFICADO — `pytest-cov` não instalado, não configurado, e instalá-lo violaria o modo somente-leitura** | `pip list`, `requirements.txt`, `pytest.ini` |
| **Workflows CI** | **1** (`ci.yml`, 1 job, 4 passos) | `ls .github/workflows/` |
| Execuções de CI (total / sucesso / falha) | **26 / 25 / 1** | API GitHub `/actions/runs` |
| Data da última falha de CI | 2026-08-07T12:04:17Z | API GitHub `/actions/runs` |
| **Linhas de Python — `django_version/`** | **7263** | `find django_version -name '*.py' -not -path '*/.venv/*' -not -path '*/__pycache__/*' \| xargs wc -l` |
| — produção (sem testes, sem migrations) | 2507 | `find accounts config profiles -name '*.py' -not -path '*/tests/*' -not -path '*/migrations/*'` |
| — testes | 4330 | `find ... -path '*/tests/*.py'` |
| — migrations | 404 | `find ... -path '*/migrations/*.py'` |
| Linhas de Python — `oop_version/` (fechado) | 3408 | mesmo comando sobre `oop_version` |
| **Linhas de Python — repositório inteiro** | **10671** | 7263 + 3408 |
| Funções/métodos — produção | 54 (51 com anotação de retorno, 94%) | AST no container |
| Funções/métodos — testes | 303 (303 anotados, 100%) | AST no container |
| Classes — produção | 33 | AST no container |
| **Dependências diretas (linhas em `requirements.txt`)** | **19** | `wc -l django_version/requirements.txt` |
| — usadas (import direto ou referência de config) | 7 | análise de `grep` de imports + settings |
| — declaradas e nunca usadas | 1 (`pillow`) | `grep 'ImageField\|FileField\|PIL'` → vazio |
| — transitivas | 11 | por eliminação sobre a lista |
| Pacotes instalados no container | 20 (19 + `pip`) | `docker compose exec -T web pip list` |
| Marcadores `TODO`/`FIXME`/`HACK`/`XXX` no código | **0** | `grep -rn -E '\b(TODO\|FIXME\|HACK\|XXX)\b'` sobre `django_version/` e `.github/` |
| Specs | 1 (12 arquivos, 4321 linhas) | `find specs -type f` + `wc -l` |
| Tarefas da spec 001 (marcadas / pendentes) | 79 / **8** | `grep -c` em `tasks.md` |
| ADRs | 5 | `ls docs/adr/` |
| Registros de dívida técnica | 4 | `ls docs/tech_debt/` |
| Documentos de auditoria anteriores | 6 | `ls docs/audits/` |
| Linhas de documentação (`docs/` + `specs/` + `ARCHITECTURE.md`) | ~9000 | soma dos `wc -l` reportados nas seções 3 e 12 |
| Arquivos rastreados com 0 bytes em `django_version/` | 11 | `git ls-files` + teste `-s` |
| Diretórios vazios | 1 (`docs/plan/`) | `find . -type d -empty` |

---

## LIMITAÇÕES DESTA AUDITORIA

O que **não** foi possível verificar, e por quê:

1. **Percentual de cobertura de testes.** `pytest-cov` e `coverage` não estão em `django_version/requirements.txt` nem instalados no container. Instalá-los alteraria o ambiente, o que a regra de somente-leitura proíbe. O número permanece desconhecido — a contagem de 304 testes e as 4330 linhas de teste **não** são substitutos de cobertura e não devem ser apresentados como tal.

2. **`gh` CLI ausente.** `command not found: gh`. Os dados do GitHub (visibilidade, datas, histórico de execuções de CI) vieram da API pública via `curl`, sem autenticação. Isso limita o histórico de execuções às 100 mais recentes por página — o total de 26 cabe nesse limite, então esse número específico é completo, mas informações que exigem autenticação (logs de execução, motivo exato da falha de 2026-08-07, artefatos, tempos por passo) não foram acessadas.

3. **Causa da única falha de CI.** Sei a data (2026-08-07T12:04:17Z) e a branch, não o motivo. Os logs do run exigem autenticação. Pelo `git log` do mesmo dia há commits `fix(profiles/models): lower both sides of the duplicate check in skill.py` e vários commits de teste, mas **correlacionar esses commits à falha seria inferência** e não foi feito.

4. **Complexidade ciclomática não medida.** Nenhuma ferramenta de análise (`radon`, `mccabe`, `ruff`) está instalada, e instalá-la violaria a regra de somente-leitura. O ranking da seção 14 combina três números obtidos por comando (linhas, classes, funções) com minha leitura da estrutura de cada arquivo. A ordem entre as posições 3 e 4 em particular é uma leitura, não uma medida — os dois arquivos são estruturalmente equivalentes.

5. **Origem do `Dockerfile` (à mão vs. template).** Explicitamente marcado como avaliação na seção 8. Não há como verificar por comando; os quatro indícios listados sustentam a leitura, não a provam.

6. **Qualidade das asserções dos testes.** Contei 304 testes e confirmei que passam. **Não** avaliei se eles testam o que dizem testar, se há testes tautológicos, ou se as asserções são significativas. Vários arquivos de `specs/001-profiles-admin-panel/tasks.md` afirmam que os testes foram "mutation-checked", mas eu não reexecutei nenhuma verificação de mutação.

7. **Comportamento em runtime do admin.** Não abri o Django Admin no navegador nem percorri o `quickstart.md`. A seção 6 descreve o que os arquivos declaram, não o que a interface renderiza. A tarefa T067 da spec (percorrer o quickstart manualmente) continua pendente e essa auditoria não a substitui.

8. **`oop_version/` inspecionado só na superfície.** Contei arquivos (18 em `src/`, 13 em `tests/`) e linhas (3408) e li o README. Não li o código nem rodei a suíte daquela pasta — `CLAUDE.md` classifica o diretório como fechado e proíbe rodar comandos de projeto nele. A alegação de "100 testes" do README **não foi verificada**.

9. **Conteúdo integral dos documentos longos.** `ARCHITECTURE.md` (952 linhas) e a spec 001 (4321 linhas) foram lidos por completo ou por seção conforme necessário; `docs/ROADMAP_SKILLBRIDGE.md` (2014 linhas) foi analisado por script para extrair sprints, tasks e estado dos checkboxes, e lido por amostragem — o conteúdo interno de cada task não foi lido linha a linha, conforme instruído. `docs/ROADMAP_STACK_TRIAGE.md` (551 linhas), `docs/SYSTEM_OVERVIEW.md` (153), os 6 arquivos de `docs/audits/` e os 3 de `docs/spekit_setup/` foram identificados e contados, **não lidos integralmente**.

10. **Segurança em profundidade.** Verifiquei o que `settings.py` declara e o que omite. **Não** rodei `manage.py check --deploy`, não fiz análise estática de segurança, não auditei as dependências contra CVEs conhecidos, e não testei o admin contra nenhum vetor de ataque. A seção 11 é um inventário de configuração, não um teste de penetração.

11. **Estado do banco de dados.** O container `db` está de pé há 3 semanas e contém dados de desenvolvimento. Não os inspecionei — nenhum `SELECT` sobre tabelas de negócio foi executado, apenas as consultas de metadados que o próprio `makemigrations --check` dispara.

12. **`origin/main` foi comparado por conteúdo, não executado.** Sei quais arquivos existem lá, o tamanho de cada um e quantas funções `def test_` contém, tudo via `git ls-tree` e `git show` sem checkout. **Não rodei a suíte naquele ref** — a contagem de testes coletados e o resultado da execução em `origin/main` permanecem desconhecidos. As 137 funções não são comparáveis diretamente aos 304 testes coletados do HEAD.

13. **Erro corrigido durante esta auditoria, registrado aqui por transparência.** A primeira versão deste documento afirmou que a branch default estava 188 commits atrás, parada em 2026-03-25 e sem o app `profiles`. A afirmação vinha do ref **local** `main`, que estava desatualizado; o estado real de `origin/main` é o merge do PR #4 de 2026-07-17, 61 commits atrás. O erro foi de método — uma conclusão sobre estado remoto derivada de estado local — e a seção 1 foi refeita contra `origin/main` e a API do GitHub. Nenhuma outra medição do documento dependia desse ref: tudo o mais foi medido sobre a árvore de trabalho.

14. **A árvore auditada não está inteiramente publicada.** 8 commits existem só nesta máquina (`[ahead 8]`). Este documento descreve o estado local em 2026-08-11, não o estado de nenhuma branch remota.

15. **Erro corrigido após esta auditoria, registrado aqui por transparência.** A verificação de 2026-08-12 (`VERIFICACAO_AUDITORIA_SKILLBRIDGE.md`) encontrou cinco imprecisões no corpo deste documento, todas corrigidas nesta revisão: (1) a seção sobre `clean()` contava um código de invariante a menos do que a própria tabela logo abaixo dela já listava; (2) a partição de testes por categoria subcontava `admin` no tamanho exato de `test_freelancer_profile_inline.py`, isolava numa categoria à parte os testes de `profiles/tests/models/test_base.py` que já estavam contados dentro de `models`, e fechava a soma em 304 com uma categoria residual sem correspondência real — a partição correta, obtida por `pytest --collect-only` por diretório, é `models = 157 · admin = 115 · validators = 32`; (3) e (4) as citações de linha do §13.8 para os links de `ARCHITECTURE.md` e para `ROADMAP.md` em `README.md` apontavam para as linhas erradas; (5) as citações de linha do §13.8 para as regras do `.gitignore` também apontavam para as linhas erradas. Nenhuma outra medição do documento foi alterada.
