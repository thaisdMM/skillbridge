# ROADMAP_STACK_TRIAGE.md

**Gerado em:** 12 June 2026
**Baseline de referência:** `STACK_BASELINE.md` (verification date: 11 June 2026)
**Roadmap analisado:** `ROADMAP_SKILLBRIDGE` v2.0
**Método:** cross-referência exclusiva entre roadmap e baseline já pesquisado.
Nenhum web search novo foi executado. Itens não cobertos pelo baseline são
marcados como 🟡 (pesquisa task-a-task quando o item for atingido).
**Última verificação de follow-up:** 19 July 2026 — ver seção
[FOLLOW-UP](#follow-up--19-july-2026) abaixo. Escopo limitado aos pacotes
já instalados em `requirements.txt`.

> **Este documento é triagem somente.** Sem código, sem correções, sem mudanças
> de arquivo. Toda ação acontece nas sessões task-a-task correspondentes.

---

## FOLLOW-UP — 19 July 2026

**Escopo desta verificação:** apenas os pacotes já pinados em
`django_version/requirements.txt` (ou seja, já instalados). Os itens 🟡
do roadmap referentes a pacotes ainda não instalados (DRF, simplejwt,
drf-spectacular, factory-boy, python-json-logger, whitenoise,
django-environ, django-axes, django-ratelimit, gunicorn, ruff/flake8,
Bootstrap 5) **não foram re-pesquisados** nesta verificação — permanecem
🟡, a pesquisar task-a-task conforme o método original deste documento.
Os itens 🟡 sobre patch level de imagem Docker (`postgres:17`,
`python:3.14-slim`) também não foram re-verificados.

**Método:** `pip index versions <pacote>` executado dentro do container
Docker (`docker-compose exec web`), consultando o índice real do PyPI —
não busca web/resumo de IA. Cross-referenciado com release notes oficiais
(Django, Pillow) para confirmar a natureza de segurança das mudanças.

### Resultado

| Pacote                                            | Flag original (12 Jun)       | Pin antes desta sessão                           | Latest PyPI (19 Jul 2026) | Ação                           |
| ------------------------------------------------- | ---------------------------- | ------------------------------------------------ | ------------------------- | ------------------------------ |
| Django                                            | 🔴 6.0.3 (3 CVEs)            | 6.0.6 (já corrigido pelo usuário entre sessões)  | 6.0.7                     | ✅ Atualizado para 6.0.7       |
| pytest-django                                     | 🔴 4.11.1                    | 4.12.0 (já corrigido pelo usuário entre sessões) | 4.12.0                    | 🟢 Já estava atual, confirmado |
| psycopg / psycopg-binary                          | 🟡 3.3.2                     | 3.3.4 (já corrigido pelo usuário entre sessões)  | 3.3.4                     | 🟢 Já estava atual, confirmado |
| psycopg-pool                                      | não flagado individualmente  | 3.3.1                                            | 3.3.1                     | 🟢 Confirmado atual            |
| pytest                                            | não flagado (🟢)             | 9.0.3                                            | 9.1.1                     | ✅ Atualizado para 9.1.1       |
| pillow                                            | não flagado (🟢, Task 4.2.2) | 12.2.0                                           | 12.3.0                    | ✅ Atualizado para 12.3.0      |
| asgiref                                           | não flagado                  | 3.11.1                                           | 3.12.1                    | ✅ Atualizado para 3.12.1      |
| typing_extensions                                 | não listado                  | 4.15.0                                           | 4.16.0                    | ✅ Atualizado para 4.16.0      |
| cffi                                              | não listado                  | 2.0.0                                            | 2.1.0                     | ✅ Atualizado para 2.1.0       |
| argon2-cffi / bindings                            | não flagado                  | 25.1.0                                           | 25.1.0                    | 🟢 Confirmado atual            |
| python-dotenv                                     | não listado                  | 1.2.2                                            | 1.2.2                     | 🟢 Confirmado atual            |
| sqlparse                                          | não listado                  | 0.5.5                                            | 0.5.5                     | 🟢 Confirmado atual            |
| packaging, iniconfig, pluggy, Pygments, pycparser | não flagados                 | —                                                | —                         | 🟢 Confirmados atuais          |

### Django 6.0.7 — novo release de segurança (não coberto pela flag original)

A flag original ([SECURITY] Django 6.0.3 → 3 CVEs corrigidos em 6.0.5) já
estava resolvida antes desta sessão — o projeto já estava em 6.0.6.
Porém, a 6.0.7 (lançada 7 Jul 2026) corrige **3 novos CVEs de severidade
baixa**, distintos dos anteriores:

- **CVE-2026-48588** — exposição potencial de dados privados via
  `Set-Cookie` cacheado. `UpdateCacheMiddleware` e `cache_page()` só
  protegiam respostas que setavam cookies sensíveis quando a request não
  tinha nenhum cookie; falhava quando a request já carregava cookies não
  relacionados (ex: preferência de idioma/tema).
- **CVE-2026-53877** — heap buffer over-read em `GDALRaster` ao
  instanciar com objetos `bytes` (~32 bytes de over-read). Escopo restrito
  a rasters no virtual filesystem do GDAL — não é uma superfície do
  projeto (SkillBridge não usa GIS), mas corrigido pela atualização.
- **CVE-2026-53878** — header injection via `DomainNameValidator`
  aceitando newlines em nomes de domínio.

Além disso, a 6.0.7 corrige uma regressão introduzida no Django 6.0: os
hashers PBKDF2 e MD5 lançavam `UnicodeDecodeError` para senhas fornecidas
como `bytes` não-UTF-8.

### Pillow 12.3.0 — segurança relevante para Task 4.2.2 (Upload de Foto)

Não coberto pela flag original — a linha original da Task 4.2.2 apenas
confirmava "já instalado, sem gap". A 12.3.0 adiciona proteção contra
decompression bombs (parsing de PDF e FontFile), corrige um command
injection em `WindowsViewer.get_command()`, e corrige múltiplos
out-of-bounds read/write (TGA save, `RankFilter`, paste, color
transforms). Relevante porque `pillow` já está pinado para a Task 4.2.2
(upload de foto de perfil), ainda pendente de implementação.

### Arquivos alterados nesta sessão

- `django_version/requirements.txt` — 6 pins atualizados (ver tabela
  acima).
- `.claude/rules/conventions.md` — tabela "Stack and versions"
  sincronizada (Django 6.0.7, pytest 9.1.1, pillow 12.3.0).
- Imagem Docker `skillbridge-web` reconstruída; suite de testes completa
  re-executada: 161/161 passed.

_Verificação de follow-up — 19 July 2026. Escopo: apenas pacotes já
instalados em `requirements.txt`. Pacotes não instalados (Fases 3-5)
permanecem não re-verificados — seguir o método task-a-task original._

---

## SUMMARY TABLE

| Categoria                        | Contagem (áreas únicas)                                          |
| -------------------------------- | ---------------------------------------------------------------- |
| 🟢 CONFIRMED                     | 22                                                               |
| 🟡 VERIFY (pesquisa task-a-task) | 17                                                               |
| 🔴 PROBLEM                       | 6 (2 resolvidos em 19 Jul 2026 — restam 4 ativos, todos Fase 3+) |
| ⚠️ ARCHITECTURAL CONFLICT        | 3                                                                |

> **Nota (19 Jul 2026):** as contagens acima refletem a triagem original de
> 12 Jun 2026. Os 🔴 de prioridade 1 e 2 (Django, pytest-django) foram
> resolvidos — ver [FOLLOW-UP](#follow-up--19-july-2026). Os 4 🔴 restantes
> (simplejwt, drf-spectacular, factory-boy, django-csp overlap) são de
> pacotes ainda não instalados e permanecem a pesquisar task-a-task.

---

### 🔴 LISTA DE PROBLEMAS — ordem de prioridade de severidade

| Prioridade | Severidade         | Decisão                                                                                                                                                                            | Fases afetadas                  |
| ---------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 1          | [SECURITY]         | ✅ RESOLVIDO (ver [FOLLOW-UP 19 Jul 2026](#follow-up--19-july-2026)) — Django 6.0.3 → 3 CVEs (fixed em 6.0.5). Projeto já em 6.0.6; agora em 6.0.7 (3 novos CVEs low corrigidos).  | TODAS                           |
| 2          | [MAINTENANCE-RISK] | ✅ RESOLVIDO (ver [FOLLOW-UP 19 Jul 2026](#follow-up--19-july-2026)) — `pytest-django==4.11.1` → agora em 4.12.0 (primeira versão com suporte oficial a Django 6.0 + Python 3.14). | 1, 2, 3, 4, 5 (CI sempre ativo) |
| 3          | [MAINTENANCE-RISK] | `djangorestframework-simplejwt==5.5.1` — zero releases desde Django 6.0; incompatibilidade não verificada                                                                          | 3 (Sprints 3.1, 3.5)            |
| 4          | [MAINTENANCE-RISK] | `drf-spectacular==0.29.0` — anterior ao Django 6.0; sub-1.0 instability                                                                                                            | 3 (Sprint 3.6)                  |
| 5          | [MAINTENANCE-RISK] | `factory-boy==3.3.3` — zero releases para Django 6.0 ou Python 3.14                                                                                                                | 3 (Sprint 3.5)                  |
| 6          | [OVERLAP]          | Django 6.0 built-in CSP middleware — substitui `django-csp`                                                                                                                        | 5 (Sprint 5.1)                  |

---

### ⚠️ CONFLITOS ARQUITETURAIS (não são problemas de baseline)

| Task                   | Campo                                                    | Conflito                                            |
| ---------------------- | -------------------------------------------------------- | --------------------------------------------------- |
| 2.2.2 — Job Model      | `client = ForeignKey(Client, on_delete=CASCADE)`         | CASCADE contradiz ARCHITECTURE.md e conventions.md. |
| 2.2.3 — Proposal Model | `job = ForeignKey(Job, on_delete=CASCADE)`               | Idem.                                               |
| 2.2.3 — Proposal Model | `freelancer = ForeignKey(Freelancer, on_delete=CASCADE)` | Idem.                                               |

Ver seção detalhada no final do documento.

---

## TRIAGEM POR FASE

---

### FASE 1 — FUNDAÇÃO (Semanas 1–2)

#### SPRINT 1.1 — Setup & Infraestrutura Base

##### TASK 1.1.1 — Ambiente & Database ✅ CONCLUÍDA

| Flag                   | Decisão                                      | Razão                                                                                                                                                                                                                                                                                                                         | Ref. baseline     |
| ---------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| 🟢                     | psycopg3 + connection pooling                | psycopg3 é o adapter recomendado; psycopg2 está em maintenance-only. Uso correto.                                                                                                                                                                                                                                             | §5                |
| 🟢                     | PostgreSQL 17 como banco de dados            | Suportado, bugfix até Novembro 2029.                                                                                                                                                                                                                                                                                          | §6                |
| 🟡                     | PostgreSQL 17 — patch level da imagem Docker | A imagem `postgres:17` pode não estar na 17.10, que corrigiu 11 vulnerabilidades de segurança em 4 Jun 2026. Verificar política de tag do Docker Hub quando o ambiente for atualizado.                                                                                                                                        | §6, "Project gap" |
| ✅ (era 🟡)            | `psycopg==3.3.2` — 2 patches atrás           | RESOLVIDO (ver [FOLLOW-UP 19 Jul 2026](#follow-up--19-july-2026)): projeto agora em 3.3.4, confirmado como latest no PyPI.                                                                                                                                                                                                    | §5, "Project gap" |
| ✅ (era 🔴 [SECURITY]) | `Django==6.0.3` — instalado em toda a Fase 1 | RESOLVIDO (ver [FOLLOW-UP 19 Jul 2026](#follow-up--19-july-2026)). A 6.0.5 corrigiu 3 CVEs (**CVE-2026-5766**, **CVE-2026-35192**, **CVE-2026-6907**); o projeto já estava em 6.0.6 antes desta sessão e agora está em **6.0.7**, que corrige 3 novos CVEs low (CVE-2026-48588, -53877, -53878) + regressão PBKDF2/MD5 bytes. | §2, "Project gap" |

##### TASK 1.1.2 — Docker ✅ CONCLUÍDA

| Flag | Decisão                                          | Razão                                                                                                                                                                          | Ref. baseline     |
| ---- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------- |
| 🟡   | `python:3.14-slim` base image — patch não fixado | Última versão da série é 3.14.6 (10 Jun 2026). O patch real na imagem depende do pull cadence do Docker Hub. Não é blocking, mas vale confirmar junto com o upgrade do Django. | §1, "Project gap" |

##### TASK 1.1.3 — GitHub Actions CI ✅ CONCLUÍDA

| Flag | Decisão                                   | Razão                                                                                             | Ref. baseline     |
| ---- | ----------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------- |
| 🟡   | PostgreSQL 17 como service no CI workflow | Mesmo risco de patch que em 1.1.1. Verificar se a tag usada alcança o 17.10 (11 CVEs corrigidos). | §6, "Project gap" |
| 🟢   | GitHub Actions como plataforma CI/CD      | Padrão da indústria. Sem impacto de baseline.                                                     | —                 |

##### TASK 1.1.4 — README ✅ CONCLUÍDA — nenhuma decisão técnica de biblioteca a triar.

---

#### SPRINT 1.2 — Completar accounts/

##### TASK 1.2.1 — Models ✅ CONCLUÍDA

| Flag | Decisão                                                   | Razão                                                                                                                                                                                                                                                                                     | Ref. baseline                                         |
| ---- | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 🟢   | Abstract Base Classes (ABC) sobre Multi-Table Inheritance | Decisão arquitetural confirmada. Nenhum impacto de baseline.                                                                                                                                                                                                                              | —                                                     |
| 🟢   | `AUTH_USER_MODEL = "accounts.StaffUser"`                  | Nenhum impacto de baseline.                                                                                                                                                                                                                                                               | —                                                     |
| 🟢   | Argon2id via `argon2-cffi==25.1.0`                        | Versão atual. Suporte explícito ao Python 3.14 confirmado upstream: "No code changes were necessary."                                                                                                                                                                                     | §10                                                   |
| 🟢   | PBKDF2 como hasher de fallback                            | Django 6.0 aumentou o iteration count do PBKDF2 de 1.000.000 para 1.200.000. Não afeta o projeto: Argon2id é o hasher primário; PBKDF2 é fallback de compatibilidade apenas.                                                                                                              | §2, "New features"                                    |
| 🟢   | `asgiref==3.11.1`                                         | Django 6.0 exige mínimo 3.9.1. O projeto está em 3.11.1. Sem gap.                                                                                                                                                                                                                         | §2, "Miscellaneous"                                   |
| 🟢   | `sqlparse==0.5.5`                                         | Django 6.0 referencia 0.5.0 como compatível com Python 3.12+. O projeto está acima disso. Sem gap.                                                                                                                                                                                        | §2                                                    |
| 🟡   | `DEFAULT_AUTO_FIELD` — setting em `settings.py`           | Django 6.0 mudou o default de `AutoField` para `BigAutoField`. Se `settings.py` não declarar explicitamente este setting, todos os modelos (incluindo os já migrados) usam BigAutoField silenciosamente. Verificar se o comportamento é intencional ou se o setting deve ser explicitado. | §2, "DEFAULT_AUTO_FIELD now defaults to BigAutoField" |

##### TASK 1.2.2 — Testes accounts/ ✅ CONCLUÍDA (75 testes)

| Flag                           | Decisão                 | Razão                                                                                                                                                                                                                                     | Ref. baseline     |
| ------------------------------ | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| ✅ (era 🔴 [MAINTENANCE-RISK]) | `pytest-django==4.11.1` | RESOLVIDO (ver [FOLLOW-UP 19 Jul 2026](#follow-up--19-july-2026)): projeto agora em **4.12.0**, a primeira versão com classifiers explícitos de Django 6.0 + Python 3.14. Confirmado como latest no PyPI. Suite completa: 161/161 passed. | §8, "Project gap" |
| 🟢                             | `pytest==9.0.2`         | Versão suficiente; mínimo exigido pelo pytest-django é pytest>=7.0. Sem impacto de baseline. Nota (19 Jul 2026): atualizado para 9.1.1 nesta sessão.                                                                                      | §8                |

##### TASK 1.2.3 — Django Admin ✅ CONCLUÍDA

| Flag | Decisão                                                                      | Razão                                         | Ref. baseline |
| ---- | ---------------------------------------------------------------------------- | --------------------------------------------- | ------------- |
| 🟢   | `has_delete_permission = False` em todos os admins                           | Padrão arquitetural. Sem impacto de baseline. | —             |
| 🟢   | `@admin.register` decorator + `list_display`, `list_filter`, `search_fields` | API admin estável.                            | —             |
| 🟢   | `TabularInline` / `StackedInline`                                            | API admin estável.                            | —             |

##### TASKS 1.2.4 e 1.2.5 ✅ CONCLUÍDAS — todos os flags já cobertos acima.

---

### FASE 2 — PROFILES & JOBS (Semanas 3–4)

#### SPRINT 2.1 — App profiles/

##### TASK 2.1.1 — Criar app profiles/ ✅ CONCLUÍDA — sem decisões de biblioteca a triar.

##### TASK 2.1.2 — Profile Abstract Base ✅ CONCLUÍDA

| Flag | Decisão                                            | Razão                                                                                                                                                                                                                                                                                                                                                        | Ref. baseline                 |
| ---- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------- |
| 🟢   | `abstract = True` em `Profile`                     | Padrão arquitetural confirmado.                                                                                                                                                                                                                                                                                                                              | —                             |
| 🟡   | `URLField` — mudança de scheme padrão (Django 6.0) | Django 6.0 mudou o default scheme de `forms.URLField` de `'http'` para `'https'`. `models.URLField` é backed por `forms.URLField` em ModelForms e serializers DRF. Ao implementar o serializer de `FreelancerProfile` (Sprint 3.2), verificar se o comportamento de validação de URLs sem scheme está alinhado com o esperado. Afeta também `ClientProfile`. | §2, "Features removed in 6.0" |

##### TASKS 2.1.3a / 2.1.3b / 2.1.3c — Skill + Testes + Fix ✅ CONCLUÍDAS

| Flag | Decisão                                              | Razão                                                      | Ref. baseline |
| ---- | ---------------------------------------------------- | ---------------------------------------------------------- | ------------- |
| 🟢   | `Skill` como vocabulário controlado gerido por admin | Decisão arquitetural. Sem impacto de baseline.             | —             |
| 🟢   | `bulk_create(ignore_conflicts=True)` no seed         | API Django estável. Padrão documentado em ARCHITECTURE.md. | —             |

##### TASK 2.1.4 — FreelancerProfile ✅ CONCLUÍDA

| Flag | Decisão                                        | Razão                                                                                                                          | Ref. baseline |
| ---- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------- |
| 🟢   | `OneToOneField(Freelancer, on_delete=PROTECT)` | Correto per ARCHITECTURE.md. Confirmado.                                                                                       | —             |
| 🟢   | `ManyToManyField(Skill, blank=True)`           | Padrão estável.                                                                                                                | —             |
| 🟡   | `portfolio_url = URLField(blank=True)`         | Ver flag de URLField em Task 2.1.2. O campo já existe; o comportamento de validação deve ser confirmado ao criar o serializer. | §2            |

##### TASK 2.1.5 — ClientProfile ⏳ (em andamento)

| Flag | Decisão                                               | Razão                        | Ref. baseline |
| ---- | ----------------------------------------------------- | ---------------------------- | ------------- |
| 🟢   | `OneToOneField(Client, on_delete=PROTECT)`            | Correto per ARCHITECTURE.md. | —             |
| 🟢   | `ManyToManyField(Skill, blank=True)` para `interests` | Padrão estável.              | —             |

##### TASK 2.1.6 — Migrations & Admin profiles/ ⬜ (pendente)

| Flag | Decisão                                      | Razão              | Ref. baseline |
| ---- | -------------------------------------------- | ------------------ | ------------- |
| 🟢   | `TabularInline` no Admin para Profile inline | API admin estável. | —             |

---

#### SPRINT 2.2 — App jobs/

##### TASK 2.2.1 — Criar app jobs/ ⬜ (pendente) — sem decisões de biblioteca a triar.

##### TASK 2.2.2 — Job Model ⬜ (pendente)

| Flag             | Decisão                                                                     | Razão                                                                                                                    | Ref. baseline                 |
| ---------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------- |
| ⚠️ ARCH CONFLICT | `client = ForeignKey(Client, on_delete=CASCADE)`                            | CASCADE não é uma questão de baseline; é um conflito interno com ARCHITECTURE.md. Ver seção "Architectural Conflicts".   | ARCHITECTURE.md               |
| 🟢               | `TextChoices` para status (`OPEN`, `IN_PROGRESS`, `COMPLETED`, `CANCELLED`) | API moderna Django. `ChoicesMeta` foi removido em Django 6.0, mas o projeto usa corretamente `TextChoices`. Sem impacto. | §2, "Features removed in 6.0" |
| 🟢               | `ManyToManyField(Skill, blank=True)` para `required_skills`                 | Padrão estável.                                                                                                          | —                             |
| 🟢               | `UniqueConstraint` em `Meta.constraints` (não `unique_together`)            | Correto. `unique_together` está deprecated desde Django 4.2. `UniqueConstraint` é o padrão atual e suportado.            | §2                            |

##### TASK 2.2.3 — Proposal Model ⬜ (pendente)

| Flag             | Decisão                                                      | Razão                                                                                                                                                                                                                                                                                                                                                      | Ref. baseline         |
| ---------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| ⚠️ ARCH CONFLICT | `job = ForeignKey(Job, on_delete=CASCADE)`                   | CASCADE proibido per ARCHITECTURE.md. Ver seção "Architectural Conflicts".                                                                                                                                                                                                                                                                                 | ARCHITECTURE.md       |
| ⚠️ ARCH CONFLICT | `freelancer = ForeignKey(Freelancer, on_delete=CASCADE)`     | Idem.                                                                                                                                                                                                                                                                                                                                                      | ARCHITECTURE.md       |
| 🟢               | `UniqueConstraint` para 1 freelancer = 1 proposta por job    | Correto e moderno.                                                                                                                                                                                                                                                                                                                                         | —                     |
| 🟡               | `UniqueConstraint` + DRF validation — `violation_error_code` | DRF 3.17.0 adicionou suporte a `violation_error_code` e `violation_error_message` de `UniqueConstraint` no `UniqueTogetherValidator`. Quando implementar o serializer de `Proposal` (Sprint 3.2), usar essa feature para propagar os error codes customizados do model constraint para a response da API, alinhado com o padrão de error codes do projeto. | §3, "3.17.0 features" |

##### TASK 2.2.4 — StatusHistory Model ⬜ (pendente)

| Flag | Decisão                                             | Razão                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Ref. baseline                    |
| ---- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| 🟡   | Django Signals (`post_save`) para audit trail       | Django 6.0 introduziu um Background Tasks framework (`django.tasks`) com decorator `@task()` e queue mechanism. As duas features têm casos de uso distintos: **Signals** são síncronos, em-linha com a transação do save, corretos para audit trail atômico. **Background Tasks** são para trabalho assíncrono diferido que requer worker separado (ex: envio de email, geração de relatório). Para `StatusHistory`, Signals continuam sendo a escolha correta. Confirmar conscientemente ao iniciar a implementação desta task — é o trigger point para re-avaliação de SDD tooling. | §2, "Background Tasks framework" |
| 🟢   | `changed_by = ForeignKey(settings.AUTH_USER_MODEL)` | Padrão correto; não importa o model diretamente.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | —                                |

---

#### SPRINT 2.3 — Services Layer

##### TASKS 2.3.1 e 2.3.2 — JobService e ProposalService ⬜ (pendentes)

| Flag | Decisão                                         | Razão                                                                 | Ref. baseline |
| ---- | ----------------------------------------------- | --------------------------------------------------------------------- | ------------- |
| 🟢   | `@transaction.atomic` para operações multi-step | API Django estável e correta para garantir consistência transacional. | —             |
| 🟢   | `Q` objects para filtros complexos em QuerySet  | API Django estável.                                                   | —             |
| 🟢   | Service Layer separado dos models               | Padrão arquitetural sem impacto de baseline.                          | —             |

---

#### SPRINT 2.4 — Admin Avançado

##### TASK 2.4.1 — Admin jobs/ ⬜ (pendente)

| Flag | Decisão                                                    | Razão                     | Ref. baseline |
| ---- | ---------------------------------------------------------- | ------------------------- | ------------- |
| 🟢   | `list_display`, `list_filter`, `search_fields`             | API admin Django estável. | —             |
| 🟢   | `TabularInline` para `Proposal` e `StatusHistory` readonly | API admin estável.        | —             |
| 🟢   | `@admin.action` para bulk actions                          | Decorator moderno.        | —             |

---

### FASE 3 — API REST (Semanas 5–7)

#### SPRINT 3.1 — DRF Setup

##### TASK 3.1.1 — Instalação e Configuração ⬜ (pendente)

| Flag                  | Decisão                                                           | Razão                                                                                                                                                                                                                                                                                                            | Ref. baseline                                                                                          |
| --------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| 🟡                    | `djangorestframework` — versão a pinnar                           | A primeira versão com suporte oficial ao Django 6.0 + Python 3.14 é a **3.17.0** (18 Mar 2026). Versão atual: **3.17.1** (24 Mar 2026). Pin obrigatório: `djangorestframework==3.17.1`. Versões anteriores (toda a série 3.16.x) não suportam oficialmente Django 6.0. Não usar "latest" nem range aberto.       | §3, "DRF 3.17.0 was the first release to add official support for Django 6.0 and Python 3.14"          |
| 🔴 [MAINTENANCE-RISK] | `djangorestframework-simplejwt`                                   | Última versão: **5.5.1** (21 Jul 2025). **Zero releases** desde o Django 6.0 (3 Dez 2025) e Python 3.14 (7 Out 2025). Compatibilidade com Django 6.0 + Python 3.14 + DRF 3.17 **não confirmada oficialmente** pelo maintainer. Pesquisa aprofundada obrigatória antes de instalar.                               | §4, "Compatibility with Django 6.0 and Python 3.14 is not officially confirmed by an upstream release" |
| 🔴 [MAINTENANCE-RISK] | `drf-spectacular`                                                 | Última versão: **0.29.0** (1 Nov 2025), lançada **antes** do Django 6.0 (3 Dez 2025). Compatibilidade com Django 6.0 não declarada no changelog nem no README. Agravante: o projeto mantém política sub-1.0 — "every new version may potentially break you." Pesquisa aprofundada obrigatória antes de instalar. | §7, release status + stability warning                                                                 |
| 🟢                    | `DEFAULT_PERMISSION_CLASSES: IsAuthenticated`                     | DRF pattern estável.                                                                                                                                                                                                                                                                                             | —                                                                                                      |
| 🟢                    | `DEFAULT_PAGINATION_CLASS: PageNumberPagination`, `PAGE_SIZE: 20` | DRF patterns estáveis.                                                                                                                                                                                                                                                                                           | —                                                                                                      |

##### TASK 3.1.2 — JWT Endpoints ⬜ (pendente)

| Flag                  | Decisão                                               | Razão                                                                                                                                               | Ref. baseline |
| --------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| 🔴 [MAINTENANCE-RISK] | `POST /api/auth/token/` e endpoints JWT via simplejwt | Dependência direta de simplejwt (flag acima em 3.1.1). Todos os endpoints JWT herdam o risco de incompatibilidade não verificada com o stack atual. | §4            |

---

#### SPRINT 3.2 — Serializers

##### TASKS 3.2.1–3.2.3 ⬜ (pendentes)

| Flag | Decisão                                                               | Razão                                                                                                                                                                                                                                                                                                                                                                         | Ref. baseline         |
| ---- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| 🟢   | `write_only=True` para password em serializers                        | DRF pattern estável.                                                                                                                                                                                                                                                                                                                                                          | —                     |
| 🟢   | Nested serializers                                                    | DRF pattern estável.                                                                                                                                                                                                                                                                                                                                                          | —                     |
| 🟢   | `SerializerMethodField` para campos calculados                        | DRF pattern estável.                                                                                                                                                                                                                                                                                                                                                          | —                     |
| 🟡   | `UniqueConstraint` → `violation_error_code` no serializer de Proposal | DRF 3.17.0 adicionou suporte a `violation_error_code` e `violation_error_message` de `UniqueConstraint` no `UniqueTogetherValidator`. Ao implementar o serializer de `Proposal`, usar essa feature para propagar o error code do constraint diretamente para a API response, alinhado com a política de error codes do projeto (assertions nos códigos, nunca nas mensagens). | §3, "3.17.0 features" |

---

#### SPRINT 3.3 — ViewSets e Permissions

##### TASKS 3.3.1–3.3.4 ⬜ (pendentes)

| Flag | Decisão                                                         | Razão                | Ref. baseline |
| ---- | --------------------------------------------------------------- | -------------------- | ------------- |
| 🟢   | `BasePermission` para `IsClient`, `IsFreelancer`, `IsOwner`     | DRF pattern estável. | —             |
| 🟢   | `has_permission()` vs `has_object_permission()`                 | API DRF estável.     | —             |
| 🟢   | Filtros por QueryString (`?skill=`, `?max_budget=`, `?status=`) | DRF pattern estável. | —             |

---

#### SPRINT 3.4 — GDPR Compliance (Logging de Acesso)

##### TASK 3.4.1 — Estrutura de Logging ⬜ (pendente)

| Flag | Decisão              | Razão                                                                                                                                                                                                                | Ref. baseline       |
| ---- | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| 🟡   | `python-json-logger` | Não coberto pelo baseline. Pesquisar compatibilidade com Python 3.14 (em particular o impacto do PEP 649 — deferred annotation evaluation — em bibliotecas que introspectem annotations) quando a task for iniciada. | Baseline: não cobre |

##### TASK 3.4.2 — Data Access Middleware ⬜ (pendente)

| Flag | Decisão                                                | Razão                                                                                                                                                                                                                                                                                        | Ref. baseline                          |
| ---- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| 🟢   | Custom Django middleware para GDPR data access logging | Middleware custom para registrar _quem_ acedeu _quais_ dados pessoais é a abordagem correta para este caso. **Não há overlap** com o `ContentSecurityPolicyMiddleware` introduzido no Django 6.0, que gerencia HTTP headers de segurança (Content-Security-Policy) — preocupações distintas. | §2, "Content Security Policy built-in" |

##### TASK 3.4.3 — Security Events Logging ⬜ (pendente)

| Flag | Decisão                                                              | Razão                                                     | Ref. baseline |
| ---- | -------------------------------------------------------------------- | --------------------------------------------------------- | ------------- |
| 🟢   | Django Signals para auth events (login, failed login, access denied) | Pattern correto para interceptar eventos de autenticação. | —             |

---

#### SPRINT 3.5 — Testes de API

##### TASK 3.5.1 — Factory Boy Setup ⬜ (pendente)

| Flag                  | Decisão       | Razão                                                                                                                                                                                                                                                                                                                                              | Ref. baseline                                                                                           |
| --------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 🔴 [MAINTENANCE-RISK] | `factory-boy` | Última versão released: **3.3.3** (3 Feb 2025). **Zero releases** desde Django 6.0 (3 Dez 2025) ou Python 3.14 (7 Out 2025). O changelog do repositório mostra `3.3.4 (unreleased)` adicionando apenas Django 5.2 — Django 6.0 e Python 3.14 não têm cobertura em **nenhuma versão released**. Pesquisa aprofundada obrigatória antes de instalar. | §9, "No release has occurred since Django 6.0 (3 Dec 2025) and Python 3.14 (7 Oct 2025) were published" |

##### TASKS 3.5.2–3.5.3 — Testes de Autenticação e Permissions ⬜ (pendentes)

| Flag                  | Decisão                                 | Razão                                                                                                                             | Ref. baseline |
| --------------------- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| 🟢                    | DRF `APIClient` para testes de endpoint | DRF pattern estável.                                                                                                              | —             |
| 🔴 [MAINTENANCE-RISK] | Testes de JWT (token endpoints)         | Dependência indireta de simplejwt. Se simplejwt tiver incompatibilidade com o stack, os testes de autenticação herdam o problema. | §4            |

---

#### SPRINT 3.6 — Swagger Documentation

##### TASK 3.6.1 — drf-spectacular Setup ⬜ (pendente)

| Flag                  | Decisão                   | Razão                                                                                                                                                                                                                                                                                                                                                           | Ref. baseline                                               |
| --------------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| 🔴 [MAINTENANCE-RISK] | `drf-spectacular==0.29.0` | Lançado em 1 Nov 2025, **anterior** ao Django 6.0 (3 Dez 2025). Nenhuma declaração de suporte ao Django 6.0 no changelog ou README upstream. Agravante adicional: política sub-1.0 explícita — "every new version may potentially break you" — o projeto recomenda pinning e diff de schema em cada update. Pesquisa aprofundada obrigatória antes de instalar. | §7, release status + "Release management" stability warning |

---

### FASE 4 — FRONTEND (Semanas 8–9)

#### SPRINT 4.1 — Templates Funcionais

##### TASK 4.1.1 — Base e Autenticação ⬜ (pendente)

| Flag | Decisão                                                    | Razão                                                                                              | Ref. baseline       |
| ---- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------- |
| 🟡   | Bootstrap 5 via CDN                                        | Não coberto pelo baseline. Verificar versão atual e integridade de CDN quando a task for iniciada. | Baseline: não cobre |
| 🟢   | Django template engine (`base.html`, herança de templates) | API Django estável.                                                                                | —                   |

##### TASKS 4.1.2–4.1.3 — Job Listings e Proposal Flow ⬜ (pendentes)

| Flag | Decisão                                    | Razão                                                                                                                                                                                                                                                                                                                                                                                                          | Ref. baseline           |
| ---- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| 🟢   | `ModelForm` para formulários               | API Django estável.                                                                                                                                                                                                                                                                                                                                                                                            | —                       |
| 🟢   | `LoginRequiredMixin` para views protegidas | API Django estável.                                                                                                                                                                                                                                                                                                                                                                                            | —                       |
| 🟢   | Django messages framework                  | API Django estável.                                                                                                                                                                                                                                                                                                                                                                                            | —                       |
| 🟡   | Template Partials (Django 6.0 built-in)    | Django 6.0 introduziu as tags `{% partialdef %}` e `{% partial %}` nativas, que substituem o pacote third-party `django-template-partials`. O roadmap não planeja instalar `django-template-partials`, mas ao implementar os templates (Phase 4), vale avaliar o uso das partials nativas para componentes reutilizáveis (navbar, cards, pagination). Não é blocking, mas evita uma dependência desnecessária. | §2, "Template Partials" |

---

#### SPRINT 4.2 — Upload e Static Files

##### TASK 4.2.1 — Static Files ⬜ (pendente)

| Flag | Decisão                                     | Razão                                                                                                                                                                        | Ref. baseline       |
| ---- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| 🟡   | `whitenoise` para servir static em produção | Não coberto pelo baseline. Pesquisar compatibilidade com Django 6.0 + Python 3.14 quando a task for iniciada. Escolha comum para Railway/Render, mas precisa de confirmação. | Baseline: não cobre |

##### TASK 4.2.2 — Upload de Foto de Perfil ⬜ (pendente)

| Flag        | Decisão                                            | Razão                                                                                                                                                                                                                                                                                                 | Ref. baseline    |
| ----------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| ✅ (era 🟢) | `Pillow` para validação e processamento de imagens | Nota (19 Jul 2026, ver [FOLLOW-UP](#follow-up--19-july-2026)): estava em 12.2.0; atualizado para **12.3.0**, que traz segurança relevante para esta task — proteção contra decompression bombs (PDF/FontFile), fix de command injection em `WindowsViewer.get_command()`, e múltiplos OOB read/write. | requirements.txt |

---

### FASE 5 — DEPLOY & PORTFÓLIO (Semanas 10–12)

#### SPRINT 5.1 — Preparação para Produção

##### TASK 5.1.1 — Settings por Ambiente ⬜ (pendente)

| Flag | Decisão          | Razão                                                                                           | Ref. baseline       |
| ---- | ---------------- | ----------------------------------------------------------------------------------------------- | ------------------- |
| 🟡   | `django-environ` | Não coberto pelo baseline. Pesquisar compatibilidade com Django 6.0 quando a task for iniciada. | Baseline: não cobre |

##### TASK 5.1.2 — Security Checklist ⬜ (pendente)

| Flag         | Decisão                                                            | Razão                                                                                                                                                                                                                                                                                                                                                                   | Ref. baseline                                                                                     |
| ------------ | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| 🟢           | `SECURE_HSTS_SECONDS`, `SECURE_SSL_REDIRECT`                       | Django built-in security settings. Estáveis.                                                                                                                                                                                                                                                                                                                            | —                                                                                                 |
| 🟢           | `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`                      | Django built-in security settings. Estáveis.                                                                                                                                                                                                                                                                                                                            | —                                                                                                 |
| 🟢           | `python manage.py check --deploy`                                  | Comando Django built-in estável.                                                                                                                                                                                                                                                                                                                                        | —                                                                                                 |
| 🔴 [OVERLAP] | Content Security Policy — `django-csp` (third-party)               | Django 6.0 introduziu `ContentSecurityPolicyMiddleware` nativo com settings `SECURE_CSP` e `SECURE_CSP_REPORT_ONLY`, **substituindo** a necessidade do pacote `django-csp`. O roadmap não cita `django-csp` explicitamente, mas a security checklist tipicamente o inclui. Ao atingir esta task, usar o built-in do Django 6.0 em vez de instalar o pacote third-party. | §2, "Content Security Policy built-in. Replaces the need for the django-csp third-party package." |
| 🟡           | `django-axes` para brute force protection                          | Não coberto pelo baseline. Pesquisar compatibilidade com Django 6.0 quando a task for iniciada.                                                                                                                                                                                                                                                                         | Baseline: não cobre                                                                               |
| 🟡           | `django-ratelimit` para rate limiting em endpoints de autenticação | Não coberto pelo baseline. Pesquisar compatibilidade com Django 6.0 quando a task for iniciada.                                                                                                                                                                                                                                                                         | Baseline: não cobre                                                                               |

##### TASK 5.1.3 — Testes em Modo Produção ⬜ (pendente)

| Flag | Decisão                                   | Razão                                    | Ref. baseline |
| ---- | ----------------------------------------- | ---------------------------------------- | ------------- |
| 🟢   | Rodar testes com `settings/production.py` | Prática padrão. Sem impacto de baseline. | —             |

---

#### SPRINT 5.2 — Deploy

##### TASK 5.2.1 — Preparar Deploy ⬜ (pendente)

| Flag | Decisão                     | Razão                                                                                                                                                                                   | Ref. baseline       |
| ---- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| 🟡   | `gunicorn` como WSGI server | Não coberto pelo baseline. Pesquisar compatibilidade com Django 6.0 + Python 3.14 quando a task for iniciada. É a escolha padrão para Railway/Render, mas requer confirmação de versão. | Baseline: não cobre |
| 🟢   | `Procfile` + `runtime.txt`  | Configuração de deploy. Independente de versão de biblioteca.                                                                                                                           | —                   |

##### TASKS 5.2.2–5.2.3 ⬜ (pendentes) — sem novas decisões de biblioteca além das já triadas.

---

#### SPRINT 5.3 — Documentação Final

##### TASK 5.3.2 — Code Quality Final ⬜ (pendente)

| Flag | Decisão            | Razão                                                                                                                                                                                                                                                                                 | Ref. baseline                                  |
| ---- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| 🟡   | `flake8` ou `ruff` | Não coberto pelo baseline. Pesquisar compatibilidade com Python 3.14 — em particular o impacto do **PEP 649** (deferred annotation evaluation) em linters que analisam type hints. `ruff` costuma ter suporte mais rápido a novas features do Python. Pesquisar ao atingir esta task. | §1, "PEP 649 — deferred annotation evaluation" |

#### SPRINT 5.4 — Apresentação Portfólio — sem decisões técnicas de biblioteca a triar.

---

## ⚠️ ARCHITECTURAL CONFLICTS — Seção Detalhada

**Estes conflitos não são problemas de baseline de ecossistema. São inconsistências diretas entre o ROADMAP_SKILLBRIDGE e os documentos arquiteturais canônicos do projeto (`ARCHITECTURE.md` e `conventions.md`).**

### Conflito: `on_delete=CASCADE` em modelos do ROADMAP

O roadmap especifica `on_delete=CASCADE` em três campos de ForeignKey:

| Task  | Model      | Campo        | Roadmap diz         | Correto per ARCHITECTURE.md |
| ----- | ---------- | ------------ | ------------------- | --------------------------- |
| 2.2.2 | `Job`      | `client`     | `on_delete=CASCADE` | `on_delete=PROTECT`         |
| 2.2.3 | `Proposal` | `job`        | `on_delete=CASCADE` | `on_delete=PROTECT`         |
| 2.2.3 | `Proposal` | `freelancer` | `on_delete=CASCADE` | `on_delete=PROTECT`         |

**Por que isso é um problema:** `ARCHITECTURE.md` declara explicitamente:

> "Always use `on_delete=models.PROTECT` on every ForeignKey and OneToOneField.
> CASCADE is explicitly rejected. The platform deactivates accounts and profiles
> via is_active=False; it does not delete them."

`CASCADE` silenciaria uma deleção acidental de `Client`, `Job`, ou `Freelancer`,
apagando em cascata as entidades dependentes — comportamento que a arquitetura
inteira é desenhada para prevenir. Quando as Tasks 2.2.2 e 2.2.3 forem iniciadas,
o roadmap deve ser corrigido para `on_delete=PROTECT` antes de qualquer código ser
escrito.

**Referências arquiteturais:**

- `ARCHITECTURE.md` → seção "ForeignKey and OneToOneField — on_delete policy"
- `conventions.md` → seção "Architectural rules" → "ForeignKey and OneToOneField — on_delete policy"
- `ARCHITECTURE.md` → seção "FreelancerProfile — on_delete=PROTECT on OneToOneField" (raciocínio análogo aplicável a Job e Proposal)

---

## NOTA FINAL — Pacotes não cobertos pelo baseline

Os seguintes pacotes aparecem no roadmap mas não foram pesquisados no
`STACK_BASELINE.md`. Todos são 🟡. Pesquisa task-a-task quando o item for atingido:

| Pacote               | Sprint | Motivo do flag          |
| -------------------- | ------ | ----------------------- |
| `python-json-logger` | 3.4    | Não coberto             |
| Bootstrap 5 (CDN)    | 4.1    | Não coberto (não é pip) |
| `whitenoise`         | 4.2    | Não coberto             |
| `django-environ`     | 5.1    | Não coberto             |
| `django-axes`        | 5.1    | Não coberto             |
| `django-ratelimit`   | 5.1    | Não coberto             |
| `gunicorn`           | 5.2    | Não coberto             |
| `flake8` / `ruff`    | 5.3    | Não coberto             |

---

_Documento de triagem — gerado em 12 June 2026._
_Sem código, sem correções, sem mudanças de arquivo._
_Toda pesquisa detalhada e toda ação acontece task-a-task, nas sessões correspondentes._
