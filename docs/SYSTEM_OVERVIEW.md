# SkillBridge — System Overview

A product-level description of what SkillBridge is, the problem it addresses,
how it works for the people who use it, and the context it operates in. This
document is intentionally non-technical: the architectural decisions and their
trade-offs live in `ARCHITECTURE.md`.

> **Project status.** This document describes the **target product** — the
> platform SkillBridge is being built to become. The product is under active
> construction: the account and profile foundations are in place, while the
> job, proposal, and matching flows described below represent the intended
> experience and are being implemented incrementally. The purpose and vision
> stated here are stable; the surface area available at any given moment is
> growing toward them.

---

## 1. Main Purpose

SkillBridge is a professional freelance marketplace that connects two groups of
people:

- **Clients** — individuals and companies who have work to be done.
- **Freelancers** — professionals who deliver that work.

The platform's purpose is to make that connection **structured, reliable, and
trustworthy**: a place where a client can describe a piece of work and reach
qualified freelancers, and where a freelancer can present their skills and
compete for work on clear terms. Identity on the platform is built around a
person's professional email, the standard for professional platforms in the
European market SkillBridge targets.

---

## 2. Problem It Solves

Connecting the right client with the right freelancer is harder than it looks,
and doing it informally breaks down in predictable ways:

- **Unreliable matching.** When skills are typed as free text, the same
  capability shows up as "python", "Python", and "Python 3" — three entries
  that never match each other. Search and matching become fragile, and good
  freelancers are missed for the wrong reasons.
- **No structured filtering.** Clients need to narrow candidates by real
  criteria — the skills a job requires, the budget available — not by scrolling
  through unfiltered listings.
- **No trustworthy trail.** Work relationships involve commitments and, over
  time, contracts. Without a record of what changed and when, there is no basis
  for accountability or dispute resolution.

SkillBridge addresses these by giving the marketplace **structure at the core**:
a curated, consistent vocabulary of skills, filtering that reflects how work is
actually scoped, and an auditable history of how each engagement progresses.

---

## 3. Main Business Flows

The following flows describe the experience the platform delivers, in the order
a real engagement tends to unfold.

**Account creation and lifecycle.** A client or a freelancer registers with
their professional email and a secure password. Accounts are never deleted; when
someone leaves or is suspended, the account is **deactivated**, preserving the
integrity of any work and history connected to it.

**Profile building.** A freelancer builds a profile that presents who they are
professionally — the skills they offer (chosen from the platform's curated
list), their hourly rate, experience, and a link to their portfolio. A client
builds a profile that presents their organisation and the budget context they
work within.

**Posting work.** A client publishes a piece of work, describing what needs to
be done. Once published, it becomes visible to freelancers on the platform.

**Submitting a proposal.** A freelancer who is a good fit submits a proposal for
that work. Each freelancer may submit **one** proposal per posting — the intent
is a considered offer, not repeated bids.

**Accepting and matching.** The client reviews the proposals received and accepts
one. Accepting a proposal **advances the engagement**: the chosen freelancer is
matched to the work, the remaining proposals are declined, and the work moves
into an active state. On the discovery side, freelancers find relevant work
through filtering by the skills a posting requires and by budget.

**Auditability.** As work progresses, every change in status is recorded — what
changed, when, and from which state to which. This gives both sides, and the
platform's operators, a reliable trail of how an engagement evolved.

**Platform administration.** Platform operators maintain the shared foundations
that keep matching reliable — most notably the **curated vocabulary of skills**.
Freelancers select from this list rather than inventing free-text entries, which
is what keeps search and matching consistent across the whole platform.

### Current build status

| Flow                              | Status               |
| --------------------------------- | -------------------- |
| Account creation and lifecycle    | Implemented          |
| Profile building                  | Implemented          |
| Skill vocabulary (admin-curated)  | Implemented          |
| Posting work                      | Planned              |
| Submitting a proposal             | Planned              |
| Accepting and matching            | Planned              |
| Auditability of status changes    | Planned              |

---

## 4. Product Vision

SkillBridge aims to be a **trustworthy, structured marketplace** rather than an
open listing board. Three commitments define where the product is heading:

- **Reliable matching as a foundation, not a feature.** The curated skill
  vocabulary exists so that connecting the right people is dependable by design,
  not left to chance or to how someone happened to spell a word.
- **Privacy and accountability by default.** The platform is built for the
  European market, with data protection treated as a starting constraint (see
  the Operational Context below), and with an auditable history of how
  engagements progress.
- **A clear path to grow.** The product has deliberate extension points for the
  future — for example, a workflow where freelancers can suggest new skills for
  administrators to approve, broader lifecycle tooling as the platform scales,
  and adjacent capabilities such as payments and messaging. These are named as
  direction, not current scope.

The guiding principle is that trust in a marketplace comes from structure:
consistent data, clear rules for how work moves forward, and a record that both
sides can rely on.

---

## 5. Operational Context

**Who uses the platform.** SkillBridge serves three groups of people:

- **Clients** — those who post work and choose who does it.
- **Freelancers** — those who present their skills and take on work.
- **Platform operators (staff)** — the internal team that keeps the platform's
  shared foundations healthy, curates the skill vocabulary, and manages account
  lifecycles.

**Market.** SkillBridge is aimed at the **European professional market**. That
choice shapes the product's defaults, from email-based professional identity to
the regulatory posture below.

**Regulatory posture — GDPR from day one.** Because the platform targets Europe,
**data protection is a first-order constraint**, present in the design from the
start rather than added later. In practice this means personal data is handled
conservatively, and the platform's lifecycle is built around **deactivating
accounts rather than deleting them** — preserving the records that
accountability and data-retention obligations depend on, while removing access
when an account should no longer be active.
