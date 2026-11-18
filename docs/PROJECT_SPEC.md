# Project Specification: Secure Student Records Management System

**Course:** BIT3360 Advanced Databases, Zambia University College of Technology
**Assignment:** Group Assignment, Topic 2: Database Security
**Internal completion target:** Saturday 21 November 2026
**Submission deadline:** Thursday 26 November 2026
**Version:** 2.0 (revised against the assignment brief). Status: pending group sign-off (see Section 12).

---

## 1. Objective and Problem Statement

Academic institutions hold sensitive data: student identifiers, course enrolments and examination marks. Its confidentiality and integrity depend on strict authorisation boundaries. Hiding buttons in a user interface does not protect data, because anyone can inspect network requests and call the backend directly. Access control must therefore be enforced inside the database, which every access path must pass through (defence in depth, per OWASP authorization guidance).

**Objective:** design, implement and verify a small PostgreSQL prototype, hosted on Supabase, that demonstrates practical database security. It combines:

1. Authentication (Supabase Auth, signed JWTs)
2. Users with different permissions (SQL roles with `GRANT`/`REVOKE`, and application roles with Row Level Security)
3. Parameterised queries (with a deliberate injectable-versus-safe comparison)
4. An automated, trigger-based audit log
5. Encryption (explained in the presentation; one small `pgcrypto` demonstration is optional)

All work is done only on a database created for this assignment, using synthetic data, as the brief requires.

## 2. Traceability to the Assessment Brief

| Brief requirement | Where it is satisfied |
|---|---|
| Create a small database (student or employee records) | Section 8, five tables plus a `private` schema |
| Create users with different permissions | Sections 4 and 6: three app roles (RLS) and three SQL roles (`GRANT`/`REVOKE`) |
| Demonstrate which operations each user can and cannot perform | Permissions matrix (Section 6), test cases TC-01 to TC-13 |
| Implement one additional security measure | Audit log (FR-06, FR-07) and parameterised queries (FR-08), both implemented |
| Use sample data; test only on own database | Section 3 and Section 10 (synthetic data, dedicated project) |
| Part A: threats, authentication, access control, encryption, parameterised queries | Section 11, presentation plan |
| Part A: concepts, how it works and where it is used, benefits, limitations, challenges, example systems and tools, sources | Section 11, slides 2 to 10 and 15 |
| Presentation: problem, tools, how it works, challenges | Section 11, slides 11 to 14 |
| Deliverable 1: PowerPoint presentation | `presentation/` |
| Deliverable 2: working prototype with scripts, sample data and application code | `database/` and `application/` |
| Every member participates and can answer questions | Section 11 (speaker allocation) and acceptance criterion 6 |

## 3. Scope and Limitations

| Dimension | Included | Excluded |
|---|---|---|
| Core entities | Profiles and roles, students, courses, enrolments with marks and grades, audit log | Tuition billing, attendance, library, timetabling, PDF transcripts |
| Authentication | Admin-provisioned test accounts signing in with Supabase Auth email and password | Self-registration with self-selected roles, OAuth, SMS multi-factor |
| Security enforcement | `REVOKE`/`GRANT`, per-operation RLS, `SECURITY DEFINER` audit trigger, parameterised queries, standalone SQL demo roles | Enterprise SSO, application-layer column encryption (beyond the optional `pgcrypto` demo), replication |
| User interface | One lightweight web page with role-appropriate views and live allow and deny demonstrations | Mobile apps, CSV import, in-app user provisioning |
| Testing environment | A dedicated Supabase project with synthetic data | Real student data; testing against any external system |

**Known limitations (to be explained during assessment):**

1. **Audit scope.** Row triggers fire only on committed `INSERT`, `UPDATE` and `DELETE` (`TG_OP`). `audit_logs` therefore records data changes, not `SELECT` reads and not rejected attempts that fail before modifying a row (for example a `42501` denial). Logging reads and denials would need `pgaudit` or server logs, which is outside this prototype.
2. **Privileged bypass.** The Dashboard `postgres` role and any `service_role` / secret key bypass RLS and can alter the audit log. The log is tamper-resistant against API users, not against the database owner.
3. **Account provisioning.** Creating or modifying other users through the Supabase Admin API needs a secret key that must never appear in browser code. Test accounts are therefore created beforehand in the Dashboard (Authentication > Users).
4. **Shared API role.** All signed-in API callers run as the single database role `authenticated`. Table and column `GRANT`s on `authenticated` therefore cannot distinguish admin, lecturer and student. That distinction is made by RLS plus triggers. The classic `GRANT`/`REVOKE` demonstration uses separate standalone roles (Section 6.2).

## 4. Roles and the Five-Layer Security Model

| Layer | Mechanism | Role in request evaluation |
|---|---|---|
| 1. Authenticated identity | `auth.users` account and signed JWT (`sub` claim) | Identifies the caller; read in policies through `(select auth.uid())` |
| 2. Database role | `anon`, `authenticated` (Data API); `demo_admin`, `demo_lecturer`, `demo_student` (standalone demo) | The principal PostgreSQL executes the statement as |
| 3. Application role | `public.profiles.app_role` = `admin`, `lecturer` or `student` | Business role that decides what a signed-in user may access |
| 4. Object privileges | `GRANT` and `REVOKE` on schemas, tables, columns, sequences, functions | Coarse gate checked first; a missing privilege raises SQLSTATE `42501` before RLS runs |
| 5. Row Level Security | `ENABLE ROW LEVEL SECURITY` and per-command policies | Fine-grained filter: `USING` selects visible or modifiable rows; `WITH CHECK` validates new row states |

**Application roles**

- **Administrator (`admin`)**: creates, views, updates and deletes students, courses and enrolments; views all profiles; reads `audit_logs`.
- **Lecturer (`lecturer`)**: views their own courses, the students enrolled in them, and enters or updates **marks** for those courses only. Cannot delete students, change enrolments, or read audit logs.
- **Student (`student`)**: views only their own student record and their own enrolments, marks and grades. No write access and no view of other students.

## 5. Functional Requirements

| ID | Requirement | Role(s) | Enforcement |
|---|---|---|---|
| FR-01 | Users sign in with email and password and receive a signed JWT. Unauthenticated callers get no table access. | All authenticated; `anon` blocked | Supabase Auth; `REVOKE ALL` from `anon` |
| FR-02 | The client reads the user's own `app_role` to render role-appropriate controls. Enforcement stays in PostgreSQL. | admin, lecturer, student | RLS `SELECT` policy on `profiles` |
| FR-03 | Create, view, update and delete students, courses and enrolments. | admin only | RLS policies calling `private.current_app_role() = 'admin'` |
| FR-04 | View enrolled students and enter or update marks (0 to 100) for assigned courses. The grade is derived from marks by the database. | lecturer (assigned courses), admin | Course-ownership RLS, immutability trigger, `CHECK` constraint, grade-derivation trigger |
| FR-05 | View own student profile and own marks and grades. Peers' records and mark changes are blocked. | student (own rows) | Ownership RLS through `private.my_student_id()` |
| FR-06 | Automatically record every committed `INSERT`, `UPDATE`, `DELETE` on `profiles`, `students`, `courses` and `enrollments`. | System | `AFTER` row trigger calling `private.log_record_change()` |
| FR-07 | Inspect audit records. Clients cannot modify or delete log history. | admin (`SELECT` only) | `REVOKE INSERT, UPDATE, DELETE, TRUNCATE` plus an admin-only `SELECT` policy |
| FR-08 | All client queries are parameterised. A documented demo contrasts an injectable query with the safe equivalent on the demo schema. | All | PostgREST parameterisation; `EXECUTE ... USING` in the safe demo function |
| FR-09 | Role assignment cannot be self-service. New accounts default to `student`; promotion is performed manually by the database owner. | System, DB owner | `auth.users` trigger with hard-coded default; admin-only `UPDATE` policy |

## 6. Permissions

### 6.1 Data API path (`anon` / `authenticated` + RLS)

All access defaults to **deny**.

| Table | anon | student | lecturer | admin |
|---|---|---|---|---|
| `profiles` | Denied (`42501`) | `SELECT` own row; writes denied | `SELECT` own row; writes denied | `SELECT` all; `UPDATE` existing; `DELETE` denied |
| `students` | Denied | `SELECT` own record | `SELECT` students enrolled in own courses; writes denied | Full `SELECT`, `INSERT`, `UPDATE`, `DELETE` |
| `courses` | Denied | `SELECT` catalogue (OD-04); writes denied | `SELECT` own courses; writes denied | Full |
| `enrollments` | Denied | `SELECT` own rows; writes denied | `SELECT` and `UPDATE` (marks only) for own courses; `INSERT`/`DELETE` denied | Full |
| `audit_logs` | Denied | `SELECT` returns 0 rows; writes `42501` | `SELECT` returns 0 rows; writes `42501` | `SELECT` all; writes `42501` |

**Mechanism notes**

- Because every signed-in user is `authenticated`, column-level control on `enrollments` is done by a `BEFORE UPDATE` trigger. For non-admins it rejects any change to `student_id` or `course_id`, and it sets `updated_by = auth.uid()`.
- A `BEFORE INSERT OR UPDATE` trigger on `enrollments` derives `grade` from `marks`, ignoring any client-supplied grade. The scale below is a proposed default.

| Marks | Grade |
|---|---|
| 75 to 100 | A |
| 60 to 74 | B |
| 50 to 59 | C |
| 40 to 49 | D |
| 0 to 39 | F |

### 6.2 Standalone SQL role path (classic `GRANT` / `REVOKE`)

This is a **core deliverable**, because the brief asks for users with different permissions. It lives in `database/04_roles_and_grants.sql` and operates on a separate **`demo` schema** (`demo.students`, `demo.courses`, `demo.enrollments`) with **RLS disabled**, so the effect of each privilege is visible without RLS filtering results to zero rows. The `demo` schema is not exposed through the Data API.

| Role | Privileges (summary) | Cannot do |
|---|---|---|
| `demo_student` | `SELECT` on `demo.courses`; `SELECT (id, student_number, full_name)` on `demo.students` | Any `UPDATE`, `INSERT`, `DELETE`; read marks |
| `demo_lecturer` | `SELECT` on all demo tables; `UPDATE (marks)` on `demo.enrollments` | `DELETE` on students; update `student_id` or `course_id`; any `INSERT` |
| `demo_admin` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on all demo tables | Create roles; alter the schema |

The demo tables use identity columns, which need no separate sequence grant. If any table is built with `serial` instead, table grants do not cover its sequence, and `demo_admin` would also need explicit `USAGE` on it to insert.

## 7. Security Controls

1. **Deny-by-default privileges.** Run `REVOKE ALL ON ALL TABLES, SEQUENCES, FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated`, then issue explicit minimum grants. Also run `ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES, SEQUENCES, FUNCTIONS FROM anon, authenticated`, so tables created later do not auto-grant. Run it for the role that creates objects (`postgres`). Supabase projects grant to `anon` and `authenticated` by default, and enabling RLS alone does not remove those grants.
2. **Per-operation RLS.** Enable RLS on every `public` table. Write separate `SELECT` (`USING`), `INSERT` (`WITH CHECK`), `UPDATE` (`USING` and `WITH CHECK`) and `DELETE` (`USING`) policies rather than `FOR ALL`. An `UPDATE` also needs a matching `SELECT` policy. Wrap `auth.uid()` as `(select auth.uid())` so it is evaluated once per statement. Index every policy-filtered column.
3. **Non-recursive helper functions.** Policies on `profiles` that query `profiles` recurse infinitely. So do policies on two tables that query each other (for example, a student policy on `enrollments` reading `students`, while a lecturer policy on `students` reads `enrollments`). All cross-table lookups go in `STABLE SECURITY DEFINER SET search_path = ''` functions in the unexposed `private` schema:
   - `private.current_app_role()`
   - `private.my_student_id()`
   - `private.is_my_course(course_id)`
   - `private.is_student_in_my_course(student_id)`

   `EXECUTE` is revoked from `PUBLIC` and `anon` and granted only to `authenticated`, which also needs `USAGE` on `private`.
4. **Hardened audit trigger.** `private.log_record_change()` is `SECURITY DEFINER SET search_path = ''` and writes `table_name`, `operation` (`TG_OP`), `record_id` (as text, since `profiles` uses UUIDs), `changed_by_auth_uid` (`auth.uid()`), `changed_by_db_role` (`current_setting('role')`), `old_data`, `new_data` and `changed_at` (`now()`). Do **not** use `current_user` for the caller: inside a `SECURITY DEFINER` function it is the function owner. Verify during setup that the logged role reads `authenticated`. Do not use `FORCE ROW LEVEL SECURITY` on `audit_logs`, or the trigger's owner-level insert will be blocked.
5. **Parameterised queries.** The web client uses `@supabase/supabase-js`, which sends values to PostgREST as parameters, so input cannot change SQL syntax. Avoid building `.or()` or `.filter()` strings from raw user input, because they can alter filter logic. Inside PL/pgSQL, never concatenate input; use `EXECUTE ... USING` and `format('%I', ...)` against allow-listed identifiers. Parameterisation prevents injection, not authorisation bypass. RLS still does that job.
6. **Authentication and key hygiene.** No password columns in `public` tables; Supabase Auth stores salted password hashes in `auth.users` and issues signed JWTs. `.env` files are excluded by `.gitignore`. `application/` contains only the project URL and the **publishable (anon) key**. Never commit a secret, `service_role` or JWT-secret key. Confirm the key names shown in your project under Settings > API Keys, as Supabase has been moving from legacy `anon`/`service_role` keys to `sb_publishable_`/`sb_secret_` keys.
7. **Safe views.** Any reporting view over an RLS-protected table must be created `WITH (security_invoker = true)`.
8. **Privilege-escalation guard.** The trigger that creates a `profiles` row on signup hard-codes `app_role = 'student'` and **never reads `raw_user_meta_data`**, which users can edit. The database owner promotes the admin and lecturers with a manual `UPDATE`. `profiles` has no non-admin `UPDATE` policy.
9. **Encryption (explained; optional demo).**
   - *In transit:* TLS between browser, API and database.
   - *At rest:* platform-level disk encryption on the hosted database.
   - *Passwords:* hashed by Supabase Auth, never stored in plain text.
   - *Optional column-level demo:* in the `demo` schema, store a synthetic `national_id` with `pgcrypto` (`pgp_sym_encrypt` / `pgp_sym_decrypt`) and show that a role without the key sees only ciphertext. Use a demo key only; never commit a real one.

## 8. Data Model

Five tables in `public`, one unexposed `private` schema, one `demo` schema.

| Table | Key columns and constraints | Purpose |
|---|---|---|
| `public.profiles` | `id uuid PK` references `auth.users(id)` `ON DELETE CASCADE`; `email` unique not null; `full_name`; `app_role` not null `DEFAULT 'student'` `CHECK (app_role IN ('admin','lecturer','student'))` | Maps `auth.uid()` to a domain role |
| `public.students` | `id bigint identity PK`; `profile_id` unique not null references `profiles(id)`; `student_number` unique not null; `full_name`; `year_of_study CHECK BETWEEN 1 AND 6` | Student identity, separated from credentials |
| `public.courses` | `id bigint identity PK`; `course_code` unique not null; `title`; `lecturer_id` not null references `profiles(id)` | Course ownership for lecturer RLS |
| `public.enrollments` | `id bigint identity PK`; `student_id` references `students(id)` **`ON DELETE CASCADE`**; `course_id` references `courses(id)`; `UNIQUE (student_id, course_id)`; `marks CHECK BETWEEN 0 AND 100`; `grade`; `updated_by` references `profiles(id)` | Protected exam scores |
| `public.audit_logs` | `id bigint identity PK`; `table_name`; `operation`; `record_id text`; `changed_by_auth_uid uuid`; `changed_by_db_role`; `old_data jsonb`; `new_data jsonb`; `changed_at timestamptz default now()`. No foreign keys, deliberately. | Append-only change history |

**Design notes**

- `audit_logs` has no foreign keys, so deleting a student never breaks, or cascades into, the log.
- `enrollments.student_id ON DELETE CASCADE` lets an admin delete a student (TC-08). Cascaded deletions fire the row trigger and are logged.
- Create a btree index on `students.profile_id`, `courses.lecturer_id`, `enrollments.student_id` and `enrollments.course_id`.
- Primary-key, unique and foreign-key integrity checks bypass RLS by design.

## 9. Test Scenarios

Run each scenario against your own Supabase project and record observed output in `docs/TEST_CASES.md`. Dashboard SQL Editor queries run as the privileged `postgres` role, which **bypasses RLS**. Test policies either through the web client signed in as each user, or inside `BEGIN; SET LOCAL ROLE authenticated; SET LOCAL "request.jwt.claims" = '{"sub":"<uuid>","role":"authenticated"}'; ... ROLLBACK;`.

Two denial behaviours must be explained during the demo:

- A missing privilege raises `42501` before RLS runs. A violated `WITH CHECK` raises an RLS policy violation.
- A `SELECT`, `UPDATE` or `DELETE` blocked only by an RLS `USING` clause fails **silently**, returning or affecting 0 rows.

### 9.1 Data API tests (authenticated roles + RLS)

| ID | Actor | Operation | Expected outcome |
|---|---|---|---|
| TC-01 | `anon` | `SELECT * FROM students` | Denied, `42501` |
| TC-02 | Student A | `SELECT` from `enrollments`; filter for Student B | Own rows only; Student B returns 0 rows |
| TC-03 | Student A | `UPDATE enrollments SET marks = 99`; attempted `INSERT` | `UPDATE` affects 0 rows; `INSERT` is denied (no write privilege or policy) |
| TC-04 | Student A | `UPDATE profiles SET app_role = 'admin'` on own row | 0 rows updated; no escalation |
| TC-05 | Lecturer 1 | Set `marks = 78` on a Course 1 enrolment | Permitted; `grade` is derived as `A`; an `UPDATE` row appears in `audit_logs` |
| TC-06 | Lecturer 1 | Set marks on a Course 2 enrolment | 0 rows updated (course-ownership RLS) |
| TC-07 | Lecturer 1 | `DELETE FROM students`; attempt to change `student_id` on an own-course enrolment | 0 rows deleted; the `student_id` change is rejected by the immutability trigger |
| TC-08 | Admin | Insert and delete a student; read `audit_logs` | Permitted; trigger logs `INSERT`, `DELETE` and the cascaded enrolment deletes; admin sees full history |
| TC-09 | Admin | `UPDATE` or `DELETE` on `audit_logs` | Denied, `42501` |
| TC-10 | Admin | Change a lecturer's `app_role` | Permitted; the change appears in `audit_logs` (`profiles` is audited) |

### 9.2 Standalone SQL role tests (`demo` schema)

| ID | Actor | Operation | Expected outcome |
|---|---|---|---|
| TC-11 | `demo_student` | `SELECT` marks; `UPDATE demo.enrollments SET marks = 99` | Denied, `42501` |
| TC-12 | `demo_lecturer` | `UPDATE (marks)` permitted; `UPDATE` of `student_id`, `DELETE FROM demo.students` and `INSERT` | Marks update succeeds; the others raise `42501` |
| TC-13 | `demo_admin` | Insert, update and delete in demo tables | Permitted |

### 9.3 Injection and encryption demonstrations

| ID | Actor | Operation | Expected outcome |
|---|---|---|---|
| TC-14 | Any user | Search with payload `' OR '1'='1` against (a) `demo.search_students_unsafe()` (string concatenation) and (b) `demo.search_students_safe()` (`EXECUTE ... USING`) and the web search box | (a) returns every row, proving the flaw; (b) and the web client treat the payload as a literal and return no rows |
| TC-15 | `demo_*` roles (optional) | Read the `pgcrypto`-encrypted `national_id` column with and without the key | Without the key only ciphertext is visible |

## 10. Acceptance Criteria

The prototype is complete only when all of these are verified through live execution:

1. Scripts in `database/` reproduce the live schema, grants, RLS policies, helper functions, triggers and the `demo` schema from scratch.
2. Synthetic seed data: 1 administrator, 2 lecturers, 3 students, 2 courses (one per lecturer) and 4 enrolments (for example A-C1, A-C2, B-C1, C-C2).
3. TC-01 to TC-14 are executed and documented with observed output in `docs/TEST_CASES.md`. TC-15 is optional.
4. The frontend in `application/` runs using only the project URL and publishable key. No secret or `service_role` key is committed to Git.
5. A repeat run on a fresh project, or a local Postgres or Supabase CLI instance, succeeds. This is the **fallback** if the live cloud demo fails (poor connectivity, or a paused free-tier project). Screenshots and a short screen recording of every test case are also prepared.
6. Every group member can explain authentication, SQL roles and grants, RLS, parameterised queries, the audit trigger and encryption, and can run at least one permitted and one denied operation live.
7. The PowerPoint presentation covers every item in Section 11 and cites its sources.

## 11. Presentation Plan (Deliverable 1)

| Slide | Content | Presenter |
|---|---|---|
| 1 | Title, group members, problem statement | Member 1 |
| 2 | What database security is; CIA triad; main concepts | Member 1 |
| 3 | How it works and where it is used (banking, health, education, e-commerce) | Member 1 |
| 4 | Common threats: SQL injection, privilege escalation, weak authentication, excessive privileges, data leakage, insider misuse | Member 2 |
| 5 | Authentication and access control (GRANT/REVOKE, roles, RLS, least privilege) | Member 2 |
| 6 | Parameterised queries and how they stop injection (with the unsafe versus safe example) | Member 3 |
| 7 | Encryption: in transit (TLS), at rest, hashed passwords, column-level `pgcrypto` | Member 3 |
| 8 | Auditing and monitoring | Member 4 |
| 9 | Benefits, limitations and challenges of database security | Member 4 |
| 10 | Example systems and tools (PostgreSQL, MySQL, Oracle, SQL Server, Supabase, `pgaudit`, OWASP resources) | Member 4 |
| 11 | The prototype: problem it addresses, architecture and five-layer model | Member 1 |
| 12 | Tools used and how it works (schema, roles, RLS, trigger, web client) | Member 2 |
| 13 | **Live demo:** TC-01, TC-05, TC-06, TC-09, TC-11, TC-12, TC-14 | All |
| 14 | Challenges encountered (RLS recursion, Dashboard bypass, silent 0-row denials, shared `authenticated` role) and lessons learned | Member 3 |
| 15 | Sources consulted | Member 4 |

The group has four members, so each member presents three or four slides and all four take part in the live demo. The brief requires every member to participate.

## 12. Open Decisions Requiring Group Approval

| ID | Decision | Proposed default | Status |
|---|---|---|---|
| OD-01 | Hosting platform | Supabase PostgreSQL | Pending |
| OD-02 | Frontend stack | Vanilla HTML5, CSS and JavaScript (ES modules) with `@supabase/supabase-js` | Pending |
| OD-03 | Lecturer data scope | Only courses where `lecturer_id = auth.uid()` | Pending |
| OD-04 | Student course visibility | Course catalogue readable; marks restricted to own rows | Pending |
| OD-05 | Dual demo (Data API with RLS plus standalone SQL roles) | **Both required** (the second is a core deliverable) | Pending |
| OD-06 | Audited tables | `profiles`, `students`, `courses`, `enrollments` | Pending |
| OD-07 | Teammate skills and rotation roles | Confirm strengths and assign Driver, Reviewer, Tester, Documenter | Pending |
| OD-08 | Group size and presenter allocation | Four members; one presenter role each (Section 11) | Confirmed |
| OD-09 | Optional `pgcrypto` encryption demo (TC-15) | Encryption is explained in the slides regardless. The live demo is built only if TC-01 to TC-14 are finished and passing by the end of Block 4 | Decide at end of Block 4 |
| OD-10 | Grading scale for derived grades | A 75+, B 60 to 74, C 50 to 59, D 40 to 49, F below 40 | Confirmed (A threshold set to 75) |

## 13. Repository Layout and Work Plan

```
docs/        PROJECT_SPEC.md, DATABASE_DESIGN.md, TEST_CASES.md
database/    01_schema.sql, 02_rls_and_grants.sql, 03_audit_trigger.sql,
             04_roles_and_grants.sql, 05_seed_data.sql
application/ index.html, app.js
presentation/ BIT3360_Database_Security.pptx
```

`.gitignore` must contain `.env`, `.env.local` and `node_modules/`.

**Seed order:** (1) create the Auth users in the Dashboard; (2) the signup trigger creates their `profiles` rows as `student`; (3) promote the admin and lecturers by SQL; (4) seed `students`, `courses` and `enrollments` using the real user UUIDs.

| Block | Work | Output |
|---|---|---|
| 0 | Sign off this specification (OD-01 to OD-10) | `docs/PROJECT_SPEC.md` |
| 1 | Schema, constraints, indexes, `private` helper functions | `01_schema.sql`, `DATABASE_DESIGN.md` |
| 2 | Default-privilege revocation, grants, RLS, immutability and grade triggers | `02_rls_and_grants.sql`; run TC-01 to TC-07 |
| 3 | Audit trigger, Auth users, seed data | `03_audit_trigger.sql`, `05_seed_data.sql`; run TC-08 to TC-10 |
| 4 | `demo` schema, standalone roles, injection demo, optional `pgcrypto` | `04_roles_and_grants.sql`; run TC-11 to TC-14 |
| 5 | Minimal web client and end-to-end test | `application/`; run TC-14 (web search box) |
| 6 | Presentation, fallback recording, rehearsal | `.pptx`, `docs/TEST_CASES.md` |

## 14. Sources

- Supabase Docs: Row Level Security, Postgres Roles, API Keys, JWT Claims, Advisors, Testing Overview (supabase.com/docs)
- PostgreSQL Documentation: Privileges, `GRANT`, `REVOKE`, `SET ROLE`, `CREATE FUNCTION`, Trigger Functions (postgresql.org/docs)
- OWASP Cheat Sheet Series: SQL Injection Prevention, Authorization, Multi-Tenant Security (cheatsheetseries.owasp.org)
- PostgREST Documentation (docs.postgrest.org)

Add any further sources the group actually consults for the presentation.
