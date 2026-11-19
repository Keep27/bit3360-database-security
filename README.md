# BIT3360 — Advanced Database Security

Role-based access control (RBAC), Row Level Security (RLS), least-privilege table grants, automated audit logging, and data-integrity triggers implemented on PostgreSQL (Supabase) for an academic records system.

---

## Repository Structure

```text
├── docs/
│   └── DATABASE_DESIGN.md         # Entity definitions, keys, relationships, and security model
├── database/
│   ├── 01_schema.sql              # Private schema, core tables, constraints, indexes, and helper functions
│   ├── 02_rls_and_grants.sql      # REVOKE/GRANT least-privilege rules and 15 per-operation RLS policies
│   ├── 03_audit_trigger.sql       # SECURITY DEFINER audit logging and enrollment guard/grade triggers
│   ├── 04_roles_and_grants.sql    # Standalone PostgreSQL roles (demo_student, demo_lecturer, demo_admin)
│   └── 05_seed_data.sql           # Sample courses, enrollments, profiles, and test records
└── README.md
```

---

## Database Schema (`public`)

| Table | Purpose |
| :--- | :--- |
| `profiles` | Maps Supabase Auth users (`auth.users`) to application roles (`student`, `lecturer`, `admin`) |
| `students` | Student academic records linked to user profiles |
| `courses` | Course catalog and assigned lecturer mappings |
| `enrollments` | Student course registrations, marks, and derived grades |
| `audit_logs` | Immutable trail of `INSERT`, `UPDATE`, and `DELETE` actions across core tables |

---

## Security Controls Implemented

### 1. Least-Privilege Grants & API Lockdown
* Unauthenticated (`anon`) access is revoked across all `public` tables (`API DISABLED` for public roles).
* Only explicitly required operations are granted to `authenticated` users, with all row visibility and write permissions enforced through RLS policies.

### 2. Row Level Security (RLS) Policies
All 5 tables have RLS enabled with 15 role-based policies applied to `authenticated`:

* **`profiles`**
  * `profiles_select_own_or_admin` (`SELECT`) — Users view their own profile; admins view all.
  * `profiles_update_admin_only` (`UPDATE`) — Only admins can modify user roles/profiles.
* **`students`**
  * `students_select_by_role` (`SELECT`), `students_insert_admin_only` (`INSERT`), `students_update_admin_only` (`UPDATE`), `students_delete_admin_only` (`DELETE`).
* **`courses`**
  * `courses_select_by_role` (`SELECT`), `courses_insert_admin_only` (`INSERT`), `courses_update_admin_only` (`UPDATE`), `courses_delete_admin_only` (`DELETE`).
* **`enrollments`**
  * `enrollments_select_by_role` (`SELECT`) — Students see their own enrollments; lecturers see enrollments for their assigned courses; admins see all.
  * `enrollments_insert_admin_only` (`INSERT`) — Only admins can enroll students.
  * `enrollments_update_admin_or_course_lecturer` (`UPDATE`) — Restricted to admins and the lecturer assigned to that course.
  * `enrollments_delete_admin_only` (`DELETE`) — Only admins can delete enrollments.
* **`audit_logs`**
  * `audit_logs_select_admin_only` (`SELECT`) — Read access restricted strictly to admins; direct client writes are blocked.

### 3. Database Triggers (`public`)
* **`01_guard_enrollment_update`** (`BEFORE UPDATE` on `enrollments`) — Calls `guard_enrollment_update()` to prevent unauthorized column tampering during updates.
* **`02_derive_enrollment_grade`** (`BEFORE INSERT OR UPDATE` on `enrollments`) — Calls `derive_enrollment_grade()` to automatically compute letter grades from numeric scores.
* **Audit Logging Triggers (`AFTER INSERT OR UPDATE OR DELETE`)** — `audit_courses_changes`, `audit_enrollments_changes`, `audit_profiles_changes`, and `audit_students_changes` call `log_record_change()` (`SECURITY DEFINER`) to record actor, action, table, and before/after row snapshots in `audit_logs`.

---

## Setup & Deployment Order

1. Create a Supabase project and add the test users under **Authentication → Users**.
2. Open the **SQL Editor** and execute the scripts in exact dependency order:
   1. `database/01_schema.sql`
   2. `database/02_rls_and_grants.sql`
   3. `database/03_audit_trigger.sql`
   4. `database/04_roles_and_grants.sql`
   5. `database/05_seed_data.sql`
3. Configure your local environment variables (do not commit `.env` to Git):
   ```env
   SUPABASE_URL=https://<your-project-ref>.supabase.co
   SUPABASE_PUBLISHABLE_KEY=<your-publishable-key>
   ```

---

## Seeded Test Accounts

Use these Supabase Auth accounts to verify role-based access and RLS policies during testing:

| Role | Test Email |
| :--- | :--- |
| **Admin** | `admin@bit3360.test` |
| **Lecturer** | `lecturer1@bit3360.test`, `lecturer2@bit3360.test` |
| **Student** | `student.a@bit3360.test`, `student.b@bit3360.test`, `student.c@bit3360.test` |