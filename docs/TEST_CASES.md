<<<<<<< HEAD
| Test ID | Feature / Control | Execution Query / Action | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-08** | Trigger-based audit logging (`public.audit_logs`) | Insert/update rows in `public.courses` and `public.enrollments` (`05_seed_data.sql`) and query `public.audit_logs` | Automatic `INSERT`/`UPDATE` audit rows with `table_name`, `operation`, `record_id`, `old_data`, `new_data`, and `changed_at` | Verified: `public.audit_logs` recorded `INSERT` (e.g., `record_id=28`, `marks=44`, `grade='D'`) and `UPDATE` (e.g., `record_id=3`, `marks: 54 -> 55`) with full JSONB snapshots | **PASS** |
| **TC-09** | Append-only audit log immutability | `SET LOCAL ROLE authenticated; DELETE FROM public.audit_logs WHERE id = (SELECT max(id) FROM public.audit_logs);` | `DELETE` blocked by privilege/RLS enforcement | `ERROR: 42501: permission denied for table audit_logs` | **PASS** |
| **TC-11** | Standalone `demo_student` least privilege | `SET LOCAL ROLE demo_student; SELECT id, student_number, full_name FROM demo.students;` followed by `SELECT * FROM demo.enrollments;` | Permitted columns on `demo.students` readable; `demo.enrollments` denied | Returned 6 student rows (`id`, `student_number`, `full_name`); `SELECT * FROM demo.enrollments` failed with `ERROR: 42501: permission denied for table enrollments` | **PASS** |
| **TC-12** | Standalone `demo_lecturer` column-level `UPDATE` & `DELETE` restriction | `SET LOCAL ROLE demo_lecturer; UPDATE demo.enrollments SET marks = 85.00 ...;` followed by `DELETE FROM demo.students;` | Column-level `UPDATE (marks)` succeeds; `DELETE` on `demo.students` denied | Updated `id=1` (`marks = 85.00`, 1 row returned); `DELETE FROM demo.students` failed with `ERROR: 42501: permission denied for table students` | **PASS** |
| **TC-13** | Standalone `demo_admin` full DML privileges | `SET LOCAL ROLE demo_admin; INSERT INTO demo.courses (course_code, title) VALUES ('TEST999', 'Temp Audit Check') RETURNING id, course_code, title;` | Full DML succeeds on `demo` tables | Inserted and returned `(9, 'TEST999', 'Temp Audit Check')` cleanly (rolled back after verification) | **PASS** |
| **TC-14** | SQL injection vs. parameterised query (`demo.search_students_*`) | Run `demo.search_students_unsafe(''' OR ''1''=''1')` vs. `demo.search_students_safe(''' OR ''1''=''1')` | Unsafe string concatenation dumps all rows; parameterised `$1` query returns 0 rows | `search_students_unsafe` leaked all 6 rows including `national_id`; `search_students_safe` returned `0 rows` | **PASS** |
=======
# BIT3360 Security Verification & Test Log (`TC-01` – `TC-14`)

**Assigned Testers:** Gabriel Mwila & Ndame  
**Test Harness:** `database/06_verification_tests.sql` (run each block individually in Supabase SQL Editor)

| ID | Layer | Actor / Role | Action Tested | Expected Outcome | Observed Result | Status | Tester / Date |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | API / Grants | `anon` (unauthenticated) | `SELECT * FROM public.students` | Blocked (`SQLSTATE 42501`: permission denied) | | Pending | |
| **TC-02** | API / RLS | `student.a@bit3360.test` | `SELECT * FROM public.students` | Returns **1 row** (`ZUT2026001` only) | | Pending | |
| **TC-03** | API / RLS | `student.a@bit3360.test` | `SELECT * FROM public.enrollments` | Returns **2 rows** (Student A's courses only) | | Pending | |
| **TC-04** | API / RLS | `student.a@bit3360.test` | `UPDATE public.enrollments SET marks = 99` | **0 rows** updated (blocked by RLS) | | Pending | |
| **TC-05** | API / RLS | `lecturer1@bit3360.test` | `SELECT * FROM public.enrollments` | Returns **2 rows** (`BIT3360` only; hides `BIT3410`) | | Pending | |
| **TC-06** | API / Trigger | `lecturer1@bit3360.test` | `UPDATE public.enrollments SET marks = 78` (Student B) | Succeeds; `grade` auto-derived as `'A'` | | Pending | |
| **TC-07** | API / Trigger | `lecturer1@bit3360.test` | `UPDATE public.enrollments SET student_id = ...` | Blocked (`SQLSTATE 42501`: non-admin FK change) | | Pending | |
| **TC-08** | API / RLS | `admin@bit3360.test` | `SELECT` on `students` & `enrollments` | Returns all **3 students** and **4 enrolments** | | Pending | |
| **TC-09** | API / Grants | `admin@bit3360.test` | `DELETE FROM public.audit_logs` | Blocked (`SQLSTATE 42501`: permission denied) | | Pending | |
| **TC-10** | Audit Trigger | `admin@bit3360.test` | `SELECT * FROM public.audit_logs` after update | Captures `OLD`/`NEW` JSONB, `auth.uid()`, `authenticated` | | Pending | |
| **TC-11** | SQL Grants | `demo_student` | Read `full_name` vs. `national_id` / `enrollments` | `full_name` succeeds (3 rows); `national_id` & `enrollments` fail (`42501`) | | Pending | |
| **TC-12** | SQL Grants | `demo_lecturer` | `UPDATE marks` vs. `DELETE` on `demo.enrollments` | `UPDATE marks` succeeds; `DELETE` fails (`42501`) | | Pending | |
| **TC-13** | SQL Grants | `demo_admin` | DML (`INSERT`/`DELETE`) vs. DDL (`CREATE TABLE`) | DML succeeds; `CREATE TABLE` fails (`42501`) | | Pending | |
| **TC-14** | SQL Injection | `demo_student` | `search_students_unsafe` vs. `search_students_safe` with `' OR '1'='1` | Unsafe leaks **3 rows**; Safe returns **0 rows** | | Pending | |
>>>>>>> upstream/main
