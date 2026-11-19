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
