-- =====================================================================
-- 02_rls_and_grants.sql
-- BIT3360 Advanced Databases: Secure Student Records Management System
-- Block 2: minimum table grants, per-operation RLS policies, enrollment
--          column-immutability guard, and automatic grade derivation.
--
-- Prerequisite: database/01_schema.sql executed cleanly.
-- Run in the Supabase SQL Editor (runs as the postgres role).
-- =====================================================================

begin;

-- ---------------------------------------------------------------------
-- 1. Minimum Table Privileges for Data API Roles
--    - anon holds ZERO grants (TC-01 raises SQLSTATE 42501).
--    - authenticated holds the coarse ceiling; RLS + triggers narrow it.
--    - audit_logs is SELECT-only for authenticated (TC-09 raises 42501).
-- ---------------------------------------------------------------------
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.students to authenticated;
grant select, insert, update, delete on public.courses to authenticated;
grant select, insert, update, delete on public.enrollments to authenticated;
grant select on public.audit_logs to authenticated;

-- ---------------------------------------------------------------------
-- 2. Per-Operation Row Level Security Policies
--    Every policy is scoped per command (SELECT, INSERT, UPDATE, DELETE).
-- ---------------------------------------------------------------------

-- 2.1 public.profiles
drop policy if exists profiles_select_own_or_admin on public.profiles;
create policy profiles_select_own_or_admin
  on public.profiles
  for select
  to authenticated
  using (
    id = (select auth.uid())
    or private.current_app_role() = 'admin'
  );

drop policy if exists profiles_update_admin_only on public.profiles;
create policy profiles_update_admin_only
  on public.profiles
  for update
  to authenticated
  using (private.current_app_role() = 'admin')
  with check (private.current_app_role() = 'admin');

-- 2.2 public.students
drop policy if exists students_select_by_role on public.students;
create policy students_select_by_role
  on public.students
  for select
  to authenticated
  using (
    private.current_app_role() = 'admin'
    or profile_id = (select auth.uid())
    or (
      private.current_app_role() = 'lecturer'
      and private.is_student_in_my_course(id)
    )
  );

drop policy if exists students_insert_admin_only on public.students;
create policy students_insert_admin_only
  on public.students
  for insert
  to authenticated
  with check (private.current_app_role() = 'admin');

drop policy if exists students_update_admin_only on public.students;
create policy students_update_admin_only
  on public.students
  for update
  to authenticated
  using (private.current_app_role() = 'admin')
  with check (private.current_app_role() = 'admin');

drop policy if exists students_delete_admin_only on public.students;
create policy students_delete_admin_only
  on public.students
  for delete
  to authenticated
  using (private.current_app_role() = 'admin');

-- 2.3 public.courses
drop policy if exists courses_select_by_role on public.courses;
create policy courses_select_by_role
  on public.courses
  for select
  to authenticated
  using (
    private.current_app_role() in ('admin', 'student')
    or (
      private.current_app_role() = 'lecturer'
      and lecturer_id = (select auth.uid())
    )
  );

drop policy if exists courses_insert_admin_only on public.courses;
create policy courses_insert_admin_only
  on public.courses
  for insert
  to authenticated
  with check (private.current_app_role() = 'admin');

drop policy if exists courses_update_admin_only on public.courses;
create policy courses_update_admin_only
  on public.courses
  for update
  to authenticated
  using (private.current_app_role() = 'admin')
  with check (private.current_app_role() = 'admin');

drop policy if exists courses_delete_admin_only on public.courses;
create policy courses_delete_admin_only
  on public.courses
  for delete
  to authenticated
  using (private.current_app_role() = 'admin');

-- 2.4 public.enrollments
drop policy if exists enrollments_select_by_role on public.enrollments;
create policy enrollments_select_by_role
  on public.enrollments
  for select
  to authenticated
  using (
    private.current_app_role() = 'admin'
    or (
      private.current_app_role() = 'student'
      and student_id = private.my_student_id()
    )
    or (
      private.current_app_role() = 'lecturer'
      and private.is_my_course(course_id)
    )
  );

drop policy if exists enrollments_insert_admin_only on public.enrollments;
create policy enrollments_insert_admin_only
  on public.enrollments
  for insert
  to authenticated
  with check (private.current_app_role() = 'admin');

drop policy if exists enrollments_update_admin_or_course_lecturer on public.enrollments;
create policy enrollments_update_admin_or_course_lecturer
  on public.enrollments
  for update
  to authenticated
  using (
    private.current_app_role() = 'admin'
    or (
      private.current_app_role() = 'lecturer'
      and private.is_my_course(course_id)
    )
  )
  with check (
    private.current_app_role() = 'admin'
    or (
      private.current_app_role() = 'lecturer'
      and private.is_my_course(course_id)
    )
  );

drop policy if exists enrollments_delete_admin_only on public.enrollments;
create policy enrollments_delete_admin_only
  on public.enrollments
  for delete
  to authenticated
  using (private.current_app_role() = 'admin');

-- 2.5 public.audit_logs (admin read-only; no write policies or write grants)
drop policy if exists audit_logs_select_admin_only on public.audit_logs;
create policy audit_logs_select_admin_only
  on public.audit_logs
  for select
  to authenticated
  using (private.current_app_role() = 'admin');

-- ---------------------------------------------------------------------
-- 3. Enrollment Integrity & Grade-Derivation Triggers
--    Numbered prefixes (01_, 02_) enforce deterministic firing order.
-- ---------------------------------------------------------------------

-- 3.1 Block non-admins from altering student_id or course_id (TC-07)
create or replace function private.guard_enrollment_update()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if current_setting('role', true) = 'authenticated'
     and private.current_app_role() is distinct from 'admin' then
    if new.student_id is distinct from old.student_id
       or new.course_id is distinct from old.course_id then
      raise exception 'Permission denied: only administrators may modify student_id or course_id'
        using errcode = '42501';
    end if;
  end if;

  return new;
end;
$$;

revoke all on function private.guard_enrollment_update() from public, anon, authenticated;

drop trigger if exists "01_guard_enrollment_update" on public.enrollments;
create trigger "01_guard_enrollment_update"
  before update on public.enrollments
  for each row execute function private.guard_enrollment_update();

-- 3.2 Auto-derive grade from marks (A: 75+, B: 60-74, C: 50-59, D: 40-49, F: <40)
create or replace function private.derive_enrollment_grade()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.marks is null then
    new.grade := null;
  elsif new.marks >= 75 then
    new.grade := 'A';
  elsif new.marks >= 60 then
    new.grade := 'B';
  elsif new.marks >= 50 then
    new.grade := 'C';
  elsif new.marks >= 40 then
    new.grade := 'D';
  else
    new.grade := 'F';
  end if;

  new.updated_by := coalesce((select auth.uid()), new.updated_by);
  new.updated_at := now();

  return new;
end;
$$;

revoke all on function private.derive_enrollment_grade() from public, anon, authenticated;

drop trigger if exists "02_derive_enrollment_grade" on public.enrollments;
create trigger "02_derive_enrollment_grade"
  before insert or update on public.enrollments
  for each row execute function private.derive_enrollment_grade();

commit;

-- =====================================================================
-- VERIFICATION (run after executing the script above)
-- =====================================================================

-- V5. Confirm expected grants (anon = 0 rows; audit_logs = SELECT only)
-- select grantee, table_name, privilege_type
-- from information_schema.role_table_grants
-- where table_schema = 'public' and grantee in ('anon', 'authenticated')
-- order by grantee, table_name, privilege_type;

-- V6. Confirm all 15 RLS policies exist across the 5 public tables
-- select tablename, policyname, cmd
-- from pg_policies
-- where schemaname = 'public'
-- order by tablename, cmd, policyname;