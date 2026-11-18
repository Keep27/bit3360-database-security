-- =====================================================================
-- 01_schema.sql
-- BIT3360 Advanced Databases: Secure Student Records Management System
-- Block 1: schema, constraints, indexes, private helper functions,
--          signup trigger and a deny-by-default security baseline.
--
-- Run in the Supabase SQL Editor (runs as the postgres role).
-- Prerequisite: a Supabase project created for this assignment only.
-- Policies, table grants and the enrollments triggers come in 02_*.sql;
-- the audit trigger comes in 03_*.sql.
-- All data in this project is synthetic.
-- =====================================================================

begin;

-- ---------------------------------------------------------------------
-- 0. Deny-by-default for objects created from now on.
--    Supabase normally auto-grants new public tables to anon and
--    authenticated. Remove that before any table exists.
-- ---------------------------------------------------------------------
alter default privileges in schema public revoke all on tables    from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke all on functions from anon, authenticated;

-- ---------------------------------------------------------------------
-- 1. Private schema (not exposed through the Data API)
-- ---------------------------------------------------------------------
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

-- ---------------------------------------------------------------------
-- 2. Tables
-- ---------------------------------------------------------------------

-- 2.1 profiles: maps auth.uid() to the application role.
create table if not exists public.profiles (
  id          uuid primary key references auth.users (id) on delete cascade,
  email       text not null unique,
  full_name   text,
  app_role    text not null default 'student',
  created_at  timestamptz not null default now(),
  constraint profiles_app_role_check
    check (app_role in ('admin', 'lecturer', 'student'))
);

-- 2.2 students: identity data, separated from credentials.
--     profile_id is UNIQUE, so it is already indexed.
create table if not exists public.students (
  id             bigint generated always as identity primary key,
  profile_id     uuid not null unique
                   references public.profiles (id) on delete restrict,
  student_number text not null unique,
  full_name      text not null,
  year_of_study  smallint not null,
  created_at     timestamptz not null default now(),
  constraint students_year_check check (year_of_study between 1 and 6)
);

-- 2.3 courses: lecturer_id anchors course-ownership checks.
create table if not exists public.courses (
  id           bigint generated always as identity primary key,
  course_code  text not null unique,
  title        text not null,
  lecturer_id  uuid not null
                 references public.profiles (id) on delete restrict,
  created_at   timestamptz not null default now()
);

-- 2.4 enrollments: protected marks. grade is derived from marks by a
--     trigger created in 02_rls_and_grants.sql.
create table if not exists public.enrollments (
  id          bigint generated always as identity primary key,
  student_id  bigint not null
                references public.students (id) on delete cascade,
  course_id   bigint not null
                references public.courses (id) on delete restrict,
  marks       numeric(5, 2),
  grade       text,
  updated_by  uuid references public.profiles (id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  constraint enrollments_student_course_key unique (student_id, course_id),
  constraint enrollments_marks_check check (marks between 0 and 100),
  constraint enrollments_grade_check check (grade in ('A', 'B', 'C', 'D', 'F'))
);

-- 2.5 audit_logs: append-only history. No foreign keys, on purpose:
--     deleting a student must never break or cascade into the log.
create table if not exists public.audit_logs (
  id                   bigint generated always as identity primary key,
  table_name           text not null,
  operation            text not null,
  record_id            text,
  changed_by_auth_uid  uuid,
  changed_by_db_role   text,
  old_data             jsonb,
  new_data             jsonb,
  changed_at           timestamptz not null default now(),
  constraint audit_logs_operation_check
    check (operation in ('INSERT', 'UPDATE', 'DELETE'))
);

-- ---------------------------------------------------------------------
-- 3. Indexes on columns used by RLS policies and joins.
--    Not needed (already covered by constraints):
--      students.profile_id     -> UNIQUE constraint index
--      enrollments.student_id  -> leading column of UNIQUE (student_id, course_id)
-- ---------------------------------------------------------------------
create index if not exists courses_lecturer_id_idx     on public.courses (lecturer_id);
create index if not exists enrollments_course_id_idx   on public.enrollments (course_id);
create index if not exists audit_logs_changed_at_idx   on public.audit_logs (changed_at desc);
create index if not exists audit_logs_table_record_idx on public.audit_logs (table_name, record_id);

-- ---------------------------------------------------------------------
-- 4. Helper functions (private schema).
--    SECURITY DEFINER lookups that read tables without triggering RLS,
--    which avoids infinite policy recursion (error 42P17).
--    search_path is empty, so every object is schema-qualified.
-- ---------------------------------------------------------------------

create or replace function private.current_app_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select p.app_role
  from public.profiles p
  where p.id = (select auth.uid());
$$;

create or replace function private.my_student_id()
returns bigint
language sql
stable
security definer
set search_path = ''
as $$
  select s.id
  from public.students s
  where s.profile_id = (select auth.uid());
$$;

create or replace function private.is_my_course(p_course_id bigint)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.courses c
    where c.id = p_course_id
      and c.lecturer_id = (select auth.uid())
  );
$$;

create or replace function private.is_student_in_my_course(p_student_id bigint)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.enrollments e
    join public.courses c on c.id = e.course_id
    where e.student_id = p_student_id
      and c.lecturer_id = (select auth.uid())
  );
$$;

-- Functions default to EXECUTE for PUBLIC. Lock them to signed-in users.
revoke all on function private.current_app_role()                   from public, anon, authenticated;
revoke all on function private.my_student_id()                      from public, anon, authenticated;
revoke all on function private.is_my_course(bigint)                 from public, anon, authenticated;
revoke all on function private.is_student_in_my_course(bigint)      from public, anon, authenticated;

grant execute on function private.current_app_role()                to authenticated;
grant execute on function private.my_student_id()                   to authenticated;
grant execute on function private.is_my_course(bigint)              to authenticated;
grant execute on function private.is_student_in_my_course(bigint)   to authenticated;

-- ---------------------------------------------------------------------
-- 5. Signup trigger: create a profiles row for every new auth user.
--    The role is HARD-CODED to 'student'. It is never read from
--    raw_user_meta_data, which users can edit. Promote the admin and
--    lecturers manually (see 05_seed_data.sql).
-- ---------------------------------------------------------------------
create or replace function private.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, full_name, app_role)
  values (
    new.id,
    coalesce(new.email, new.id::text),
    coalesce(new.raw_user_meta_data ->> 'full_name', new.email),
    'student'
  );
  return new;
end;
$$;

revoke all on function private.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function private.handle_new_user();

-- ---------------------------------------------------------------------
-- 6. Security baseline: RLS on, no privileges for API roles.
--    With RLS enabled and no policies, non-owner roles see nothing.
--    02_rls_and_grants.sql adds the minimum grants and policies.
-- ---------------------------------------------------------------------
alter table public.profiles    enable row level security;
alter table public.students    enable row level security;
alter table public.courses     enable row level security;
alter table public.enrollments enable row level security;
alter table public.audit_logs  enable row level security;

revoke all on public.profiles, public.students, public.courses,
              public.enrollments, public.audit_logs
  from public, anon, authenticated;

commit;

-- =====================================================================
-- VERIFICATION (run each query separately after the script succeeds)
-- =====================================================================

-- V1. RLS must be enabled on all five tables (relrowsecurity = true).
-- select c.relname, c.relrowsecurity
-- from pg_class c join pg_namespace n on n.oid = c.relnamespace
-- where n.nspname = 'public' and c.relkind = 'r'
-- order by c.relname;

-- V2. API roles must hold no table privileges yet. Expect 0 rows.
-- select grantee, table_name, privilege_type
-- from information_schema.role_table_grants
-- where table_schema = 'public' and grantee in ('anon', 'authenticated');

-- V3. Helper functions: anon = false, authenticated = true.
-- select has_function_privilege('anon',          'private.current_app_role()', 'execute') as anon_can_run,
--        has_function_privilege('authenticated', 'private.current_app_role()', 'execute') as authenticated_can_run;

-- V4. Signup trigger exists on auth.users.
-- select tgname from pg_trigger where tgname = 'on_auth_user_created';
