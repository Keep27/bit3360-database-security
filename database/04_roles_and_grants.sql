-- =====================================================================
-- 04_roles_and_grants.sql
-- BIT3360 Advanced Databases: Secure Student Records Management System
-- Block 4: standalone demo schema (RLS disabled), classic GRANT/REVOKE
--          SQL roles (TC-11 to TC-13), and SQL injection demo (TC-14).
--
-- Run in the Supabase SQL Editor (runs as the postgres role).
-- The demo schema is NOT exposed through the Data API.
-- =====================================================================

begin;

-- 1. Standalone demo schema (unexposed to API roles)
create schema if not exists demo;
revoke all on schema demo from public, anon, authenticated;

-- 2. Standalone SQL roles (granted to current_user so SET LOCAL ROLE works in tests)
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'demo_student') then
    create role demo_student nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'demo_lecturer') then
    create role demo_lecturer nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'demo_admin') then
    create role demo_admin nologin;
  end if;
end $$;

grant demo_student, demo_lecturer, demo_admin to postgres;
grant usage on schema demo to demo_student, demo_lecturer, demo_admin;

-- 3. Demo tables (RLS intentionally disabled; identity PKs need no sequence grants)
create table if not exists demo.students (
  id             bigint generated always as identity primary key,
  student_number text not null unique,
  full_name      text not null,
  national_id    text not null
);

create table if not exists demo.courses (
  id          bigint generated always as identity primary key,
  course_code text not null unique,
  title       text not null
);

create table if not exists demo.enrollments (
  id         bigint generated always as identity primary key,
  student_id bigint not null references demo.students (id) on delete cascade,
  course_id  bigint not null references demo.courses (id) on delete restrict,
  marks      numeric(5, 2) check (marks between 0 and 100),
  unique (student_id, course_id)
);

-- 4. Classic GRANT / REVOKE privileges (Section 6.2)
revoke all on demo.students, demo.courses, demo.enrollments from public, anon, authenticated;
revoke all on demo.students, demo.courses, demo.enrollments from demo_student, demo_lecturer, demo_admin;

-- demo_student: read courses + non-sensitive student columns only; no marks or writes
grant select on demo.courses to demo_student;
grant select (id, student_number, full_name) on demo.students to demo_student;

-- demo_lecturer: read all demo tables + update marks column only
grant select on demo.students, demo.courses, demo.enrollments to demo_lecturer;
grant update (marks) on demo.enrollments to demo_lecturer;

-- demo_admin: full DML on demo tables (no DDL / role creation)
grant select, insert, update, delete on demo.students, demo.courses, demo.enrollments to demo_admin;

-- 5. Seed synthetic demo records
insert into demo.students (student_number, full_name, national_id)
values
  ('ZUT2026001', 'Kabwe Zulu',    '111111/10/1'),
  ('ZUT2026002', 'Natasha Phiri', '222222/10/1'),
  ('ZUT2026003', 'Thabo Sakala',  '333333/10/1')
on conflict (student_number) do nothing;

insert into demo.courses (course_code, title)
values
  ('BIT3360', 'Advanced Databases'),
  ('BIT3410', 'Information Systems Security')
on conflict (course_code) do nothing;

insert into demo.enrollments (student_id, course_id, marks)
values
  (1, 1, 82.00),
  (1, 2, 68.00),
  (2, 1, 54.00)
on conflict (student_id, course_id) do nothing;

-- 6. SQL Injection Demonstration: Unsafe Concatenation vs. Safe Parameterisation (TC-14)
create or replace function demo.search_students_unsafe(p_query text)
returns table (id bigint, student_number text, full_name text)
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return query execute
    'select id, student_number, full_name from demo.students where full_name = ''' || p_query || '''';
end;
$$;

create or replace function demo.search_students_safe(p_query text)
returns table (id bigint, student_number text, full_name text)
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return query execute
    'select id, student_number, full_name from demo.students where full_name = $1'
    using p_query;
end;
$$;

revoke all on function demo.search_students_unsafe(text) from public, anon, authenticated;
revoke all on function demo.search_students_safe(text)   from public, anon, authenticated;
grant execute on function demo.search_students_unsafe(text) to demo_student, demo_lecturer, demo_admin;
grant execute on function demo.search_students_safe(text)   to demo_student, demo_lecturer, demo_admin;

commit;

-- V9. Quick smoke test for TC-14 (run in SQL Editor)
-- select 'unsafe' as mode, * from demo.search_students_unsafe($q$' OR '1'='1$q$);
-- select 'safe'   as mode, * from demo.search_students_safe($q$' OR '1'='1$q$);
