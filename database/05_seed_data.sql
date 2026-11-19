-- =====================================================================
-- 05_seed_data.sql
-- BIT3360 Advanced Databases: Secure Student Records Management System
-- Block 3: promote admin/lecturers and seed synthetic domain records
--          (1 admin, 2 lecturers, 3 students, 2 courses, 4 enrolments).
--
-- Prerequisite:
--   1. 01_schema.sql, 02_rls_and_grants.sql, and 03_audit_trigger.sql run.
--   2. Create the 6 synthetic users in Dashboard > Authentication > Users:
--      admin@bit3360.test, lecturer1@bit3360.test, lecturer2@bit3360.test,
--      student.a@bit3360.test, student.b@bit3360.test, student.c@bit3360.test
-- Run in the Supabase SQL Editor (runs as the postgres role).
-- =====================================================================

begin;

-- Guard: fail clearly if any of the 6 Auth accounts was not created yet.
do $$
declare
  v_count int;
begin
  select count(*) into v_count
  from public.profiles
  where email in (
    'admin@bit3360.test',
    'lecturer1@bit3360.test',
    'lecturer2@bit3360.test',
    'student.a@bit3360.test',
    'student.b@bit3360.test',
    'student.c@bit3360.test'
  );

  if v_count < 6 then
    raise exception 'Expected all 6 synthetic Auth users in public.profiles, found %', v_count;
  end if;
end $$;

-- 1. Promote administrator and lecturers; set display names
update public.profiles set full_name = 'Chanda Mwale',      app_role = 'admin'    where email = 'admin@bit3360.test';
update public.profiles set full_name = 'Dr. Bwalya Tembo',  app_role = 'lecturer' where email = 'lecturer1@bit3360.test';
update public.profiles set full_name = 'Prof. Mutale Banda',app_role = 'lecturer' where email = 'lecturer2@bit3360.test';
update public.profiles set full_name = 'Kabwe Zulu'                               where email = 'student.a@bit3360.test';
update public.profiles set full_name = 'Natasha Phiri'                            where email = 'student.b@bit3360.test';
update public.profiles set full_name = 'Thabo Sakala'                             where email = 'student.c@bit3360.test';

-- 2. Seed 3 students (Student A, Student B, Student C)
insert into public.students (profile_id, student_number, full_name, year_of_study)
values
  ((select id from public.profiles where email = 'student.a@bit3360.test'), 'ZUT2026001', 'Kabwe Zulu',    3),
  ((select id from public.profiles where email = 'student.b@bit3360.test'), 'ZUT2026002', 'Natasha Phiri', 3),
  ((select id from public.profiles where email = 'student.c@bit3360.test'), 'ZUT2026003', 'Thabo Sakala',  2)
on conflict (profile_id) do nothing;

-- 3. Seed 2 courses (one per lecturer)
insert into public.courses (course_code, title, lecturer_id)
values
  ('BIT3360', 'Advanced Databases',           (select id from public.profiles where email = 'lecturer1@bit3360.test')),
  ('BIT3410', 'Information Systems Security', (select id from public.profiles where email = 'lecturer2@bit3360.test'))
on conflict (course_code) do nothing;

-- 4. Seed 4 enrolments (A-C1, A-C2, B-C1, C-C2); grades auto-derived by trigger
insert into public.enrollments (student_id, course_id, marks)
values
  ((select id from public.students where student_number = 'ZUT2026001'), (select id from public.courses where course_code = 'BIT3360'), 82.00),
  ((select id from public.students where student_number = 'ZUT2026001'), (select id from public.courses where course_code = 'BIT3410'), 68.00),
  ((select id from public.students where student_number = 'ZUT2026002'), (select id from public.courses where course_code = 'BIT3360'), 54.00),
  ((select id from public.students where student_number = 'ZUT2026003'), (select id from public.courses where course_code = 'BIT3410'), 45.00)
on conflict (student_id, course_id) do nothing;

commit;

-- V8. Verify seeded counts, auto-derived grades, and audit trail
-- select (select count(*) from public.profiles)    as profiles_cnt,
--        (select count(*) from public.students)    as students_cnt,
--        (select count(*) from public.courses)     as courses_cnt,
--        (select count(*) from public.enrollments) as enrollments_cnt,
--        (select count(*) from public.audit_logs)  as audit_logs_cnt;
