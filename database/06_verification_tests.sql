
-- TC-08: Admin reads all students and enrollments (Expect 3 students, 4 enrollments)
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', (select id::text from public.profiles where email = 'admin@bit3360.test'), true);
select set_config('request.jwt.claims', json_build_object('sub', (select id from public.profiles where email = 'admin@bit3360.test'), 'role', 'authenticated')::text, true);
select count(*) as total_students from public.students;
select count(*) as total_enrollments from public.enrollments;
rollback;

-- TC-09: Admin attempts to delete from audit_logs (Expect ERROR 42501)
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', (select id::text from public.profiles where email = 'admin@bit3360.test'), true);
select set_config('request.jwt.claims', json_build_object('sub', (select id from public.profiles where email = 'admin@bit3360.test'), 'role', 'authenticated')::text, true);
delete from public.audit_logs;
rollback;

-- TC-10: Verify audit_logs captures actor UID, DB role, and OLD/NEW JSONB diff
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', (select id::text from public.profiles where email = 'lecturer1@bit3360.test'), true);
select set_config('request.jwt.claims', json_build_object('sub', (select id from public.profiles where email = 'lecturer1@bit3360.test'), 'role', 'authenticated')::text, true);
update public.enrollments set marks = 80
where student_id = (select id from public.students where student_number = 'ZUT2026002');
set local role postgres;
select id, table_name, operation, changed_by_auth_uid, changed_by_db_role,
       old_data->>'marks' as old_marks, new_data->>'marks' as new_marks, new_data->>'grade' as new_grade
from public.audit_logs
order by id desc limit 1;
rollback;

-- TC-11: Classic SQL role demo_student (column grant vs. denied column/table)
begin;
set local role demo_student;
select id, student_number, full_name from demo.students; -- Expect 3 rows
-- Run next line separately to confirm ERROR 42501:
-- select national_id from demo.students;
rollback;

-- TC-12: Classic SQL role demo_lecturer (UPDATE marks vs. DELETE)
begin;
set local role demo_lecturer;
update demo.enrollments set marks = 85 where id = 1 returning *; -- Expect 1 row
-- Run next line separately to confirm ERROR 42501:
-- delete from demo.enrollments where id = 1;
rollback;

-- TC-13: Classic SQL role demo_admin (DML succeeds, DDL fails with 42501)
begin;
set local role demo_admin;
insert into demo.students (student_number, full_name, national_id) values ('ZUT2026099', 'Temp Test', '999999/10/1') returning *;
-- Run next line separately to confirm ERROR 42501:
-- create table demo.unauthorized_table (id int);
rollback;

-- TC-14: SQL Injection comparison (Unsafe vs. Parameterised)
select 'unsafe' as mode, * from demo.search_students_unsafe($q$' OR '1'='1$q$);
select 'safe'   as mode, * from demo.search_students_safe($q$' OR '1'='1$q$);

-- TC-08: Admin reads all students and enrollments (Expect 3 students, 4 enrollments)
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', (select id::text from public.profiles where email = 'admin@bit3360.test'), true);
select set_config('request.jwt.claims', json_build_object('sub', (select id from public.profiles where email = 'admin@bit3360.test'), 'role', 'authenticated')::text, true);
select count(*) as total_students from public.students;
select count(*) as total_enrollments from public.enrollments;
rollback;

-- TC-09: Admin attempts to delete from audit_logs (Expect ERROR 42501)
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', (select id::text from public.profiles where email = 'admin@bit3360.test'), true);
select set_config('request.jwt.claims', json_build_object('sub', (select id from public.profiles where email = 'admin@bit3360.test'), 'role', 'authenticated')::text, true);
delete from public.audit_logs;
rollback;

-- TC-10: Verify audit_logs captures actor UID, DB role, and OLD/NEW JSONB diff
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', (select id::text from public.profiles where email = 'lecturer1@bit3360.test'), true);
select set_config('request.jwt.claims', json_build_object('sub', (select id from public.profiles where email = 'lecturer1@bit3360.test'), 'role', 'authenticated')::text, true);
update public.enrollments set marks = 80
where student_id = (select id from public.students where student_number = 'ZUT2026002');
set local role postgres;
select id, table_name, operation, changed_by_auth_uid, changed_by_db_role,
       old_data->>'marks' as old_marks, new_data->>'marks' as new_marks, new_data->>'grade' as new_grade
from public.audit_logs
order by id desc limit 1;
rollback;

-- TC-11: Classic SQL role demo_student (column grant vs. denied column/table)
begin;
set local role demo_student;
select id, student_number, full_name from demo.students; -- Expect 3 rows
-- Run next line separately to confirm ERROR 42501:
-- select national_id from demo.students;
rollback;

-- TC-12: Classic SQL role demo_lecturer (UPDATE marks vs. DELETE)
begin;
set local role demo_lecturer;
update demo.enrollments set marks = 85 where id = 1 returning *; -- Expect 1 row
-- Run next line separately to confirm ERROR 42501:
-- delete from demo.enrollments where id = 1;
rollback;

-- TC-13: Classic SQL role demo_admin (DML succeeds, DDL fails with 42501)
begin;
set local role demo_admin;
insert into demo.students (student_number, full_name, national_id) values ('ZUT2026099', 'Temp Test', '999999/10/1') returning *;
-- Run next line separately to confirm ERROR 42501:
-- create table demo.unauthorized_table (id int);
rollback;

-- TC-14: SQL Injection comparison (Unsafe vs. Parameterised)
select 'unsafe' as mode, * from demo.search_students_unsafe($q$' OR '1'='1$q$);
select 'safe'   as mode, * from demo.search_students_safe($q$' OR '1'='1$q$);
