-- =====================================================================
-- 03_audit_trigger.sql
-- BIT3360 Advanced Databases: Secure Student Records Management System
-- Block 3: tamper-resistant, trigger-based audit logging (FR-06, FR-07).
--
-- Prerequisite: 01_schema.sql and 02_rls_and_grants.sql executed.
-- Run in the Supabase SQL Editor (runs as the postgres role).
-- =====================================================================

begin;

create or replace function private.log_record_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_record_id text;
  v_old_data  jsonb;
  v_new_data  jsonb;
begin
  if tg_op = 'INSERT' then
    v_record_id := new.id::text;
    v_old_data  := null;
    v_new_data  := to_jsonb(new);
  elsif tg_op = 'UPDATE' then
    v_record_id := new.id::text;
    v_old_data  := to_jsonb(old);
    v_new_data  := to_jsonb(new);
  elsif tg_op = 'DELETE' then
    v_record_id := old.id::text;
    v_old_data  := to_jsonb(old);
    v_new_data  := null;
  end if;

  insert into public.audit_logs (
    table_name,
    operation,
    record_id,
    changed_by_auth_uid,
    changed_by_db_role,
    old_data,
    new_data
  ) values (
    tg_table_name,
    tg_op,
    v_record_id,
    (select auth.uid()),
    current_setting('role', true),
    v_old_data,
    v_new_data
  );

  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

revoke all on function private.log_record_change() from public, anon, authenticated;

drop trigger if exists audit_profiles_changes on public.profiles;
create trigger audit_profiles_changes
  after insert or update or delete on public.profiles
  for each row execute function private.log_record_change();

drop trigger if exists audit_students_changes on public.students;
create trigger audit_students_changes
  after insert or update or delete on public.students
  for each row execute function private.log_record_change();

drop trigger if exists audit_courses_changes on public.courses;
create trigger audit_courses_changes
  after insert or update or delete on public.courses
  for each row execute function private.log_record_change();

drop trigger if exists audit_enrollments_changes on public.enrollments;
create trigger audit_enrollments_changes
  after insert or update or delete on public.enrollments
  for each row execute function private.log_record_change();

commit;

-- V7. Confirm all 4 audit triggers exist (expect 4 rows)
-- select event_object_table as table_name, trigger_name
-- from information_schema.triggers
-- where trigger_schema = 'public' and trigger_name like 'audit_%_changes'
-- order by 1;
