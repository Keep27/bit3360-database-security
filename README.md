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