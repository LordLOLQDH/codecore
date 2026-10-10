# CODECORE

Secure code-management foundation for vouchers, TOTP authentication, administration and API integrations.

**Status: foundation in progress.** The responsive landing page and initial database migration are present. The complete product is not yet deploy-ready: Edge Functions, full authentication flows, TOTP secret encryption and automated integration tests still need to be implemented and run.

## Stack
- GitHub Pages: static frontend hosting
- Supabase PostgreSQL: transactional data and constraints
- Supabase Auth: identity and sessions
- Supabase Edge Functions: privileged operations and external API
- Lightweight HTML/CSS frontend

## Repository structure
```text
.
├── index.html
├── styles.css
└── supabase/
    └── migrations/
        └── 20261010000100_initial_schema.sql
```

## Requirements
- GitHub account and `LordLOLQDH/CODECORE`
- Free Supabase project
- Supabase CLI recommended for local development and Edge Function deployment

## Database setup
1. Create a Supabase project at https://supabase.com/dashboard.
2. Open **SQL Editor**.
3. Run `supabase/migrations/20261010000100_initial_schema.sql`.
4. Verify the tables in **Table Editor**.
5. Never put service-role or secret keys in GitHub Pages.

The migration creates profiles, vouchers, redemption records, TOTP factor storage, API key metadata and audit logs. RLS is enabled. Voucher redemption uses a row lock and unique constraint to protect against concurrent and repeated redemptions.

### Set the first administrator
After creating the user through Supabase Auth, run this in SQL Editor with that user's real Auth UUID:
```sql
insert into public.profiles (user_id, display_name, role)
values ('REPLACE-WITH-AUTH-USER-UUID', 'Administrator', 'admin')
on conflict (user_id) do update set role = 'admin';
```
Never let users update their own role.

## Frontend deployment
1. Open repository **Settings → Pages**.
2. Choose deployment from branch `main` and folder `/(root)`.
3. Save and wait for the deployment.
4. The current static page is not connected to Supabase authentication or privileged operations. Status labels are not proof that a backend has been deployed.

## Security design
- Browser code may only use a Supabase publishable key.
- Keep service-role/secret keys and TOTP encryption keys in Supabase Edge Function secrets.
- Never return TOTP secrets after setup; display a provisioning QR only during setup and require a valid code before enabling a factor.
- Hash API keys before storage and show a newly generated key only once.
- Check administrator permissions server-side against trusted database roles.
- Add rate limits and generic errors to authentication and verification endpoints.
- TOTP replay prevention requires an atomic database update accepting only a time step newer than the last accepted step.
- Review RLS and grants whenever adding tables, views or functions.

## Voucher redemption
The migration includes `public.redeem_voucher(p_code_hash)`. It requires an authenticated user, locks the voucher row, checks disabled/expiry/limits, then inserts a unique redemption in one transaction. A server-side function must calculate the hash consistently before calling it. Do not expose voucher hashes or privileged voucher-management operations to clients.

## TOTP status
The schema includes encrypted-secret storage and a last-accepted time-step field. Provisioning, QR generation, encrypted storage, verification, atomic replay protection and rate limiting still need implementation before production use. Do not store plaintext TOTP secrets.

## API status
The public verification API is not deployed yet. It must use HTTPS, revocable API keys, server-side key hashing, rate limiting, minimal responses and logs that never record raw codes or secrets.

## Testing checklist
Before production, add and run tests for valid/invalid/expired/disabled vouchers, redemption limits and concurrency, duplicate redemption, TOTP validity and replay rejection, RLS isolation, unauthorized admin calls, API key revocation, rate limiting and secret redaction.

**No test results are claimed here.** Apply the migration to a disposable Supabase project and run database and Edge Function tests before relying on CODECORE for real accounts or benefits.

## License
No license has been specified yet.

## Deploy Edge Functions

Install the Supabase CLI and authenticate it, then link this repository to your project:

```sh
supabase login
supabase link --project-ref YOUR_PROJECT_REF
supabase db push
supabase functions deploy voucher-api
supabase functions deploy totp-api
supabase functions deploy admin-api
```

Set a 32-byte random TOTP encryption key encoded as Base64. Generate one locally with:

```sh
openssl rand -base64 32
supabase secrets set TOTP_ENCRYPTION_KEY=PASTE_GENERATED_VALUE
```

Supabase automatically provides `SUPABASE_URL`, `SUPABASE_ANON_KEY` and `SUPABASE_SERVICE_ROLE_KEY` to Edge Functions. Never copy the service-role key into browser files or commit it to GitHub.

### Connect the frontend

Edit `app.js` and replace `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` with the project URL and publishable/anon key from Supabase project settings. These are public client values; service-role keys are not.

### Important remaining production checks

The TOTP module is an implementation draft and must be tested against the deployed schema before production use. In particular, verify the atomic replay-protection RPC with an authenticated user context, factor removal permissions, signup profile provisioning, QR provisioning and code-window handling. The external API-key verification flow and rate limiting also require implementation before third-party apps should rely on this service.
