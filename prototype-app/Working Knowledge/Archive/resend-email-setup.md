# Final Resend email configuration

Email configuration and workflows verified on 1 November 2026 (Asia/Kolkata); account inventory rechecked on 5 November 2026.

## Configuration

- Provider: Resend, connected and configured through MCP.
- Source repository: [AxC-SG/SG](https://github.com/AxC-SG/SG), repository ID `1427276590`. GitHub confirmed this current owner on 5 November 2026; earlier `AxonCyber-SG` and `AxG-SG` references name previous locations of this repository. Resend is an API-based delivery provider; the Render backend owns the Git source connection. See [deployment sources](deployment-sources.md) for the repository migration status.
- Verified sending domain: `scoutgrid.io`; DKIM and SPF verified, sending enabled.
- Sender: `Scout.ai <noreply@scoutgrid.io>`.
- Application key: `ScoutGrid_Application_Email_2026_11`, sending-only and restricted to the verified domain.
- Hosted backend: `scout-backend` in the confirmed Scout Render workspace.
- Hosted activation destination: `https://scoutgrid.io`.
- Open and click tracking: disabled. Receiving remains disabled; outbound transactional email does not require it.
- Runtime email secrets reside in Render service environment settings and the ignored private `backend/.env.local` file. No credential values are in this document or committed source.
- Superseded credential cleanup: completed after explicit confirmation. `Scout_Render_Production_v2`, `Scout_Render_Production`, and `Onboarding` were revoked through Resend MCP. A subsequent key listing confirmed only `ScoutGrid_Application_Email_2026_11` remains.

The 5 November account check confirmed that the same application key is the only remaining key, `scoutgrid.io` is verified with sending enabled, and no webhooks are configured. Recent provider logs retain successful application `POST /emails` requests from 1 November. This recheck did not change credentials, send email, or establish a new hosted end-to-end delivery result. A repository transfer does not require recreating the Resend domain or key.

The Render configuration update merged only `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `RESEND_FROM_DOMAIN`, and `APP_DEMO_APP_BASE_URL`. Other service configuration was preserved. Render automatically deployed the update, and deployment `dep-dbjdierbc2fs73ch0m6g` reached `live`. Both the hosted readiness endpoint and public login destination returned HTTP 200.

The checked-in Blueprint declares the same non-secret sender/domain/hosted URL and retains `sync: false` for the API key. Backend runtime and bootstrap CLI defaults now use the verified domain. Local activation links retain the configured local frontend destination.

## Verification

33 targeted regression tests passed across the Resend client, email composition, tenant invitation services/controllers, and demo approval service/controller. The additional sender regression checks empty configuration defaults to the verified domain.

A real local application workflow exercised the existing PostgreSQL runtime and actual Resend API. The initial owner approval used a short-lived token signed by the local test configuration because the saved local owner password was stale. No existing owner's credentials were changed. Subsequent tenant administrator and member logins used passwords established through delivered invitations.

- public request accepted.
- platform owner approval created tenant.
- invitation queued.
- email activation token validates.
- HttpOnly setup cookie issued.
- CSRF password setup succeeds.
- tenant administrator login succeeds with scoped access.
- tenant member invitation queued.
- member invitation accepted.
- member password setup succeeds.
- member login succeeds.
- member cannot access platform approval queue.
- accepted demo and member invitation tokens cannot be reused.

Resend confirmed `delivered` for these controlled test messages:

| Message | Resend email ID |
| --- | --- |
| MCP sender check | `01a195c2-cfcc-77cf-be1e-a4a7d0ad2fed` |
| Approved tenant activation | `01a195c4-3a9a-758e-92e4-68fde0b27b7a` |
| Tenant member invitation | `01a195c4-ec36-7b63-8f2b-e06ee66ae2cb` |

Application outbox records for both invitations reached `ACCEPTED` on their first attempt with matching provider IDs. Application acceptance and Resend delivery are separate observations; acceptance alone is not treated as mailbox delivery.

Recipients were Resend's official `delivered+...@resend.dev` test addresses, which simulate successful delivery. These checks do not establish inbox placement at a real customer's mailbox. The complete approval and activation workflow was tested locally; hosted configuration, deployment and health were verified, but an authenticated hosted approval journey was not run.

The synthetic local tenant `aff57d25-3738-4b63-884b-1084375076b1` is suspended after testing. Administrative tenant deletion is deliberately disabled in the application, so that restriction was preserved. The local Docker backend was recreated with the corrected project mount after the project moved to `Desktop/Code/SG`; its former container remains stopped as `sg-ui-review-backend-before-resend` for recovery.

## Operation

Approval and member invitations use the existing encrypted transactional outbox. The runtime must include worker scheduling (`APP_RUNTIME_ROLE=all` or a separately configured worker), a consistent credential encryption key, and the Resend sending key. Unknown outcomes retain the existing bounded retry and reconciliation policy. Webhooks were not configured because this application does not currently expose a Resend delivery-event handler.

The source defaults and Blueprint preserve the final email configuration for future deployments. The hosted environment configuration was applied and verified independently through Render MCP.

After revocation, a fresh API request authenticated with the final key in the private runtime configuration was accepted, and Resend MCP confirmed the message as `delivered`. Provider message ID: `01a195cc-628d-7d98-b87c-7a477eda809e`.

## Fresh successful workflow test after credential cleanup

Run on 1 November 2026, after all three old keys were revoked. The local application used the final configured key and the real Resend API. Official Resend test recipients simulated successful delivery; this was not a hosted browser journey or a real customer inbox placement test.

- Public request submission and platform owner approval passed.
- Application status progressed from `QUEUED` to `SENT` / `INVITE_SENT`.
- Tenant activation email was confirmed `delivered` by Resend MCP at 12:00:59 IST.
- Invitation acceptance, HttpOnly setup cookie, CSRF-protected password establishment, and tenant administrator password login passed.
- Tenant administrator member invitation was confirmed `delivered` by Resend MCP at 12:01:14 IST.
- Member password setup and login passed with `READ_ONLY_AUDITOR` access; platform approval access was denied with HTTP 403.
- Both outbox records reached `ACCEPTED` on attempt 1 and matched the Resend message IDs. Exactly one outbox record existed per invitation.
- Accepted invitation tokens could not be reused.
- The synthetic local tenant was suspended after testing, and temporary test passwords/tokens were removed from the test state.

| Message | Resend ID | Confirmed status |
| --- | --- | --- |
| Tenant activation | `01a195cd-de1d-7bc7-882b-9299c9d7e382` | delivered |
| Member invitation | `01a195ce-1a76-7d57-813c-aeaca9bfd9d6` | delivered |

Synthetic local tenant: `cfaf627d-568e-487b-b8fc-b5444003b982`.
