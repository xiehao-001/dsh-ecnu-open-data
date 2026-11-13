# ECNU open data

`@eduwork/dsh-ecnu-open-data` · v0.1.0 · MulanPSL-2.0 AND MIT

Read-only access to the East China Normal University open-data platform from a DeepSeek Harness session: personnel lookup, student and staff profiles, portraits, identity-governance positions, and one allowlisted query tool for the rest of the gateway.

The university exposes two OAuth2 surfaces, and this plugin keeps them apart. Institutional reads use the platform client credentials, which the platform explicitly allows to run concurrently. Data that belongs to one person uses the university SSO authorization-code flow, caught on a loopback port, so a read may omit the school work number and still return the signed-in user's own record.

## Highlights

- Eight read-only tools; no endpoint in this plugin writes anything.
- Two credentials paths with no silent fallback: `mode=institutional` never uses a personal token, `mode=personal` never uses client credentials.
- One shared client token per session, refreshed five minutes before expiry, re-issued once when the gateway answers `A401OT`.
- Local token bucket under the platform's 300 requests per minute per application ceiling.
- The generic query tool is an allowlist; certificate numbers, facial recognition, identity verification, message sending, app management and sync endpoints are refused before any request leaves the machine.
- Identifier card numbers are masked in every result and the tool output is capped.
- Session state lives in `$DSH_HOME/ecnu-open-data/user-token.json` (mode 0600) and is removed by `ecnu_open_logout`.

## Install

```sh
dsh plugin --profile web add https://github.com/xiehao-001/dsh-ecnu-open-data
```

Offline, point the same command at the local directory instead.

## Configuration

The bundle patch installs one row with the public defaults. Credentials never sit in the profile: they are read from the DSH credential store.

| Setting | Default | Meaning |
| --- | --- | --- |
| `apiBaseURL` | `https://api.ecnu.edu.cn` | Gateway origin; `/api/v1` is appended per call. |
| `ssoBaseURL` | `https://sso.ecnu.edu.cn` | SSO origin for the authorize, token, profile and logout endpoints. |
| `scope` | `ECNU-Basic` | Requested OAuth2 scope. |
| `redirectUri` | `http://127.0.0.1:47823/oauth2/callback` | Loopback redirect; must match the value registered with the platform. |
| `clientIdRef` | `ECNU_OPENAPI_CLIENT_ID` | Credential reference for the public client id. |
| `clientSecretRef` | `ECNU_OPENAPI_CLIENT_SECRET` | Credential reference for the client secret. |
| `userTokenRef` | `ECNU_OPENAPI_USER_TOKEN` | Optional pasted personal token; wins over the browser flow. |
| `requestTimeoutMs` | `20000` | Per-request timeout. |
| `rateLimitPerMinute` | `240` | Local pacing; the platform default is 300. |
| `allowGenericQuery` | `true` | Set to `false` to keep only the five dedicated reads. |
| `recordLimit` | `200` | Maximum records kept per result. |

`apiBaseURL` and `ssoBaseURL` may also come from `ECNU_OPENAPI_BASE_URL` and `ECNU_OPENAPI_SSO_URL`. Put the three credential values in `$DSH_HOME/.credentials.yaml` (or the profile's credential store) under `refs`.

## Tools

| Tool | Reads | Notes |
| --- | --- | --- |
| `ecnu_open_auth_status` | – | Whether client credentials are configured, whether a person is signed in, token lifetime. |
| `ecnu_open_login` | – | Returns the authorize URL; the loopback receiver catches the redirect, then `ecnu_open_auth_status` shows the result. |
| `ecnu_open_logout` | – | Forgets the person locally and stops the loopback listener. |
| `ecnu_open_user_info` | `/user/info` | Name, identity type, department, active status. |
| `ecnu_open_user_profile` | `/user/profile/{student,staff,bks,yjs}` | Full profile with optional field selection. |
| `ecnu_open_positions` | `/user/position`, `/user/positionusers` | Person to positions, or position to people. |
| `ecnu_open_user_photo` | `/user/photo` | Base64 data URL, capped at 512 KiB. |
| `ecnu_open_query` | allowlisted `/api/v1/*` | The escape hatch for directories, teaching and campus-card reads. |

`mode` accepts `auto` (default), `institutional` or `personal`. `auto` prefers a signed-in person because that path may omit `userId`, and falls back to client credentials.

## Requirements

- DSH `>=0.2.1 <0.3.0` and `@deepseek-ai/dsh-tools >=0.1.2-rc.1`.
- A developer account on the ECNU open platform with client credentials, plus approval for each data category you need.
- The gateway answers only from campus networks; off campus the requests fail at the network edge, which the plugin reports as a network error rather than a credential problem.
- The authorization-code redirect must be registered with the platform exactly as `redirectUri`, including the port.

## Notes and limits

- Every read is a GET. The plugin deliberately has no write, message or sync tool.
- A `client_credentials` token is valid for two hours; the authorization-code flow issues tokens per person and requires a `refresh_token` to survive expiry. The client secret is used for the refresh as well, which is why it stays in the credential store and never in the profile.
- The platform allows one authorization-code token per user per application; signing in from another machine can invalidate this one, and the next read re-issues or reports the failure.
- Portraits and profiles are personal data. Results stay in this conversation, are never written to disk except the token cache above, and the plugin logs no payloads.
- Limited validation: the tool wiring, token handling, allowlist and loopback login are covered by `tools/test-ecnu-open-data.mjs` (21 checks) and `tools/e2e-ecnu-open-data.mjs` (14 checks) against a mock gateway. Nothing here has been exercised against the real ECNU gateway, because that needs an approved client id and a campus network address.

## 中文文档

See [README.zh-CN.md](./README.zh-CN.md).

## License

Mulan PSL v2 with an MIT part for the plugin shell; see [LICENSE](./LICENSE), [LICENSE-MIT](./LICENSE-MIT) and [LICENSING.md](./LICENSING.md).
