
## Documented residual risks

### CodeQL `js/http-to-file-access` in `server/ClaudeRequest.js` `writeCredentialsToFile`

- **Status:** suppressed inline (`// codeql[js/http-to-file-access]` on the two
  `writeFileSync` sinks), with the justification comment in the source. This is
  a by-design flow, documented here and in code — not a UI dismissal.
- **Why it cannot be "fixed":** the credentials file's entire purpose is to
  persist OAuth token strings issued by the Anthropic token endpoint. The token
  values are, by definition, data that originated from an HTTP response; no
  transformation can make them not-network-derived while keeping them valid
  credentials.
- **Hardening that IS applied:** payload must JSON-parse and match the expected
  `claudeAiOauth` shape (else refuse); values are re-serialized through a
  type-whitelisting depth-capped sanitizer (plain JSON scalars/containers
  only); destination is a fixed path under `~/.claude/.credentials.json`
  (atomic temp+rename, chmod 0600 on Unix); the WSL fallback receives the same
  sanitized payload.
- **Exposure:** the write target is never attacker-influenced (constant path);
  the sanitized content can only contain validated JSON scalars.
