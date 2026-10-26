Synthetic local test PKI for the ScrapeLens reference test servers.

Files:
  scrapelens-test-ca.crt.pem         test-only CA (trust anchor for CLI clients)
  scrapelens-test-ca.key.pem         test-only CA key (never use outside this repo)
  scrapelens-test-localhost.crt.pem  leaf for localhost, 127.0.0.1, ::1
  scrapelens-test-localhost.key.pem  leaf key
  scrapelens-test-localhost.crt.der  leaf DER
  spki-sha256-base64.txt             Chrome SPKI pin for the leaf

Use:
  curl --cacert scrapelens-test-ca.crt.pem https://127.0.0.1:8782/...
  Chrome: --ignore-certificate-errors-spki-list=<pin from spki-sha256-base64.txt>

Do NOT install the CA in the system keychain. The CA is valid 2026-01-01..2036-01-01
and exists only so the servers can be trusted explicitly by the test harness.
Regenerate (new keys, new pin):
  cargo run -p scrapelens-testserver -- gen-cert --force
