Synthetic local test PKI for the ScrapeLens reference test servers.

Nothing here is tracked except this README. The certificates and keys are generated
(synthetic, valid 2026-01-01..2036-01-01) and ignored by git:

  scrapelens-test-ca.crt.pem         test-only CA (trust anchor for CLI clients)
  scrapelens-test-ca.key.pem         test-only CA key (never use outside this repo)
  scrapelens-test-localhost.crt.pem  leaf for localhost, 127.0.0.1, ::1
  scrapelens-test-localhost.key.pem  leaf key
  scrapelens-test-localhost.crt.der  leaf DER
  spki-sha256-base64.txt             Chrome SPKI pin for the leaf

Generate them (from the repository root; a folder that already has them is kept):
  cargo run -p scrapelens-testserver -- gen-cert            # this folder
  cargo run -p scrapelens-testserver -- gen-cert --force    # new keys, new pin

The test suites of testserver do not use this folder: they generate their own
certificates in the system temp folder, once per process.

Use:
  curl --cacert scrapelens-test-ca.crt.pem https://127.0.0.1:8782/...
  Chrome: --ignore-certificate-errors-spki-list=<pin from spki-sha256-base64.txt>

Do NOT install the CA in the system keychain. The CA exists only so the servers can be
trusted explicitly by the test harness.
