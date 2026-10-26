# experiments/ — prova de fidelidade de captura

Pergunta: **quais fontes e eventos preservam qual sequência de headers em
HTTP/1.1, h2 e h3 no Chrome 156.0.8078.48?**

Resultado consolidado em [`../docs/02-matriz-fidelidade.md`](../docs/02-matriz-fidelidade.md).
Tudo aqui é sintético, local (127.0.0.1) e temporário.

## O que roda

| Peça | Arquivo | Papel |
|---|---|---|
| Servidor h1 | `servers/h1_raw.py` | socket cru, sem biblioteca HTTP: ordem e repetição exatas |
| Servidor h2 | `servers/h2_tls.py` | `h2`/HPACK: lista de pares decodificada |
| Servidor h3 | `servers/h3_quic.py` | `aioquic`/QPACK: lista de pares decodificada |
| Launcher | `capture/launch_chrome.py` | perfil dedicado temporário, debug só em 127.0.0.1, `--log-net-log` |
| Cliente CDP | `capture/cdp_capture.mjs` | grava eventos Network.* crus, sem normalizar headers |
| Orquestrador | `run_experiment.py` | servidores → Chrome → CDP → NetLog → análise |
| Comparador | `compare.py` | três camadas por requisição + `layers.json`/`report.md` |
| HAR derivado | `har_from_cdp.mjs` | HAR 1.2 a partir de CDP (fixture; não é o exportador do DevTools) |
| Cross-check | `crosscheck_contract.py` | mesmo pipeline contra `testserver/` (Rust/httlib-hpack/quiche) |

Portas: **8781** h1, **8782** h2/TLS, **8783** h3/QUIC. Certificado autoassinado
gerado em `certs/` e dispensado no Chrome por `--ignore-certificate-errors-spki-list`
(nada é instalado no sistema). h3 é forçado com `--origin-to-force-quic-on`,
sem desabilitar QUIC.

## Reproduzir

```bash
cd experiments
python3 -m venv .venv
.venv/bin/pip install h2 aioquic
.venv/bin/python certs/gen_cert.py
.venv/bin/python run_experiment.py --all     # 9 experimentos, ~3 min
.venv/bin/python compare.py                  # layers.json + report.md + matrix.json
node har_from_cdp.mjs results/h1-page
```

Um experimento isolado:

```bash
.venv/bin/python run_experiment.py --exp h2-ordered
.venv/bin/python compare.py
```

Cross-check contra os servidores do contrato (somente leitura em
`testserver/` e `fixtures/`):

```bash
.venv/bin/python crosscheck_contract.py --proto all   # h1, h2 e h3
```

Resultado: h1 14/14 idêntico; h2 confirma o `cookie` fundido no log; **h3 falha
no servidor de contrato** (`ERR_QUIC_PROTOCOL_ERROR` / `CERTIFICATE_VERIFY_FAILED`,
reproduzido também com um cliente `aioquic`), então a linha h3 vem do mock.

`run_experiment.py --list` mostra os nomes. Cada execução grava em
`results/<experimento>/`:

- `plan.json` — URLs, modo (`native`/`ordered`), headers injetados;
- `cdp-events.jsonl` — todo evento Network.* na ordem de emissão;
- `fetch-decisions.jsonl` — header list entregue a `Fetch.continueRequest`;
- `chrome-netlog.json` — NetLog (`--net-log-capture-mode=Everything`);
- `server-h{1,2,3}.jsonl` — referência: pares decodificados + headers de resposta;
- `layers.json` — as três camadas comparadas por requisição;
- `report.md` — leitura humana; `run.json` — versão do Chrome e integridade do NetLog.

## Experimentos

| Nome | O que exercita |
|---|---|
| `h1-plain` / `h2-plain` / `h3-plain` | navegação GET simples |
| `h1-page` / `h2-page` / `h3-page` | `/setcookie` (2× Set-Cookie) e `/page`: cada documento dispara 2 GET, 1 POST e 1 fetch com `Headers` da Fetch API, todos com cookies |
| `h1-ordered` / `h2-ordered` / `h3-ordered` | ordem + duplicatas impostas por `Fetch.continueRequest` |

## Achados que a matriz usa

1. `requestWillBeSentExtraInfo.headers` é um **mapa ordenado em ASCII** e já vem
   sem duplicatas; `requestWillBeSent.headers` é só o subconjunto do Blink.
2. `responseReceivedExtraInfo.headersText` (h1) é o único lugar do CDP com a
   ordem bruta da resposta; o objeto `headers` funde repetições com `\n`.
3. NetLog de envio h1 preserva ordem, caixa e duplicatas; em h2/h3 o evento de
   sessão pode inverter `priority`/`cookie`, e o `Cookie` aparece como 1 campo
   mesmo quando o fio leva N.
4. NetLog de recepção h2/h3 funde duplicatas com `\x00`; o evento
   `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` mantém as repetições separadas.
5. Header fornecido por API não sai como entrou: `Fetch.continueRequest` com 6
   pares (3 duplicados) chega como 3 pares (último valor vence); `Headers` da
   Fetch API funde `append()` em `"a, b"`.

## Cuidados aplicados

- Perfil em `results/<exp>/chrome-profile` (apagado ao final); nunca o perfil pessoal.
- `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`: nenhum tráfego externo.
- Encerra apenas o processo iniciado pelo launcher (`os.killpg` do grupo criado).
- NetLog em modo `Everything` contém cookies — todos sintéticos (`sl_a`, `sl_b`).
  O produto deve avisar o usuário antes de usar esse modo.
- NetLog inválido/truncado é registrado como `netlog_valid_json: false`, sem
  descartar a sessão parcial.
