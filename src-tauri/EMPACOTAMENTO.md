# Empacotamento — bundle final validado

Estado do pacote entregue nesta rodada. Serve como evidência reprodutível: os
comandos abaixo geram exatamente o artefato descrito, na mesma máquina e nas
mesmas condições.

## macOS — exportação completa opcional (2026-11-04, vigente)

Código App: `71d9f7c`. O diálogo **Exportar / Sanitizar…** mantém a cópia
sanitizada por padrão. O checkbox **Incluir dados sensíveis** habilita a captura
completa (sessão, anexos e os artefatos presentes `cdp-events.jsonl`, `netlog.json`,
`cdp-bodies.jsonl`), sem redações, com aviso destacado e destino sugerido `-full`.
O destino continua sujeito às mesmas recusas: origem, pasta interna, symlinks ou
pasta ocupada. Arquivos brutos especiais/symlinks são recusados; cópia em fluxo
com `O_NOFOLLOW`, arquivos 0600 e diretório 0700. Nada da origem é alterado.

Bundle: `src-tauri/target/release/bundle/macos/ScrapeLens.app`.
SHA-256 de `Contents/MacOS/scrapelens` (18.268.880 bytes):
`bd8d10a6b753287ad85235c7a48a3b6a3659f612d7e9e2b08cc55feb40fd5d71`.
Assinado com `ScrapeLens Local Signing`; `codesign --verify --deep --strict`
aprovado e DR preservado (`d0a53befa59a447043abc9e58a3381addbbf1751`).
Nenhuma janela aberta ou ativada. Linux não recompilado nesta tarefa.

Validação: `cargo test --locked` 60 aprovados, 0 falhas, 8 ignorados;
clippy `--locked --all-targets -- -D warnings` limpo; `npm test` (sete suítes),
typecheck e build aprovados. Testes Rust preservam segredos das fixtures em
cookies/corpos/artefatos, verificam permissões e recusas de destino/symlinks.
`app/src/Export.test.tsx` exercita o checkbox, chamadas de prévia e salvamento
com `includeSensitive=true`, alternância do destino sugerido e preservação de
caminho editado. Teste de componente React, sem automação do diálogo nativo.
Logs: `/tmp/sl-full-{rust,clippy,front,bundle}.log`.

## macOS — seletor de cookies de navegador (vigente)

Origem: `3e09738`, sobre `2a52152`, árvore limpa antes do build.
O seletor **Cookies** ao lado de URL inicial lista os perfis detectados e
salva somente o identificador em preferências privadas. Uma fonte removida
volta para sessão limpa; fonte inválida passada ao comando é recusada. Com URL
vazia, a captura ignora a fonte e a UI avisa para informar a URL inicial.
O DTO não expõe o caminho do banco. Os cookies seguem para `CaptureConfig`
e são importados pela crate de captura antes de navegar; falhas são mostradas
pelo aviso de início da captura.

Bundle: `src-tauri/target/release/bundle/macos/ScrapeLens.app`.
Executável interno `Contents/MacOS/scrapelens`: **18.277.584 bytes**,
SHA-256 `9645c147f2f43b3286421d94e7e0a39376b2add404f0e22b0502fe0bff8a80c8`.
O hash identifica o executável, não o diretório `.app`.
Assinatura `ScrapeLens Local Signing`; `codesign --verify --deep --strict`
aprovado; DR preservado (`d0a53befa59a447043abc9e58a3381addbbf1751`).
Bundle pronto para o usuário abrir, sem abrir/ativar janelas nesta execução.
A instância existente não foi encerrada nem substituída em execução.

Validação: `cargo test --locked` **58 aprovados, 0 falhas, 8 ignorados**;
`cargo clippy --locked --all-targets -- -D warnings` limpo; seis suítes front
(`test:cookie-source`, `test:shortcuts`, `test:adapter`, `test:capture-url`,
`test:paged`, `test:list-view`), typecheck e build aprovados. Novos testes cobrem
preferências legadas/persistência, validação de IDs, ausência de caminho do banco
no DTO e markup do seletor (escolha salva, sessão limpa, bloqueio e dica de URL).
Não foi realizada importação real de cookies pessoais nem teste GUI do seletor.
Linux não foi recompilado nesta tarefa; os pacotes abaixo seguem em `22854c3`.
Logs: `/tmp/sl-cookie-rust.log`, `/tmp/sl-cookie-validation.log`,
`/tmp/sl-cookie-validation.json` e `/tmp/sl-cookie-bundle.log`.

## Release rodada 16 — 2026-11-03 (vigente)

Esta seção substitui os hashes e a origem das rodadas anteriores abaixo.
Origem: `22854c3` (árvore limpa antes dos builds), incluindo `f377617`
(validação FIFO/wrappers da Captura) e `ad4f5c1` (parser NetLog em fluxo P4), com fechamento de clippy/Core e semântica de `events` duplicado em `22854c3`.
Builds executados até o término neste turno, sem callback, sem abrir ou ativar
janelas macOS, sem tocar nas VMs e sem push.

| Artefato (relativo à raiz) | Bytes | SHA-256 |
|---|---:|---|
| `src-tauri/target/release/bundle/macos/ScrapeLens.app/Contents/MacOS/scrapelens` | 18089024 | `cbebd19d9c2339774fb6e959ae136439c896d69efd747f4bdf53d07f4c9ccf3f` |
| `src-tauri/linux/out/amd64/ScrapeLens_0.1.0_amd64.deb` | 6404930 | `871a04eb10e79ca291de16ca113a60dc766c733f84fad98a6ec8cdc6c479be15` |
| `src-tauri/linux/out/amd64/ScrapeLens_0.1.0_amd64.AppImage` | 84404728 | `d06c7d80d5bcb99d648944571cb704e72c71d11356b18eb1160c7721bb47039c` |
| `src-tauri/linux/out/amd64/scrapelens` | 21938000 | `6d9007aa510787e3376c3c3e3a400abff903ac3716c9bf04bbe803834ae815fd` |
| `src-tauri/linux/out/arm64/ScrapeLens_0.1.0_arm64.deb` | 6504416 | `11161abc54774b9ce94f7d140645c0120c24f76b4f27d12bdc2db33e1571a410` |
| `src-tauri/linux/out/arm64/ScrapeLens_0.1.0_aarch64.AppImage` | 82569736 | `5fb8f9138ef3dd65cb3af26a08f0a4801381de4b37729f8331df1502aa76aef6` |
| `src-tauri/linux/out/arm64/scrapelens` | 20702552 | `f9e0ecf0d2ffeafbee2ed69e5678d4eac1fa85841b09c18c246fed543b2116d5` |

macOS arm64: `cargo test --locked` **56 aprovados, 0 falhas, 8 ignorados**;
`cargo clippy --locked --all-targets -- -D warnings`, cinco testes front
(`test:shortcuts`, `test:list-view`, `test:paged`, `test:capture-url`,
`test:adapter`), typecheck e build Vite aprovados. Bundle assinado com
`ScrapeLens Local Signing`; `codesign --verify --deep --strict` aprovado.
DR preservado: `identifier "app.scrapelens.desktop" and certificate root =
H"d0a53befa59a447043abc9e58a3381addbbf1751"`.
O hash macOS identifica o executável dentro do `.app`, não o diretório.
Não foi executado smoke GUI macOS nesta rodada.

Linux amd64 (emulado) e arm64 (nativo) via Docker/Ubuntu 22.04:
`cargo test --locked` **56 aprovados, 0 falhas, 8 ignorados** em cada arquitetura;
clippy com `-D warnings`, os mesmos cinco testes front e typecheck aprovados;
`.deb` e AppImage gerados. Smoke Xvfb com `SCRAPELENS_TEST_MODE=1 --import-har`
gravou `session.json` com **1 requisição** em cada arquitetura e encerrou o
executável por SIGTERM. O smoke usa o executável avulso: não executa o AppImage
nem testa instalação dos pacotes ou atalhos via X11. Não houve nova validação
em Ubuntu 24.04/Debian 12. Sem assinatura Linux; conferir com
`sha256sum -c SHA256SUMS` no respectivo diretório de saída.
A receita fixa toolchains/lockfiles, mas não promete reprodução bit a bit.

Evidências: `/tmp/sl-r16-{macos,amd64,arm64}.log`,
`/tmp/sl-r16-result.json`, `/tmp/sl-r16-final-hashes.json` e
`src-tauri/linux/out/{amd64,arm64}/{build.log,smoke.log,SHA256SUMS}`.

O primeiro `docker run` amd64 falhou com snapshot pai ausente no daemon;
a repetição do mesmo comando concluiu com código 0. Log da tentativa bem-sucedida:
`/tmp/sl-r16-amd64-retry.log` (o JSON do script conserva `run=125` da primeira tentativa).

## Fontes do build

| Item | Valor |
|---|---|
| Repositório | `/Users/cesar/Projects/scrapelens` |
| Commit do app no momento do build | `f81ea80` (HEAD limpo; rodada 13 onda 1 + P5 paginado + adendo 9; `f81ea80` só acrescenta o log de `list_requests` no stderr sob `SCRAPELENS_TEST_MODE=1`, usado como evidência) + identidade local `ScrapeLens Local Signing` |
| Commits de exportação incluídos | `eaf5471` (shell Tauri), `0a6e696` (UI), `0446f18`/`12457cd` (formatação), `3a3c676` (ajuste da prévia) |
| Contrato da rodada | `4c97bc9` (`docs/07-exportacao-ui.md`); multi-alvo `docs/14-captura-multi-alvo.md` + UI `9a06463` |
| Core | path `scrapelens-core`; `3fe7efc` (A9-B1/A9-B2) com P1/P2/P3/P6/P7 (validação em fluxo, correlação por índice, `session.json` compacto, `sanitize_bundle_owned`) |
| Captura | crate `capture/`; gravação por descritor em `capture/src/fdio.rs`; CDP por pipe; `SCRAPELENS_CDP_TRANSPORT=port` volta ao modo antigo (`737290a`) |
| Data do build | 2026-11-02 (UTC−03) |
| Working tree | HEAD `f81ea80` limpo; `src-tauri/Cargo.lock` sem alteração; `SCRAPELENS_TEST_MODE=1 --open-capture tests/capture/runs/20261027T0730Z/session-har` preencheu a lista pelo contrato paginado (`list_requests offset=0 items=15 matched=15 total=15`); `--open-capture /private/tmp/big20k` paginou 20.002 requisições em 11 páginas de 2.000 |

Não há sidecar, processo auxiliar nem runtime Node/Python no produto.

## Comandos executados

```sh
# na raiz do repositório
cd app && npm install                     # uma vez
cd ../app && npx tsc --noEmit             # typecheck do frontend — sem saída
cd ../app && npm run build                # bundle Vite — 590,75 kB (gzip 123,89 kB)
cd ../app && npm run test:paged           # contrato paginado (lista + detalhe)
cd ../core && cargo test                  # ok (358 passam, 0 falham, 1 ignorado)
cd ../src-tauri && cargo test             # 55 passam, 8 ignorados; 0 falhas
cd ../src-tauri && cargo clippy --all-targets
cd .. && ./app/node_modules/.bin/tauri build --bundles app
# tauri.conf.json → bundle.macOS.signingIdentity = "ScrapeLens Local Signing"
# (o Tauri assina sozinho; re-sign manual equivalente:)
cd src-tauri/target/release/bundle/macos
codesign --force --deep --options runtime --sign "ScrapeLens Local Signing" ScrapeLens.app
codesign --verify --deep --strict ScrapeLens.app
codesign -dr - ScrapeLens.app   # DR estável: certificate root, não cdhash
```

Ferramentas usadas: rustc 1.99.0, Node 26.8.1, macOS 26.5.2 (arm64).

## Identidade local de Code Signing

**Não é Developer ID.** Não serve para distribuição, Gatekeeper nem notarização.
É só um certificado autoassinado no login keychain do desenvolvedor, para o
designated requirement do bundle citar o certificado (estável entre builds)
em vez do cdhash ad-hoc (que muda a cada re-sign e quebra o TCC / App Management).

| Item | Valor |
|---|---|
| Nome / CN | `ScrapeLens Local Signing` |
| Keychain | login (`~/Library/Keychains/login.keychain-db`) |
| Designated requirement | `identifier "app.scrapelens.desktop" and certificate root = H"d0a53befa59a447043abc9e58a3381addbbf1751"` |
| Estabilidade | igual em dois `tauri build` seguidos (conferido) |

### Como recriar (máquina nova / keychain limpa)

Arquivos temporários só em `/tmp`; apagar a chave e o `.p12` depois do import.
Nunca versionar a chave privada.

```sh
TMP=$(mktemp -d /tmp/scrapelens-codesign.XXXXXX)
cat > "$TMP/codesign.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_codesign
prompt = no
[req_distinguished_name]
CN = ScrapeLens Local Signing
O = ScrapeLens Local
C = BR
[v3_codesign]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
EOF
openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 \
  -keyout "$TMP/scrapelens.key" -out "$TMP/scrapelens.crt" -config "$TMP/codesign.cnf"
P12PASS=$(openssl rand -base64 24)
openssl pkcs12 -export -inkey "$TMP/scrapelens.key" -in "$TMP/scrapelens.crt" \
  -out "$TMP/scrapelens.p12" -name "ScrapeLens Local Signing" -passout "pass:${P12PASS}"
security import "$TMP/scrapelens.p12" -k ~/Library/Keychains/login.keychain-db \
  -f pkcs12 -P "$P12PASS" -T /usr/bin/codesign -T /usr/bin/security
unset P12PASS
security add-trusted-cert -r trustRoot -p codeSign \
  -k ~/Library/Keychains/login.keychain-db "$TMP/scrapelens.crt"
# Opcional (pede a senha do login keychain se a sessão não estiver desbloqueada):
# security set-key-partition-list -S apple-tool:,apple:,codesign: -s \
#   -D "ScrapeLens Local Signing" -t private ~/Library/Keychains/login.keychain-db
rm -f "$TMP/scrapelens.key" "$TMP/scrapelens.p12" "$TMP/scrapelens.crt" "$TMP/codesign.cnf"
rmdir "$TMP"
security find-identity -v -p codesigning   # deve listar "ScrapeLens Local Signing"
```

Se `security import` ou `set-key-partition-list` pedirem a senha do Keychain, rode o
comando no Terminal (não grave a senha em arquivo nem no chat).

## Artefato

| Item | Valor |
|---|---|
| Bundle | `src-tauri/target/release/bundle/macos/ScrapeLens.app` |
| Executável | `ScrapeLens.app/Contents/MacOS/scrapelens` |
| Arquitetura | `Mach-O 64-bit executable arm64`, thin (sem universal binary) |
| Tamanho do bundle | 18.332 KiB (`du -sk`) |
| Tamanho do executável | 18.015.088 bytes |
| SHA-256 do executável | `fcdc4bd26a71a4e31e5366d7e2b881e0c5cd63911589186d70db17068ad4acde` |
| Identificador | `app.scrapelens.desktop` |
| Assinatura | `ScrapeLens Local Signing` (`flags=0x10000(runtime)`, `TeamIdentifier=not set`) — **não** Developer ID |
| Designated requirement | `identifier "app.scrapelens.desktop" and certificate root = H"d0a53befa59a447043abc9e58a3381addbbf1751"` |
| `codesign --verify --deep --strict` | exit 0 (valid on disk, satisfaz o Designated Requirement) |
| `spctl -a` | rejeitado — esperado: sem Developer ID e sem notarização |

Rodada 13 D7 rebuild limpo HEAD `885b592` (2026-11-03; Captura `e8ae66c`/`885b592` suprime o aviso de automação em toda captura; aberto e fechado uma vez com `open -g`, sem ativar a janela; SHA `fcdc4bd2…` substitui `78155379…`). Antes: rodada 13 onda 2 rebuild limpo HEAD `291fae4` (2026-11-02; rede aberta na captura com `SCRAPELENS_CAPTURE_NETWORK=loopback` só para testes (Captura `3dda266`), lista paginada sob demanda (`6f11440`), demo sem chips vazios e selo de gravação só na sessão gravada (`f00a2e4`), sem janela decorativa interna (`312c891`), clippy `-D warnings` limpo; SHA `78155379…` substitui `52cd14fd…`). Antes: rodada 13 onda 1 rebuild limpo HEAD `f81ea80` (2026-11-02; contrato paginado P5, abertura/importação/encerramento fora da thread principal, estado `starting`, sessão por nome com qualquer nome; SHA `52cd14fd…` substitui `2691f152…`). Antes: rodada 12 adendo 8 rebuild limpo HEAD `ce68eb9` (2026-11-02; CLI de teste exige `SCRAPELENS_TEST_MODE=1`; SHA `2691f152…` substitui `405b77fa…`). Antes: rodada 12 onda 1 rebuild limpo HEAD `737290a` (2026-11-02; modo de teste por CLI conferido no bundle; SHA `405b77fa…` substitui `f3039e58…`). Antes: rodada 12 rebuild limpo HEAD `fc5ca18` (2026-11-01; Core `73e457d`/`fc5ca18` completeness + sessionSetup; SHA `f3039e58…` substitui `65a6529c…`). Antes: rodada 11 rebuild limpo HEAD `1f7d7d5` (2026-11-01; core sem rustix; SHA `65a6529c…` substitui `d30af7f4…` inválido). Antes: rodada 11 rebuild limpo (HEAD `517b949`, `core/` = `868127b`, 2026-11-01; SHA `d30af7f4…` substitui `39f1233d…` gerado com árvore suja). Antes: rodada 11 rebuild captura+core `0b94424`/`39826a3`/`93361b8`/`e6fc955`/`868127b` (HEAD de origem `868127b`, 2026-11-01; rustix no core; SHA `39f1233d…`; hash anterior `114614c2…`). Antes: rodada 11 rebuild captura+core `daa3414`/`e6a9edd`/`952921a`/`d50a19f` (HEAD de origem `d50a19f`, 2026-10-31; SHA `114614c2…`; hash anterior `57264aed…`). Antes: rodada 11 rebuild captura `23bcba6`/`0997a3b` (HEAD de origem `d8ad643`, 2026-10-31; SHA `57264aed…`; hash anterior `8558470b…`). Antes: rodada 11 rebuild captura `62afa63` (HEAD de origem `61ad875`, 2026-10-31; SHA `8558470b…`; hash anterior `4636a3cf…`). Antes: rodada 11 rebuild captura (HEAD de origem `03ee85c`, 2026-10-31; codesign Chrome `--deep`, NetLog no perfil, CLOEXEC, prazo navigate; SHA `4636a3cf…`; hash anterior `6c0092c3…`). Antes: rodada 11 (HEAD de origem `eb66afa`, 2026-10-31; captura em `capture/`; CDP por pipe por padrão, `SCRAPELENS_CDP_TRANSPORT=port` para o modo antigo; SHA `6c0092c3…`; hash anterior `1901f3b4…`). Antes: rodada 10 assinatura estável (HEAD de origem 0ddd387, 2026-10-31; cert local `ScrapeLens Local Signing`; DR por certificate root, estável em 2 builds; hash anterior `b3e12edc…`). Antes: rodada 10 limpeza órfãos (HEAD de origem 8fd4f6d, 2026-10-31; setup Tauri chama `capture::cleanup_orphans` em thread; teste `startup_removes_orphan_capture_with_dead_owner`; hash anterior `7a46fa4c…`). Antes: rodada 10 definitiva (HEAD de origem 66e97e3, 2026-10-31; UI `target.notes` + `cdp.target_setup_error`/`timeout` em Limites; captura `/multi/` com “não confirmada” no sw-intercept e Limites sem aviso de setup; print 44; hash anterior `02e6ef30…`). Antes: rodada 10 final (HEAD de origem 8cfe828, 2026-10-30; Captura 1716d39–8cfe828 + Core df421cf/7892303; SW sem cópias na lista, sw-intercept ligado como ambígua, Limites sem “não anexou” falso; sessão antiga sem sessionId sem coluna Alvo; prints 42/44/47; hash anterior `77cf7355…`). Antes: rodada 10 (HEAD de origem 881fa0d, 2026-10-30; bundle com captura multi-alvo d60c1ae+, UI Alvo `9a06463`, aceite das Testes; captura ao vivo `/multi/` pelo `.app` com coluna Alvo e filtro de alvos; evidência `evidence/busca-corpos/46-multi-alvo-bundle.png`; hash anterior `d1136cbb…`). Antes: rodada 9, onda B, 3ª vez (HEAD de origem 7410fa4, 2026-10-29; bundle com `plan.parameters` isento só com plano verificado — versão atual, hash e alvo conferidos; correção só de core, traces e tela sem mudança; hash anterior `a4fe000a…`). Antes: rodada 9, onda B, 2ª vez (HEAD de origem 39410bf, 2026-10-29; bundle recompilado com a isenção de `parameters` restrita ao par (name, part) do plano — correção só de core, traces e tela sem mudança; hash anterior `860c2008…`). Antes: rodada 9, onda B (HEAD de origem 31bcaa9, 2026-10-29; plan.version 2 no trace, traces ok/403/incompleta regenerados contra o detran-sim e validação sem avisos espúrios na trace fiel; inclui o cleanup_on_start de 4a81cb0 e o plan.parameters de d83d620; hash anterior `bdce5796…`). Antes: rodada 9, 3ª vez (HEAD de origem a37cd60, 2026-10-29; temporária do trace com guardar/descartar, limite de 64 MiB, vereditos novos do validate com plan.hash do core; hash anterior `0b49ba0c…`). Antes: rodada 9, 2ª vez (HEAD de origem 2a5c533, 2026-10-29; validate com adaptador e classe "parâmetro do usuário"; hash anterior `48e1ab6d…`). Antes: rodada 9 (HEAD de origem 744df02, 2026-10-29; linha do tempo, "Validar execução…" com import-trace em pasta nova e validate; hash anterior `bda06a2d…`). Antes: build final que encerra a rodada 8 (HEAD de origem dc14ac3, 2026-10-29; estrito como padrão nas partes do adaptador; opção avançada "partes tolerantes" (`lenient_parts`) no script de priming, desligada por padrão; hash anterior `0eb5632a…`). Antes: build final da rodada 8, 2ª vez (HEAD de origem c07b514, 2026-10-29; inclui b4511fb e c07b514 da Captura; hash anterior `bee5f6d6…`). Antes: build final da rodada 8 (HEAD de origem 5d2c6e6, 2026-10-29; inclui 391db16, 5d2c6e6 da Captura, 3ba9486 do Core e o corte de partes da visão do adaptador; hash anterior `53009655…`). Antes: rebuild final da rodada 8 (HEAD de origem b0ce0f0, 2026-10-29; inclui limites da gramática da Captura, core c61d407 e o limite por campo da visão do adaptador; hash anterior `9aec2199…`). Antes: rebuild da rodada 8 (HEAD de origem aab8559, 2026-10-29; adaptador `natural-ajax` por dependência de path em origins/chain/compare/priming, visão estruturada e aba "Script de priming"; hash anterior `6e301e70…`). Antes: rebuild final (HEAD de origem 4b16b0e, 2026-10-29; inclui cf015b2 initiator do CDP e 6a85676 detectores do priming; hash anterior `1a097cd0…`). Antes: rebuild 7e (leitura de `assess-rules.json` só como arquivo regular sem symlink, até 256 KiB, erro de parse sem eco; hash anterior `56514c8b…`). Antes: rebuild 7d (avisos de `AssessRules::warnings()` devolvidos por `assess_session` e mostrados na lista e na aba Aplicação; hash anterior `0dba0476…`). Antes: rebuild 7c (filtros separados "Falhas da aplicação" = app-error e "Possíveis bloqueios?" = blocked?, combináveis; hash anterior `aa066f1a…`). Antes: rebuild 7b-2 (`counts` do assess com `VerdictKind::count_key()`, chaves kebab-case iguais ao `verdictKind`; hash anterior `83d67718…`). Antes: rebuild do ajuste 7b (verdict `not-assessed` neutro; hash anterior `0f6d04bf…`). Antes: rebuild da onda 7b (comando `assess_session`, coluna/filtro/aba "Aplicação", veredito na cadeia e no compare; hash anterior `4f7ca2aa…`). Antes: rebuild com frames auxiliares e iniciador (hash anterior `1697321d…`). Antes: rebuild da onda 6b (controle HTML, contexto estático, páginas de contexto, avisos de HAR sem cookies, compare por rodadas com opções, sanitização de negócio; hash anterior `f777988f…`). Antes: rebuild da dica de reordenação ligada a `SessionComparison.reordered` (hash anterior `21824159…`). Antes: rebuild do ajuste de layout do compare (chips quebram linha; dica de reordenação opcional); hash anterior `ac7213b2…`. Antes: rebuild com os rótulos do core (possível origem) e fixtures regeneradas; hash anterior `31ec27c3…`. Antes: rebuild das correções da revisão da rodada 5 (possível origem, confiança por passo, comparação paginada, caminhos canônicos, partsCounts; hash anterior `c1783a57…`). Antes: rebuild da onda 5b (aba Origem, cadeia de priming, comparação A × B, exportação com origens anotadas; hash anterior `2f08150d…`). Antes: rebuild do acabamento da rodada 4 (legenda de realce só quando há tracejado, nota discreta para `chrome-decoded`, aviso para `charset:*`/`lossy-postData`); hash anterior `0e2754f4…`. Antes: rebuild com busca preguiçosa do core (LazySession + search_lazy), realce sólido/tracejado e texto da fixture sintética; hash anterior `f9c0acec…`. Antes: rebuild das correções da revisão 4b (rótulos de origem, realce pelo intervalo do core, cache do bundle de busca, recusa de symlink em anexos, `transformed`; hash anterior `56ee754b…`). Antes: rebuild da onda 4b (busca no payload e painel de corpos: commands `search_session` e `read_body`, UI; 28+2 ignorados em src-tauri, 16/16 em tests/exportacao, `npm run test:adapter` ok; evidência em `evidence/busca-corpos/`). Hash anterior `9c04b98b…` substituído. Histórico: rebuild de 0d4dbab (`fix(app)`: adapter tolera campos omitidos que o core aceita via serde default; teste `npm run test:adapter` com a fixture mínima; 15+1 ignorado Tauri, 16/16 regressões tests/exportacao). Hash anterior `5934556c…` (16015a1) substituído. Antes: rebuild com validação de todos os ancestrais do destino (F1/F2): o hash acima é deste build. O SHA-256 é do executável **após** o re-sign ad-hoc. Um `tauri build` limpo
produz um binário byte-diferente (o linker assina antes do bundle), por isso o
hash identifica este artefato, não a saída de qualquer build. O build anterior
desta mesma rodada, sem o ajuste `3a3c676`, tinha
`ee127a56fa51a1403616dc4cb3796afd3bb5ec4d595c6da699c0cac1a16d9344`; ele foi
substituído por este.

## Validação de execução

- Bundle iniciado pelo drive de automação (`app.scrapelens.desktop`), janela
  única 1440×920, sem telemetria.
- `cargo test` no `src-tauri` cobre a ponte de exportação: prévia cURL/Python,
  escaping de aspas, corpo `captured` vs `unavailable`, recusa de sobrescrita,
  recusa de link simbólico e origem intacta após sanitizar.
- `cargo test` no `core` cobre os exportadores e a sanitização usados aqui; não
  houve alteração no core nesta rodada.

### Contrato paginado no bundle (rodada 13)

- `SCRAPELENS_TEST_MODE=1 ScrapeLens.app/Contents/MacOS/scrapelens --open-capture
  tests/capture/runs/20261027T0730Z/session-har` → stderr com
  `list_requests offset=0 items=15 matched=15 total=15`; janela fechada por SIGTERM.
  O log só existe no modo de teste; a lista veio pelo contrato novo, não por
  `session.json` inteiro no front.
- `--open-capture /private/tmp/big20k` (session de 20.002 requisições) → 11 páginas
  de 2.000 + 2 finais, `matched=20002 total=20002`. RSS do processo
  `WebKit.WebContent` ao abrir: **181.488 KiB (~177 MiB)**; processo principal
  **1.334.736 KiB (~1,27 GiB)**.
- A janela precisa estar ativa: com o app em segundo plano o WebKit não executou
  as chamadas de `list_requests` até a ativação (throttling/App Nap do macOS).
  A medição e a confirmação da lista foram feitas com a janela ativa; sem ativação,
  o CLI abriu a sessão mas a lista ficou pendente. O front também refez a varredura
  completa três vezes (33 chamadas) ao montar a tela.
- Onda 2 (HEAD `291fae4`, bundle `78155379…`): a mesma abertura de `/private/tmp/big20k`
  com a janela ativada (por `System Events`, sem clique) fez **2** chamadas de
  `list_requests` até a primeira tela (`offset=0` e `offset=2000`, página visível + 1 de
  folga, `matched=20002`), contra 33 na onda 1. A janela continua precisando estar ativa.
- `/tmp/big20k` não é aceito como caminho: `/tmp` é symlink para `/private/tmp` e a
  CLI recusa symlink em qualquer componente (comportamento esperado, A8-B6).

## Linux (rodada 14)

Build em container, sem nada instalado no macOS: `src-tauri/linux/Dockerfile`
(Ubuntu 22.04 fixado por digest `sha256:076e7bf8…5e11`, Rust 1.98.1, Node 26.8.1
conferido pelo `SHASUMS256.txt` oficial, `cargo --locked` e `npm ci`) e
`src-tauri/linux/build.sh` (testes, `tauri build --bundles deb,appimage`, smoke com Xvfb).

```bash
# na raiz do repositório; ARCH=amd64 (emulado no OrbStack) ou arm64 (nativo)
docker build --platform linux/$ARCH -f src-tauri/linux/Dockerfile -t scrapelens-linux:$ARCH .
docker run --rm --platform linux/$ARCH -v "$PWD/src-tauri/linux/out:/out" scrapelens-linux:$ARCH
# saída: src-tauri/linux/out/$ARCH/{*.deb,*.AppImage,scrapelens,SHA256SUMS,build.log,smoke.log}
```

Os artefatos em `src-tauri/linux/out/` ficam fora do git (`.gitignore`).

| Artefato (HEAD de origem `98ab629`, árvore limpa, atalhos Linux corrigidos e porte de `capture/` incluído) | SHA-256 |
|---|---|
| `amd64/ScrapeLens_0.1.0_amd64.deb` | `5d288b32575bd8a12bb65f59178534cf4f34e447fd0ec3e5485ff35115df53ac` |
| `amd64/ScrapeLens_0.1.0_amd64.AppImage` | `64b08eb83747f4dec1205c7f99f83e5219d0e2c4df6119d474f4993e88c40ec5` |
| `amd64/scrapelens` (executável) | `cd606a5d08aae7de7ce98f05c9183cbd3d06a7c3edafed1bf944c6d1d7f9367b` |
| `arm64/ScrapeLens_0.1.0_arm64.deb` | `a43397f34591c707d6c4f34f2321bd7d67750572efedce4880a7879ef35fde09` |
| `arm64/ScrapeLens_0.1.0_aarch64.AppImage` | `7c291e0b0ba29508b3e157ccf5ef334ff3fb89f723d02f34de89fff0a40d66f1` |
| `arm64/scrapelens` (executável) | `fc667f779f0f017c4844f7994bf321500dc8cf21ded8a38f712f7d4dbf1debf3` |

Sem assinatura no Linux. Para verificar: `sha256sum -c SHA256SUMS` na pasta do
artefato, ou `sha256sum ScrapeLens_0.1.0_amd64.deb` comparado com a tabela acima.
O build **não é bit a bit reprodutível**: dois builds arm64 seguidos deram hashes
diferentes (o hash identifica o artefato, não a receita). Toolchain e dependências
são fixas; o que varia é o conteúdo gerado (ids de build, timestamps internos).

Resultado nos containers (amd64 e arm64 iguais): `cargo test` 56/0/8, clippy
`-D warnings` limpo, `test:shortcuts`, `test:list-view`, `test:paged`, `test:capture-url`,
`test:adapter` e `tsc` ok; smoke com `SCRAPELENS_TEST_MODE=1 --import-har
fixtures/aceite/headers-cookies/headers-cookies.har` sob `xvfb-run` gravou
`~/.local/share/app.scrapelens.desktop/sessions/har-…/session.json` (1 requisição)
e o app foi fechado por SIGTERM. Os dois smokes emitiram aviso AT-SPI de bus de acessibilidade ausente, sem impedir a importação nem a listagem. Evidência deste rebuild: `/tmp/sl-shortcuts-{amd64,arm64}.log`, `/tmp/sl-shortcuts-result.json` e `src-tauri/linux/out/{amd64,arm64}/{build.log,smoke.log,SHA256SUMS}`. Não houve teste dos atalhos via X11 nem reinstalação destes pacotes nas VMs nesta execução; a validação dos atalhos aqui é automatizada no front. No build anterior (árvore suja), o `.deb` amd64 instalou com `apt install ./…deb` em
`ubuntu:24.04` e `debian:12`, sem biblioteca faltando no `ldd`. O AppImage não foi
executado (precisaria de FUSE ou `--appimage-extract-and-run`); 24.04/Debian 12
foram só instalação, sem abrir a janela.

Diferenças de plataforma: atalhos aparecem como `Ctrl+`/`Shift+` (o menu já usa
`CmdOrCtrl`); preferências em `$XDG_CONFIG_HOME/app.scrapelens.desktop` (0700/0600,
mesma escrita atômica); "Mostrar no gerenciador de arquivos" abre a pasta com
`xdg-open` (não seleciona o arquivo). O porte Linux de `capture/` está incluído. Os atalhos de captura, importação, demo e cópia de URL também são tratados no `keydown` fora do macOS (`98ab629`), com as guardas de estado dos botões.

## Evidência da exportação/sanitização

Pasta: `src-tauri/evidence/exportacao/`.

| Arquivo | Conteúdo |
|---|---|
| `command-output.txt` | saída real (gerada por exemplo `export_dump`, já removido do repositório): prévias cURL/Python, prévia da sanitização e resultado gravado |
| `preview-curl.json`, `preview-python.json` | respostas literais de `export::preview` (1317 e 1745 bytes de texto) |
| `sanitize-preview.json`, `sanitize-saved.json` | 24 requisições, 152 redações (`cookie`, `header:cookie`, `header:set-cookie`, `setCookie`), destino sugerido e resultado |
| `05`–`14-*.png` | telas do app: demo, sessão aberta, detalhe, diálogo cURL, diálogo Python, cancelamento, arquivo salvo, sanitização, resultado e sessão sanitizada aberta |
| `ui-harness.mjs` | harness Playwright que exercita os componentes React |
| `ui-harness-result.json` | resumo: cópia e arquivo salvos idênticos à prévia Python (`copied_matches_python`, `saved_matches_python`) |
| `saved-har-0002.sh` | texto exato que o diálogo de salvamento entregou ao command |
| `prepare-payloads.py` | recria os payloads grandes usados pelo harness |

Sessão usada: `~/Library/Application Support/app.scrapelens.desktop/sessions/har-3dbc391c02a985c5-2`
(24 requisições, importada de HAR sintético de `127.0.0.1:8781`). A pasta
sanitizada de referência (0700/0600, `session.json` com 872.082 bytes) foi
gerada em `evidence/exportacao/sanitized-har-synthetic/` e conferida por busca
de marcadores: `fromjs`, `sc_a=alpha` e `sc_b=beta` não aparecem em nenhum
arquivo sanitizado. Ela é derivada e por isso não entra no git; o exemplo `export_dump` que a gerava foi removido — recrie-a pelo comando de sanitização do app.

**O que o harness prova e o que não prova.** O harness serve o `dist/` real do
frontend, injeta um stub de `__TAURI_INTERNALS__` e usa as respostas **reais**
gravadas pelo Rust; apenas os diálogos nativos, o clipboard e o file picker são
simulados. Ele prova o comportamento dos componentes React (alternância
cURL/Python, texto copiado/salvo igual à prévia, cancelamento sem gravação,
abertura da sessão sanitizada). Ele **não** prova o diálogo nativo do macOS nem
a gravação real do arquivo pelo usuário; esses caminhos são cobertos pelos
testes Rust (`write_text_file`, `sanitize_to`) e pelo bundle, mas a passagem
manual pelo `NSSavePanel` não foi automatizada nesta rodada.

## Prints

| Arquivo | Conteúdo |
|---|---|
| `src-tauri/evidence/exportacao/08-dialog-curl.png` | prévia cURL com estado do corpo, avisos e aviso de não execução |
| `src-tauri/evidence/exportacao/09-dialog-python.png` | mesma requisição em Python (`http.client`) |
| `src-tauri/evidence/exportacao/10-dialog-cancel.png` | cancelamento do diálogo nativo: nada gravado |
| `src-tauri/evidence/exportacao/11-dialog-saved.png` | arquivo salvo com caminho e bytes |
| `src-tauri/evidence/exportacao/12-dialog-sanitize.png` | prévia de sanitização com redações por origem |
| `src-tauri/evidence/exportacao/14-sanitized-session.png` | sessão sanitizada aberta no app |

## Limitações que este pacote mantém

- Sem assinatura Apple Developer ID e sem notarização; distribuição fora desta
  máquina exige `xattr -d com.apple.quarantine` ou assinatura/notarização reais.
- Apenas arm64 compilado e testado; Intel não validado.
- Captura multi-alvo: página, popup, `_blank`, OOPIF, worker e service worker;
  documento `_blank` pode vir só do NetLog.
- Corpos vindos do CDP ficam `unavailable` (não são baixados); a UI mostra o
  motivo em vez de inventar conteúdo. Nenhuma sessão capturada nesta máquina
  tem corpo; só o teste unitário cobre o caso `captured`.
- `--remote-allow-origins=*` no endpoint CDP (ver `src-tauri/src/capture.rs`);
  risco limitado a loopback, porta efêmera e à janela da captura.
- O fluxo manual de salvar pelo `NSSavePanel` dentro do bundle não foi
  automatizado: o painel nativo do macOS não expõe AX para o driver
  (`off_space_or_ax_unresolved`) e a tentativa em foreground atingiu outro app.
  Roteiro para validar em 2 minutos: abrir `ScrapeLens.app`, `Abrir captura…` →
  `har-3dbc391c02a985c5-2`, abrir a requisição `/setcookie`, `Exportar…`,
  `Salvar…`, escolher pasta nova e conferir o arquivo 0600; depois `Sanitizar…`
  e `Abrir sessão sanitizada`.
