# Validação Linux (rodada 14)

Máquinas OrbStack (`orb`), Ubuntu 24.04 (noble). Tudo roda dentro das máquinas;
nada é instalado no macOS e nenhum clique é dado em janelas do usuário.

| Máquina | Arquitetura | Execução | Navegador de captura |
|---|---|---|---|
| `sl-ubuntu-amd64` | amd64 (`--arch amd64`) | **Rosetta** (host arm64 traduz x86_64) | Google Chrome estável (repositório oficial do Google) |
| `sl-ubuntu-arm64` | arm64 | **nativa** (aarch64) | Chromium (Google não publica Chrome para Linux arm64) |

Registre sempre qual resultado veio de Rosetta e qual veio de execução nativa:
a pasta de saída do roteiro traz `host:` e `tipo de execução:` na primeira linha.

## Preparo (já feito)
1. `orbctl create -a amd64 ubuntu:24.04 sl-ubuntu-amd64` e `orbctl create -a arm64 ubuntu:24.04 sl-ubuntu-arm64`.
2. `tests/linux/setup-vm.sh` dentro de cada máquina (Xvfb, openbox, xdotool, scrot/imagemagick,
   Chrome ou Chromium). Logs locais em `tests/.work/linux/` (ignorados pelo git).
   Rodar: `orb -m <máquina> bash -s < tests/linux/setup-vm.sh`.

## Artefatos
- `.deb` e AppImage em `src-tauri/linux/out/` (somente leitura; copiados para `~/artifacts-r14b/` na máquina,
  com SHA-256 conferido dos dois lados antes de rodar).
- Binário `scrapelens-testserver` compilado para Linux (dentro da máquina, a partir de `testserver/`),
  em `~/scrapelens/testserver/target/release/`.
- Fixtures de import em `~/fixtures-r14/`: `har-derived.json` e `h1h2h3.chrome-netlog.json`.

## Roteiro
`tests/linux/acceptance.sh <amd64|arm64> <AppImage> [.deb] [testserver] [probe_server.py]`
1. Instala o `.deb` da arquitetura da máquina (amd64 e arm64) e confirma o pacote instalado.
2. Sobe o testserver em 127.0.0.1:8781 (`/page`).
3. Abre o AppImage com `SCRAPELENS_TEST_MODE=1`, `SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page`,
   `SCRAPELENS_CAPTURE_NETWORK=loopback`.
4. Iniciar e Encerrar pelos **atalhos de teclado** do app, enviados com `xdotool key --clearmodifiers`
   (XTEST) na tela virtual `:99`, com a janela principal focada por `xdotool windowactivate --sync`:
   `ctrl+shift+r` (Iniciar sessão) e `ctrl+period` (Encerrar). O foco precisa ser reativado antes de cada
   atalho, porque ao iniciar a captura o foco vai para a janela do Chrome. Os botões (1044,178) e (1138,178)
   não são clicados em nenhum passo; se a tecla não chegar ao WebView, o roteiro tenta de novo com um único
   clique neutro em (700,900) — área vazia, longe de controles — só para dar foco, e registra em `atalhos.txt`.
   Durante a captura: `ss -ltnp` e confirmação de nenhum LISTEN do Chrome da captura.
5. Confere a sessão no disco (`~/.local/share/app.scrapelens.desktop/sessions`).
6. Imports com `--import-har` e `--import-netlog` pela CLI de teste.
7. Confere as contagens: HAR complete 24, NetLog partial 32.
8. `navigator.webdriver`: captura com `tests/linux/probe_server.py` (página-sonda em loopback);
   o valor gravado tem de ser `false`.
9. Prints da janela (`import -window`), salvos na pasta de saída.

Saída: `~/sl-acceptance-<arch>-<timestamp>/summary.txt` na máquina; `FALHAS=0` quando tudo passa.

## Limites conhecidos
- O roteiro envia teclas via `xdotool` na tela virtual da máquina (nada no macOS). Os atalhos só funcionam
  com foco no WebView; por isso cada atalho é precedido de `windowactivate --sync`. O clique neutro de foco
  em (700,900) é a última alternativa e fica registrado em `atalhos.txt`.
- A janela do app só aparece com área útil ≥ 100 px alguns segundos após o lançamento; a espera é pela
  janela real (não pelo helper `InputOnly` 10x10), com até 60 s.
- O X reporta a janela cliente do app como 10x10 (a moldura do openbox não tem geometria própria),
  então os prints são da tela virtual inteira (1600x1000), que contém só o openbox e as janelas do app.
- A captura usa CDP por pipe (sem porta TCP), então o `navigator.webdriver` é lido pela página-sonda
  e não por CDP no navegador.
- Este README não registra resultados: eles ficam em `tests/RELATORIO-FINAL.md` quando a bateria rodar.
