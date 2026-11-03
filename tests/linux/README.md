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

## Artefatos (pendentes, vêm do App)
- `.deb` e AppImage em `src-tauri/linux/` (somente leitura; copiados para a máquina).
- Binário `scrapelens-testserver` compilado para Linux (dentro da máquina, a partir de `testserver/`).
- Fixtures de import em `~/fixtures-r14/`: `har-derived.json` e `h1h2h3.chrome-netlog.json`
  (copiar de `tests/.work/r12-import/` ou de `~/Projects/scrapelens-import-tmp/`; nunca da Mesa).

## Roteiro
`tests/linux/acceptance.sh <amd64|arm64> <AppImage> [.deb] [testserver] [probe_server.py]`
1. Instala o `.deb` (só amd64) e confirma o binário no PATH.
2. Sobe o testserver em 127.0.0.1:8781 (`/page`).
3. Abre o AppImage com `SCRAPELENS_TEST_MODE=1`, `SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page`,
   `SCRAPELENS_CAPTURE_NETWORK=loopback`.
4. Iniciar e Encerrar por **clique** (xdotool na tela virtual 1600x1000): Iniciar sessão em (1044,178),
   Encerrar em (1138,178). Os atalhos de teclado (ctrl+shift+r / ctrl+period) não chegam ao app no Linux,
   por isso não são usados. Durante a captura: `ss -ltnp` e confirmação de nenhum LISTEN do Chrome da captura.
5. Confere a sessão no disco (`~/.local/share/app.scrapelens.desktop/sessions`).
6. Imports com `--import-har` e `--import-netlog` pela CLI de teste.
7. Confere as contagens: HAR complete 24, NetLog partial 32.
8. `navigator.webdriver`: captura com `tests/linux/probe_server.py` (página-sonda em loopback);
   o valor gravado tem de ser `false`.
9. Prints da janela (`import -window`), salvos na pasta de saída.

Saída: `~/sl-acceptance-<arch>-<timestamp>/summary.txt` na máquina; `FALHAS=0` quando tudo passa.

## Limites conhecidos
- O roteiro usa cliques via `xdotool` na tela virtual da máquina (nada no macOS).
- O X reporta a janela cliente do app como 10x10 (a moldura do openbox não tem geometria própria),
  então os prints são da tela virtual inteira (1600x1000), que contém só o openbox e as janelas do app.
- A captura usa CDP por pipe (sem porta TCP), então o `navigator.webdriver` é lido pela página-sonda
  e não por CDP no navegador.
- Este README não registra resultados: eles ficam em `tests/RELATORIO-FINAL.md` quando a bateria rodar.
