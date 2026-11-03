# Rodada 14 — validação Linux (ScrapeLens)

Artefatos: `src-tauri/linux/out/` (commit 25248f3, origem fa89c25). SHA-256 conferidos antes de copiar:
- amd64: `ScrapeLens_0.1.0_amd64.deb` 5843dd5a…8225801; `ScrapeLens_0.1.0_amd64.AppImage` 30f549a5…27b628
- arm64: `ScrapeLens_0.1.0_arm64.deb` d4a15edc…35dc0; `ScrapeLens_0.1.0_aarch64.AppImage` 3fbac33f…5da80

## Placar final (roteiro `tests/linux/acceptance.sh`, versão final)

| Máquina | Execução | Navegador | Falhas | Captura | HAR | NetLog | `navigator.webdriver` | LISTEN do Chrome da captura |
|---|---|---|---|---|---|---|---|---|
| `sl-ubuntu-amd64` (x86_64) | **ROSETTA** (host arm64) | Google Chrome 156.0.8078.79 (repositório oficial) | **0** | complete, 11 req | complete, 24 | partial, 32 | `false` | nenhum (`ss -ltnp` sem o pid do Chrome) |
| `sl-ubuntu-arm64` (aarch64) | **NATIVA** | Chromium 156.0.8078.47 (snap) | **0** | complete, 11 req | complete, 24 | partial, 32 | `false` | nenhum (`ss -ltnp` sem o pid do Chrome) |

Pasta de cada execução: `amd64/` e `arm64/` (summary.txt, contagens.txt, ss-durante-captura.txt,
print-captura.png, print-final.png, probe.jsonl, logs). `ts/` e `xdg/` (dados de sessão) ficaram só na máquina.

Passos do roteiro (placar `OK` em ambas): instalar o .deb; pacote `scrape-lens` instalado; testserver
responde `/page`; janela do ScrapeLens; Iniciar e Encerrar por clique; nenhum LISTEN do Chrome da captura;
print durante a captura; sessão no disco com requisições; imports `--import-har` e `--import-netlog`;
HAR complete 24; NetLog partial 32; `navigator.webdriver === false`.

## Como foi medido
- **Rosetta vs nativo:** amd64 roda sobre Rosetta (uname x86_64 num host arm64); arm64 roda nativo (aarch64).
  Os resultados são de máquinas diferentes e não se misturam.
- **Início e fim da captura:** cliques no botão do app na tela virtual (xdotool, 1600x1000). Os atalhos
  de teclado do menu (Ctrl+Shift+R / Ctrl+.) não chegam ao app no Linux e não foram usados.
- **`ss -ltnp` durante a captura:** a única porta de escuta é a do testserver (127.0.0.1:8781), do próprio
  roteiro; no arm64 também aparece `:631` (cups do sistema). Nenhum socket de escuta pertence ao Chrome da captura.
- **`navigator.webdriver`:** lido por `tests/linux/probe_server.py`, uma página em 127.0.0.1:8791 que envia o
  valor para o próprio servidor. A captura usa CDP por pipe, então não há porta de depuração a consultar.
- **Prints:** a tela virtual inteira (1600x1000), porque o X reporta a janela cliente como 10x10 (a moldura
  do openbox não tem geometria própria). A tela contém só o openbox e as janelas do app (captura do Chrome de
  teste e a janela do ScrapeLens).

## Histórico (execuções que não fecharam e o que mudou)
1. Atalhos de teclado (Ctrl+Shift+R) não iniciaram a captura: troca para cliques no botão.
2. Imports pela CLI: a sessão só aparece após ~16 s; a espera fixa de 12 s era curta. Troca para esperar a sessão nova (até 60 s).
3. Início da captura falhou numa execução (amd64, 03:04): o app ainda não tinha a janela pronta. Troca para
   20 s de espera após abrir, e até 3 tentativas com reativação da janela.
4. `import -window <id>` travou com id obsoleto (processo preso segurando o X); removido, print agora é da tela inteira.
5. Prints iniciais saíram 10x10 porque a geometria da janela cliente não serve para recorte; corrigido.

## Observações de produto (para o App)
- Atalhos do menu Captura (Ctrl+Shift+R, Ctrl+.) não disparam no Linux quando enviados via X; os botões funcionam.
- Chromium por snap no arm64 funciona para a captura (aceito; não foi preciso PPA ou apt).
- Pacote `scrape-lens` (nome do .deb `ScrapeLens_0.1.0_*.deb`) depende de `libwebkit2gtk-4.1-0`; `dpkg -i` sozinho
  deixa o pacote quebrado até `apt-get install <deb>` resolver as dependências.

## Máquinas
- `sl-ubuntu-amd64` e `sl-ubuntu-arm64`: running, **não apagadas** (até o fim da rodada).
- Preparo extra além do `setup-vm.sh`: `libfuse2t64` (AppImage), `build-essential git cmake clang libclang-dev
  golang-go ninja-build pkg-config` e rustup (para compilar o testserver dentro da máquina).
- Dentro das máquinas ficam Xvfb e openbox (desktop virtual), por escolha do roteiro.
