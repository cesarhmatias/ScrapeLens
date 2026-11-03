# Rodada 14 — validação Linux (ScrapeLens)

Artefatos: `src-tauri/linux/out/` (commit `e6d5fc6`, origem `98ab629`). SHA-256 conferidos no macOS e
dentro de cada máquina antes de rodar:
- amd64: `ScrapeLens_0.1.0_amd64.deb` `5d288b32…15df53ac`; `ScrapeLens_0.1.0_amd64.AppImage` `64b08eb8…3e88c40ec5`
- arm64: `ScrapeLens_0.1.0_arm64.deb` `a43397f3…9ef35fde09`; `ScrapeLens_0.1.0_aarch64.AppImage` `7c291e0b…a40d66f1`

## Placar final (roteiro `tests/linux/acceptance.sh`, revisão com atalhos de teclado)

| Máquina | Execução | Navegador | Falhas | Iniciar | Encerrar | Captura | HAR | NetLog | `navigator.webdriver` | LISTEN do Chrome |
|---|---|---|---|---|---|---|---|---|---|---|
| `sl-ubuntu-amd64` (x86_64) | **ROSETTA** (host arm64) | Google Chrome 156.0.8078.79 (repositório oficial) | **0** | `Ctrl+Shift+R`, teclado puro | `Ctrl+.`, teclado puro | complete, 11 req | complete, 24 | partial, 32 | `false` | nenhum (`ss -ltnp` sem o pid do Chrome) |
| `sl-ubuntu-arm64` (aarch64) | **NATIVA** | Chromium 156.0.8078.47 (snap) | **0** | `Ctrl+Shift+R`, teclado puro | `Ctrl+.`, teclado puro | complete, 11 req | complete, 24 | partial, 32 | `false` | nenhum (`ss -ltnp` sem o pid do Chrome) |

Pasta de cada execução: `amd64/` e `arm64/` (summary.txt, atalhos.txt, contagens.txt,
ss-durante-captura.txt, print-captura.png, print-final.png, probe.jsonl, logs).

## Atalhos de teclado (o que esta revisão prova)

- Iniciar e Encerrar dispararam com **teclado puro**: `xdotool windowactivate --sync` na janela principal
  e `xdotool key --clearmodifiers`, sem clique em botão e sem clique neutro de foco
  (`atalhos.txt`: `cliques em coordenadas de botão …: 0`, `cliques neutros de foco …: 0`).
- Nas duas máquinas e nas duas capturas do roteiro (a principal e a da sonda `navigator.webdriver`).
- O foco precisa ser reativado antes de cada atalho: ao iniciar a captura, o foco X vai para a janela do
  Chrome. Sem `windowactivate`, o `Ctrl+.` vai para o Chrome e não encerra nada — foi o que aconteceu na
  verificação manual que motivou esta revisão.
- Tela virtual `:99` (Xvfb 1600x1000 + openbox) dentro da VM; nenhuma tecla ou clique no macOS.

Passos do roteiro (todos `OK` em ambas): instalar o `.deb`; pacote `scrape-lens` instalado; testserver
responde `/page`; janela do ScrapeLens; Iniciar pelo atalho; nenhum LISTEN do Chrome da captura;
print durante a captura; Encerrar pelo atalho; sessão no disco com 11 requisições; imports
`--import-har` e `--import-netlog`; HAR complete 24; NetLog partial 32; `navigator.webdriver === false`;
nenhum clique nos botões; atalhos de iniciar e encerrar confirmados.

## Como foi medido
- **Rosetta vs nativo:** amd64 roda sobre Rosetta (uname x86_64 num host arm64); arm64 roda nativo (aarch64).
  Os resultados são de máquinas diferentes e não se misturam.
- **Início e fim da captura:** atalhos do WebView (`ctrl+shift+r`, `ctrl+period`) via XTEST. O script
  identifica a janela real do app (maior área) e não o helper `InputOnly` 10x10 que também se chama
  "ScrapeLens".
- **`ss -ltnp` durante a captura:** a única porta de escuta é a do testserver (127.0.0.1:8781), do próprio
  roteiro; no arm64 também aparece `:631` (cups do sistema). Nenhum socket de escuta pertence ao Chrome da captura.
- **`navigator.webdriver`:** lido por `tests/linux/probe_server.py`, uma página em 127.0.0.1:8791 que envia o
  valor para o próprio servidor. A captura usa CDP por pipe, então não há porta de depuração a consultar.
- **Prints:** a tela virtual inteira (1600x1000), porque o X reporta a janela cliente como 10x10 (a moldura
  do openbox não tem geometria própria). A tela contém só o openbox e as janelas do app (Chrome de teste e
  a janela do ScrapeLens).

## Histórico
1. Rodada 14 original (artefatos `25248f3`, origem `fa89c25`): atalhos `Ctrl+Shift+R` / `Ctrl+.` não
   iniciavam nem encerravam; o roteiro usava cliques nos botões e fechou 0 falhas nas duas máquinas.
2. App corrigiu o listener `keydown` para Linux (`98ab629`) e regenerou os pacotes (`e6d5fc6`).
3. Esta revisão: atalhos refeitos no roteiro e **ambos disparam**. Duas observações de execução:
   o print inicial pode sair preto se for tirado antes do WebView pintar (a espera agora é pela janela
   real, não pelo helper 10x10); e o `Ctrl+.` só funciona com o ScrapeLens em foco, porque o Chrome assume
   o foco ao abrir.
4. Execuções anteriores: imports levam ~16 s para gravar `session.json` (espera até 60 s); `import -window`
   travou com janela obsoleta (print passou a ser da tela inteira); no amd64 houve uma falha de início por
   janela ainda não pronta (espera de 20 s + 3 tentativas).

## Observações de produto (para o App)
- `Ctrl+Shift+R` e `Ctrl+.` funcionam no Linux pelo listener do WebView, mas **só com foco na janela do app**.
  Ao iniciar a captura o Chrome toma o foco; o usuário precisa clicar na janela do ScrapeLens (ou usar o
  botão Encerrar) antes de `Ctrl+.`. Se quiser `Ctrl+.` global, falta um atalho de nível GTK/janela.
- Atalhos de menu declarados como aceleradores GTK continuam não chegando ao WebView.
- Chromium por snap no arm64 funciona para a captura (aceito; não foi preciso PPA ou apt).
- Pacote `scrape-lens` depende de `libwebkit2gtk-4.1-0`; `dpkg -i` sozinho deixa o pacote quebrado até
  `apt-get install <deb>` resolver as dependências.

## Máquinas
- `sl-ubuntu-amd64` (192.168.139.105) e `sl-ubuntu-arm64` (192.168.139.230): running, **não apagadas**.
- Dentro das máquinas ficam Xvfb `:99` e openbox (desktop virtual), por escolha do roteiro; nenhum app,
  Chrome de captura, testserver ou sonda ficou rodando após a bateria.
- Artefatos novos copiados para `~/artifacts-r14b/` nas duas máquinas.
