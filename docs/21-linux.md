# 21. Versão Linux do ScrapeLens (captura e reconhecimento)

Rodada 14, a pedido do usuário. Escopo desta etapa: portar `capture/` (e `recon/`, que
não precisou de mudança) para Linux **sem regredir o macOS**. O porte de `capture/` não
dependeu do App: o `src-tauri/` não foi tocado nesta etapa, mas no **aceite da rodada 14**
ele foi empacotado (`.deb` e `AppImage`, amd64 e arm64) e passou na bateria real das VMs do
OrbStack (§7.1). O servidor MCP (`mcp/`) compila e passa os testes no Linux sem mudança.

## 1. Alvo e o que foi testado

Alvo principal: Linux x86_64 (Ubuntu 22.04, Ubuntu 24.04, Debian 12), com navegador
**Google Chrome estável**. Secundário: arm64, onde o Google **não publica** build Linux do
Chrome estável: o navegador aceito é o **Chromium**, e isso fica registrado na sessão.

Ambiente de teste: Docker via OrbStack nesta máquina (engine `linux/arm64`; `linux/amd64`
roda por emulação), imagens em `experiments/linux/`. Tudo dentro do container, em loopback,
sem site real; nada foi instalado no macOS do usuário.

### Placar por plataforma

Todas as linhas rodaram com o **mesmo código** (a árvore de trabalho no commit desta rodada).
Cada coluna é um comando; `—` = não se aplica.

| Plataforma | Navegador | clippy `-D warnings` (capture, recon) | `cargo test --lib` (capture) | vivos em loopback (`--ignored`) | recon: `cargo test` + `live_e2e.sh` | `check_multi_target.py` | perfil sob `XDG_RUNTIME_DIR` | mcp |
|---|---|---|---|---|---|---|---|---|
| Ubuntu 24.04 amd64 | Google Chrome 156.0.8078.79 (`google-chrome-stable`) | ✓ | 96 passed | 17/17 | 27 + 3 passed | OK (16/16 NetLog, ≥15/16 CDP) | ✓ | ✓ |
| Ubuntu 22.04 amd64 | Google Chrome 156.0.8078.79 | ✓ | 96 passed | 17/17 | 27 + 3 passed | OK | ✓ | ✓ |
| Debian 12 amd64 | Google Chrome 156.0.8078.79 | ✓ | 96 passed | 17/17 | 27 + 3 passed | OK | ✓ | ✓ |
| Debian 12 **arm64** | **Chromium** 156.0.8078.73 (`chromium`) | ✓ | 96 passed | 17/17 | 27 + 3 passed | OK | ✓ | ✓ |
| macOS arm64 (esta máquina) | Google Chrome 156 | ✓ | 91 passed (os 5 a menos são os testes só-Linux) | 17/17 | 27 + 3 passed | OK | — | ✓ |

- Os **17 vivos** incluem `navigator.webdriver === false` na captura completa e na controlada,
  pipe e porta, os 8 caminhos da lacuna de porta, symlinks plantados, troca da pasta da sessão,
  mensagem acima do teto, segundo cliente CDP e a rede aberta resolvendo um nome local.
- Também com janela (**não headless**) sob **Xvfb** (`SL_LIVE_HEADED=1`): as duas capturas que
  escondem `navigator.webdriver` passam no Ubuntu 24.04 amd64 (Chrome) e no Debian 12 arm64
  (Chromium).
- O navegador real de cada imagem passa em `validate_chrome` e devolve produto, versão,
  binário e pacote dono: `GoogleChrome 156.0.8078.79 /opt/google/chrome/chrome
  pacote=Some("google-chrome-stable")` e `Chromium 156.0.8078.73 /usr/lib/chromium/chromium
  pacote=Some("chromium")`.


## 2. O que mudou no código

| Arquivo | Mudança | macOS |
|---|---|---|
| `capture/src/chrome.rs` | candidatos Linux; `validate_chrome_linux` (§3); `BrowserKind` (Chrome ou Chromium, marcado); `ValidatedChrome` ganhou `kind` e `package`; erro `Untrusted` | inalterado (o ramo do `codesign` ficou como era) |
| `capture/src/lib.rs` | diretório do descritor por `readlink /proc/self/fd/N`; `close_range(CLOEXEC)` com laço de reserva; base privada do perfil/state root (§4); processos por `/proc` e `kill(2)` em vez de `ps`/`kill`; nota de Chromium na sessão | inalterado (`F_GETPATH`, `ps`) |
| `capture/src/transport.rs` | `pipe2(O_CLOEXEC)` no Linux: fecha a janela entre `pipe()` e o `fcntl` | inalterado (`pipe` + `F_DUPFD_CLOEXEC`) |
| `capture/src/browser.rs` (testes) | `lsof`/`ps` por caminho que existe (`/usr/sbin` no macOS, `/usr/bin` no Linux) | só testes |
| `recon/` | nenhuma | — |

`cfg(target_os)` só onde o sistema difere. `O_NOFOLLOW`, `O_DIRECTORY`, `openat`,
`renameat`, `unlinkat`, `fstatat` e `fdopendir` do `fdio.rs` são POSIX e funcionaram sem
mudança (verificado pelos testes do `fdio` e pelos vivos no Linux). O pipe do CDP continua
nos fds 3 e 4 (`dup2` no `pre_exec`).

## 3. Validação do navegador no Linux (equivalente ao `codesign`)

No macOS o Chrome é validado por `codesign --verify --deep -R=<requisito da Google>`. O Linux
não tem assinatura de código no binário (o pacote `.deb` é assinado pela chave do repositório
no momento da instalação, mas isso não fica no arquivo). O equivalente definido e
implementado em `chrome::validate_chrome_linux`, **sem executar nada até o fim das
checagens**:

1. O caminho dado e o canônico não têm caractere de controle nem são não-UTF-8.
2. O caminho é resolvido ao **canônico** (os links `/usr/bin/google-chrome-stable` →
   `/etc/alternatives/google-chrome` → `/opt/google/chrome/google-chrome` caem no destino).
   Se o destino é um **script** (`#!`), só vale se o **nome** for de um wrapper conhecido do
   pacote: `google-chrome` ou `google-chrome-stable` (o `chrome` ELF ao lado, em
   `/opt/google/chrome/`), `chromium` ou `chromium-browser` (os caminhos do Debian/Ubuntu,
   `/usr/lib/chromium/chromium` e `/usr/lib/chromium-browser/chromium-browser`). Um script de
   nome arbitrário é recusado, nunca trocado por um binário de outro lugar. O que roda é
   sempre um **ELF**.
3. O nome do executável é de navegador (`chrome`, `chromium`, `chromium-browser`).
4. O binário é **arquivo regular, de root (uid 0), executável, sem escrita para grupo nem
   outros**; **cada diretório acima, até `/`, é de root e sem escrita para grupo/outros**.
   Quando o usuário atual não é root, `access(W_OK)` precisa **falhar** para o binário e para
   cada diretório (cobre ACL e permissões que o modo não mostra).
   O tipo do arquivo é conferido no **descritor aberto** com
   `O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC` + `fstat`: FIFO, socket e device são
   recusados na hora, sem bloquear (um FIFO sem escritor travaria um `open` comum antes de
   qualquer timeout).
5. **Só depois** roda `<binário> --version` (ambiente limpo, `PATH=/usr/bin:/bin`, 10 s). A
   saída tem de ser `Google Chrome <n.n.n.n>` (o estável: Beta, Dev e "for Testing" têm mais
   palavras e são recusados) ou `Chromium <n.n.n.n> …`. O produto e a versão vêm daí.
6. O **pacote dono** (`dpkg -S`, depois `rpm -qf`) é consultado e registrado em
   `ValidatedChrome.package`; a validação **não depende** dele (o sistema pode não ter
   `dpkg` nem `rpm`).

Candidatos, em ordem: `/opt/google/chrome/chrome`, `/usr/bin/google-chrome-stable`,
`/usr/bin/google-chrome`, `/opt/google/chrome/google-chrome`, depois o Chromium
(`/usr/lib/chromium/chromium`, `/usr/lib/chromium-browser/chromium-browser`,
`/usr/bin/chromium`, `/usr/bin/chromium-browser`). O Chrome estável vem antes; o Chromium é
alternativa e vem **marcado** (`BrowserKind::Chromium`). Quando o navegador é Chromium, a sessão
registra em `capture.notes`: "navegador: Chromium (alternativa ao Google Chrome estável, que
não existe para este sistema/arquitetura)".

**Fica de fora, e é dito:** o Chromium instalado por **snap** — no aceite da rodada 14 o
Chromium do snap (arm64, 156.0.8078.47) passou a bateria real do App, com 0 falhas
(`tests/results/linux/README.md`). O binário ELF dentro do snap é de root e cumpre as regras
acima; o **lançador** `/snap/bin/chromium` (o que o `apt install chromium-browser` do Ubuntu
cria) não é candidato nem aceito, porque é um lançador do snapd, não o binário do pacote. Uma
instalação em pasta do usuário (`~/chrome`, binário baixado à mão) é recusada de propósito: o
diretório é do usuário.

**Janela que resta:** entre a checagem e o `exec` há uma janela (TOCTOU), como no macOS. Aqui
o binário e todos os diretórios são de root e inacessíveis para escrita pelo usuário, então só
root a explora, e root já pode tudo.

Testes (Linux): `parses_the_version_line_of_each_product_and_refuses_the_others`,
`candidates_list_chrome_before_chromium_and_the_real_binary_before_the_script`,
`a_regular_trusted_elf_passes_every_check_and_only_then_runs_version`,
`a_binary_writable_by_group_or_others_is_refused_before_anything_runs`,
`a_writable_directory_above_the_binary_is_refused`,
`a_file_owned_by_someone_else_is_refused`,
`scripts_and_non_browser_names_are_refused_without_running` (inclui um script de nome
arbitrário ao lado de um `chrome` ELF, que **não** é trocado),
`a_fifo_is_refused_immediately_without_blocking` (um FIFO sem escritor é recusado em menos de
5 s, provando que o `open` não bloqueia),
`a_symlink_is_resolved_to_the_canonical_binary`, `control_characters_in_the_path_are_refused`
e `the_installed_browser_passes_when_present` (o navegador real do container, com versão,
tipo e pacote; no arm64 exige `Chromium`).

## 4. Diretórios privados: perfil, NetLog e state root

Tudo continua criado 0700 e conferido depois de aberto (`create_private_dir_new`,
`verify_private_dir`). O que muda é **onde**:

- **macOS:** `temp_dir()` (`$TMPDIR` é por usuário).
- **Linux:** `$TMPDIR`, se o usuário o definiu (não vazio); senão `$XDG_RUNTIME_DIR`, se for um
  diretório **real** (não link), absoluto, **do usuário atual e com modo 0700**; senão `/tmp`.
- O **state root** (marcadores de órfãos, resgates) vive nessa base. Sob um `XDG_RUNTIME_DIR`
  válido chama-se `scrapelens-capture-state`; na base compartilhada `/tmp` o nome leva o uid
  (`scrapelens-capture-state-<uid>`), para dois usuários não disputarem a mesma pasta.
- `ensure_private_state_root` cria/aperta a raiz e confere que é diretório **do usuário, 0700 e
  não link**, **antes** de qualquer `chmod` (um link no lugar é recusado sem tocar o alvo).
- `is_app_profile` (limpeza de órfãos) passa a comparar com essa base, não com o `temp_dir()`.

Testes: `linux_base_dir_prefers_tmpdir_then_a_valid_xdg_runtime_dir_then_tmp`,
`the_state_root_is_created_0700_and_a_symlink_in_its_place_is_refused_untouched`; e a etapa
`xdg` do container (um `XDG_RUNTIME_DIR` 0700, sem `TMPDIR`) mostra o perfil
`scrapelens-chrome-<pid>-<ns>` e `scrapelens-capture-state` (0700) criados **dentro dele**
durante a captura.

## 5. Descritores, processos e pipes

- **CLOEXEC no filho:** o Linux usa `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)` (kernel 5.11+),
  que marca **todos** os descritores `>= first` sem teto de varredura; se o syscall não existir
  (kernel antigo, seccomp), cai no mesmo laço do macOS (`min(getdtablesize(), 65536)`). Com o
  pipe, `first = 5` (o 3 e o 4 são do CDP).
- **Pipe:** `pipe2(O_CLOEXEC)` no Linux; no macOS (`pipe` + `F_DUPFD_CLOEXEC`) a janela mínima
  continua e está documentada no `docs/16b`.
- **Caminho do descritor** (mensagem quando a pasta da sessão é trocada): `readlink
  /proc/self/fd/N` no Linux (`F_GETPATH` no macOS).
- **Órfãos:** `/proc/<pid>/cmdline` e `kill(2)` no lugar de `ps`/`kill`, que um container
  mínimo pode não ter.

## 6. Containers de teste (`experiments/linux/`)

- `Dockerfile`: parametrizado por base (`ubuntu:22.04`, `ubuntu:24.04`, `debian:12`) e navegador
  (`chrome`: o `.deb` oficial de `dl.google.com`, amd64; `chromium`: o pacote `chromium` do
  Debian, para arm64), mais Xvfb, Rust (rustup), `cmake`/`clang` (o `testserver`, via quiche, só
  compila com eles) e um usuário comum (`tester`, uid 1001). O Chrome roda como esse usuário
  **com o sandbox ligado** (`--security-opt seccomp=unconfined`, para o Chrome criar namespaces de
  usuário); **nunca** `--no-sandbox` (D6).
- `run.sh <rótulo> <plataforma> <base> <chrome|chromium> [comando]`: constrói a imagem, monta um
  **snapshot somente leitura** do repositório e roda `inside.sh`.
- `inside.sh [etapas]`: `info`, `clippy`, `unit` (`cargo test --lib`), `live` (os testes vivos em
  loopback, `--ignored`, sob `xvfb-run`, uma thread), `recon` (`cargo test` e `live_e2e.sh`),
  `multi` (o `check_multi_target.py`), `xdg` e `mcp`.
- `shim/`: substituto de `src-tauri` **só no container**. O `check_multi_target.py` dirige
  `cargo test live_bodies_cycle` dentro de `src-tauri`; sem o Tauri no Linux, o container troca
  `src-tauri` por uma crate mínima cujo teste faz exatamente o mesmo (`scrapelens_capture::run`,
  headless, só loopback). O script de aceite, da Testes, não foi tocado.

## 7. O que rodou e o que não rodou

**Rodou** (todas as plataformas da tabela, salvo onde a célula diz `—`): `cargo clippy
--all-targets -D warnings` em `capture/` e `recon/`; `cargo test --lib` de `capture/`; os testes
vivos de `capture/` (`--ignored`, uma thread, `xvfb-run`); `cargo test` e `scripts/live_e2e.sh` de
`recon/`; `check_multi_target.py` (16/16 NetLog, ≥15/16 CDP, tipos de alvo, corpos, sem fusão,
service worker) com o `testserver` e o `scrapelens-core` compilados no próprio container; os testes
do `mcp/`; a captura com perfil e state root sob `XDG_RUNTIME_DIR`; as duas capturas de
`navigator.webdriver` com janela sob Xvfb (Ubuntu 24.04 amd64 e Debian 12 arm64).

**Não rodou, e por quê:**

- **`src-tauri/` (o App Tauri) no Linux, nesta bateria de contêiner:** não foi compilado nem
  testado aqui; exige webkit2gtk/GTK e o empacotamento Linux, que ficaram na etapa do App. O
  `check_multi_target.py` rodou com o `shim/` no lugar do `src-tauri/` (§6), e os 8 testes
  `--ignored` do `src-tauri` não rodaram no contêiner. No **aceite da rodada 14** o App foi
  empacotado e validado nas VMs do OrbStack (§7.1).
- **Distribuições RPM** (Fedora, RHEL): não testadas. O caminho `rpm -qf` está codificado, mas
  nunca foi executado; `dpkg -S` foi exercitado (Ubuntu e Debian).
- **Outros navegadores do sistema:** Chrome Beta/Dev/for Testing (recusados de propósito). O
  Chromium por snap passou no aceite do App (§7.1); o lançador `/snap/bin/chromium` segue fora
  dos candidatos.
- **Caminho de reserva de `close_range`** (kernel < 5.11 ou seccomp que bloqueie o syscall): o
  laço de `fcntl` é o mesmo código do macOS e passa lá, mas não foi forçado no Linux.
- **Montagem somente leitura / ACL** na validação do navegador (o `access(W_OK)` para usuário não
  root): coberto pelo código, não por um teste (os testes de modo e dono cobrem o resto).
- **Emulação x86:** os amd64 rodam por emulação (OrbStack), então os tempos dos vivos (≈ 280 s)
  não valem como desempenho; o arm64 nativo leva ≈ 200 s.
- **HTTP/3, outras CPUs, Wayland:** fora do que a captura testa em loopback.

### 7.1 Aceite do App nas VMs do OrbStack (rodada 14)

Execução do App real empacotado, registrada pela Testes/App em `tests/results/linux/README.md`
(artefatos `src-tauri/linux/out/` do commit `e6d5fc6`): duas VMs Ubuntu 24.04, amd64 sobre
Rosetta com Google Chrome 156.0.8078.79 do repositório oficial, e arm64 nativa com **Chromium
156.0.8078.47 do snap**. Instalado o `.deb` (`ScrapeLens_0.1.0_amd64.deb` e
`ScrapeLens_0.1.0_arm64.deb`; também `AppImage` das duas arquiteturas), **0 falhas** em cada
máquina: iniciar e encerrar por atalho, captura `complete` com 11 requisições, HAR `complete` 24,
NetLog `partial` 32, `navigator.webdriver === false`, nenhum socket LISTEN do Chrome da captura.

É a prova de que a validação de navegador deste módulo funciona com o Chrome do repositório e com
o Chromium do snap no App real; a bateria de contêiner da tabela do §1 continua sendo a prova de
`capture`/`recon` por plataforma.

**Regressão no macOS:** nenhuma. A lista da tabela é a mesma de antes (clippy, 91 unitários, 17 vivos,
recon, `src-tauri` 56 passed, mcp, `check_multi_target` OK); os ramos `cfg(target_os = "macos")`
(`codesign`, `plutil`, `F_GETPATH`, `ps`, `pipe` + `F_DUPFD_CLOEXEC`) não foram tocados.

**Como repetir:**

```
experiments/linux/run.sh u24-amd64 linux/amd64 ubuntu:24.04 chrome       # Chrome estável
experiments/linux/run.sh d12-arm64 linux/arm64 debian:12 chromium         # Chromium (arm64)
# etapas: info clippy unit live recon multi xdg headed mcp (padrão: info clippy unit live recon)
experiments/linux/run.sh u24-amd64 linux/amd64 ubuntu:24.04 chrome /src/experiments/linux/inside.sh multi xdg
```

