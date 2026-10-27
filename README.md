# ScrapeLens

Inspetor local de sessões HTTP para desenvolvedores de scraping. Captura Chrome
via CDP + NetLog, importa HAR/NetLog e mostra headers, duplicatas, cookies,
redirects e proveniência na sequência preservada pela fonte. A sequência da
fonte não é automaticamente prova da ordem transmitida.

App macOS Tauri 2 + React/TypeScript + Rust, sem sidecar e sem telemetria.
O navegador acessa os sites em que você navega; capturas são armazenadas
localmente. Não há envio de capturas a um serviço do ScrapeLens.

## Pacote local e instalação

Bundle validado: `src-tauri/target/release/bundle/macos/ScrapeLens.app`
(aproximadamente 13,2 MiB, arm64). Abra pelo Finder ou, na raiz do repositório:

```sh
open src-tauri/target/release/bundle/macos/ScrapeLens.app
```

Pode copiar o `.app` para `/Applications`. O usuário final precisa de macOS e
Chrome/Chromium externo para capturar; não precisa de Node, Python ou Rust.
Somente macOS 26.5.2 em Apple Silicon foi testado. Intel não foi validado.

Assinatura local ad-hoc verificada, sem Developer ID e sem notarização.
Gatekeeper não aprova este pacote para distribuição. Nada foi publicado.
Veja [evidência do bundle](src-tauri/EMPACOTAMENTO.md) e
[relatório final](docs/06-entrega.md).

## Uso

1. **Iniciar sessão** abre Chrome com perfil temporário dedicado, inicialmente
   em `about:blank`. Navegue nesse Chrome e clique em **Encerrar** no ScrapeLens.
2. **Abrir captura…** (`⌘O`) seleciona uma pasta de sessão com `session.json`.
   Os comandos **Importar HAR** e **Importar NetLog** têm seletores próprios.
3. Selecione uma requisição para inspecionar headers, cookies, payload,
   resposta, redirects, tentativas e evento original. Estados de corpo ausente
   são explícitos; HTML capturado nunca é executado.
4. **Comparar…** compara duas requisições da sessão aberta. A busca atual
   cobre URL, ID, método e status; não pesquisa corpos.

Atalhos incluem `⌘F` buscar e `⌘⇧C` copiar URL. Capturas/importações são salvas
em `~/Library/Application Support/app.scrapelens.desktop/sessions/` com
permissões 0700/0600. O perfil pessoal do Chrome não é utilizado.

## Exportação e sanitização

Disponíveis no CLI do core; ainda não conectadas a ações da interface desktop.
O CLI é uma ferramenta separada de desenvolvimento, não é embarcado no `.app`.
Na raiz, compile e use uma pasta de sessão e IDs reais obtidos por `inspect`:

```sh
cargo build --manifest-path core/Cargo.toml --release --offline
core/target/release/scrapelens-core inspect /caminho/sessao
core/target/release/scrapelens-core export-curl /caminho/sessao cdp-r0001
core/target/release/scrapelens-core export-python /caminho/sessao cdp-r0001
core/target/release/scrapelens-core sanitize /caminho/sessao /caminho/saida-nova
```

Os caminhos e o ID acima são exemplos. Sanitização é heurística; eventos
brutos e anexos não sanitizáveis são omitidos com aviso. Revise a saída antes
de compartilhar. Código exportado não é executado automaticamente e não
promete reproduzir TLS, fingerprint ou transporte do Chrome.

## Fidelidade e limitações

- Headers são arrays ordenados com duplicatas e proveniência por informação.
  Sem evidência, a UI mostra **não verificada**; HAR e objetos CDP não
  comprovam ordem transmitida. NetLog/`headersText` h1 fornecem evidências
  específicas; h2/h3 têm cobertura parcial conforme a matriz.
- Empates na correlação CDP×NetLog aparecem como ambíguos, com candidatos.
- Chrome 156.0.8078.48 foi medido em HTTP/1.1, h2 e h3 locais. HTTP/3 foi
  observado com aioquic; o cenário quiche ficou bloqueado. QUIC não é
  desabilitado por padrão. Veja a [matriz](docs/02-matriz-fidelidade.md).
- Captura acompanha um target/página. Corpos CDP não são baixados e ficam
  `unavailable`; importações podem trazer corpos em anexos.
- CDP usa loopback e porta efêmera, com `--remote-allow-origins=*`; o endpoint
  aceita qualquer Origin durante a captura. Zero eventos CDP gera erro
  explícito; sessões com eventos parciais são preservadas como parciais.
- Busca em payload, análise de priming/campos dinâmicos e comparação entre
  sessões do caso DETRAN ainda não estão implementadas na UI.
- Bateria: 10/10, 282 asserções. Captura nova e importações HAR/NetLog
  verificadas no bundle final; arquivos selecionados manualmente pelo usuário
  no seletor nativo. [Relatório final](docs/06-entrega.md) e
  [bateria](docs/05-aceite.md).

## Desenvolvimento e build

Requisitos: Xcode Command Line Tools, Rust e Node/npm. Ambiente validado:
Rust 1.98.1 e Node 26.8.1. Lockfiles estão em `core/`, `src-tauri/` e `app/`.
Comandos independentes, todos executados da raiz:

```sh
npm --prefix app ci
npm --prefix app run typecheck
npm --prefix app run build
cargo test --manifest-path core/Cargo.toml --offline
cargo test --manifest-path src-tauri/Cargo.toml --offline
./app/node_modules/.bin/tauri dev
./app/node_modules/.bin/tauri build --bundles app
codesign --force --deep --sign - src-tauri/target/release/bundle/macos/ScrapeLens.app
codesign --verify --deep --strict src-tauri/target/release/bundle/macos/ScrapeLens.app
```

O primeiro build pode precisar baixar dependências; `--offline` requer cache.
Para a bateria e captura de referência, consulte [tests/README.md](tests/README.md).
O harness usa Python apenas em desenvolvimento. [Contribuição](CONTRIBUTING.md).

## Código e dependências

Código do ScrapeLens sob [MIT](LICENSE). Tauri/plugins, React, Vite,
TypeScript e crates Rust conservam suas próprias licenças; versões exatas
constam dos lockfiles. O inventário completo de avisos/licenças transitivas
para redistribuição ainda está pendente; não houve auditoria completa.

`app/`: UI; `src-tauri/`: shell/captura; `core/`: modelo/importadores/exportação;
`tests/`, `fixtures/`, `testserver/`: validação; `experiments/`: fidelidade;
`docs/`: decisões e evidências. `outputs/ux-review/` é proposta isolada, não
integrada ao produto.
