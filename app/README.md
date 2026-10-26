# ScrapeLens — fatia de interface (prévia, sessão sintética)

Prévia navegável da interface pedida pelo usuário **antes** do gate de fidelidade.
Serve para revisar hierarquia, densidade, estados de verificação e tema. Não é a
interface final e não captura nada.

## O que é real aqui

- Componentes React + TypeScript, CSS, build Vite, tema claro/escuro.
- A lógica de listagem, busca, filtros, normalização de headers **derivada** e o
  diff de headers (adicionados/removidos/alterados/reordenados) com pareamento de
  repetidos por valor.
- Prints gerados por Chromium real (Playwright) a partir do build.

## O que é sintético / desligado

- Toda a sessão `demo-sintetica-01`: 13 requisições inventadas em domínios
  `.invalid`, corpos fictícios, eventos e timestamps simulados. A tela marca
  **DEMO / dados sintéticos** no título, no banner, na sessão e no rodapé.
- Iniciar/Encerrar/Abrir captura estão **desativados** com o motivo visível:
  captura ao vivo e importadores dependem da matriz de fidelidade e do contrato
  oficial.
- Copiar valores, abrir evento original e alternar abas são interações de UI sem
  integração nativa ainda.
- Sem Tauri nesta fatia (rodou no navegador para os prints, como autorizado).
- Sem telemetria, sem rede, sem persistência.

## Contrato

`CONTRACT-DRAFT.md` define o contrato **provisório** de sessão usado pelos tipos
em `src/types.ts`. Ele existe só para destravar esta fatia e será substituído por
`docs/03-contratos.md` (dono: líder). O ponto de troca é `src/demo/session.ts`
(dados) e `src/types.ts` (formas).

## Rodar

```sh
cd app
npm install
npm run dev        # http://localhost:5173
npm run build      # gera dist/
npm run shots      # build já pronto → PNGs em ../docs/screenshots/
npm run typecheck
```

Parâmetros de URL úteis para abrir um estado direto:

```
?view=session&theme=dark
?view=detail&id=req-0004&tab=headers   # headers|normalized|cookies|payload|response|redirects|event
?view=compare&a=req-0009&b=req-0010
```

## Prints

`../docs/screenshots/` — `01`…`11`, com principal, detalhe e comparação em claro
e escuro. Gerados em 1440 px CSS, escala 2×.

## Limites conhecidos

- Diálogos nativos, atalhos reais (⌘O/⌘F/⌘C), seleção manual do Chrome e
  empacotamento Tauri não estão nesta fatia.
- Importação grande/streaming não foi exercitada: a sessão demo é pequena.
- O diff cobre headers de requisição, headers de resposta, cookies enviados,
  corpo e protocolo; cookies recebidos aparecem na tela de detalhe, ainda não no
  diff.
