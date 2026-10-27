# ScrapeLens — plano de implementação da proposta de UX

Este plano descreve mudanças futuras. **Nenhuma foi aplicada ao frontend de produção nesta revisão.** Diagnóstico, evidências e imagens: [review.md](review.md). Protótipo e limitações: [proposal/README.md](proposal/README.md).

## Ordem recomendada

| Ordem | Prioridade | Entrega concreta | Componentes/arquivos afetados | Dependência | Porte relativo |
|---|---|---|---|---|---|
| 1 | P0 | Separar origem, estado da sessão e confirmação da sequência | `App.tsx`: banners, `HeaderBlock`, `VerificationPanel`, `CompareView`; `types.ts`; `v1/adapter.ts` | Auditoria da semântica de proveniência v1 e matriz existente | M |
| 2 | P0 | Não esconder APIs de HAR por ausência de tipo | Filtros em `App.tsx`, `v1/adapter.ts`; opcionalmente `core/src/parse/har.rs` | UI de tipo desconhecido independente; `_resourceType` depende de importador | S na UI / M na integração |
| 3 | P1 | Entrada vazia, lista persistente, foco e seleção por teclado | `App.tsx`: estado de sessão, tabela, `DetailView`; `styles.css`; menu Tauri | Preservar virtualização e comandos existentes | M–L |
| 4 | P1 | Busca local de headers, cookies em tabela e cópia com retorno | `HeaderBlock`, conteúdo de Cookies, `BodyPanel`, `VerificationPanel`; estilos e clipboard | Layout e política de evidência da etapa 1 | M |
| 5 | P1 | Comparação a partir da seleção, categorias e “somente diferenças” | `CompareView`, `diff.ts`, estado de A/B, reutilização de tabela seletora | Identidade de ocorrências e direção A→B estáveis | M |
| 6 | P1 | Expor exportadores existentes em “Código…” | `bridge.ts`, `src-tauri/src/commands.rs`, registro de commands, core export existente | Contrato de erros/avisos e resolução de anexos | M |
| 7 | P2 | Salva localmente, Mostrar no Finder, recuperação de importação | Cabeçalho, notices, `bridge.revealPath`, menu nativo | `sessionDir` já fornecido | S |
| 8 | P2 | Salvar cópia do bundle e reabrir por histórico, se priorizado | Commands, diálogo de destino e armazenamento de recentes | Operações adicionais no shell; não necessárias ao novo inspetor | M–L |

S/M/L representam comparação de esforço entre itens, não estimativas de prazo.

## 1. Corrigir a linguagem de fidelidade antes do desenho

Reaproveitar a proveniência por informação existente, mantendo arrays intactos. Expor um pequeno modelo de apresentação para cada direção de headers:

```ts
// Exemplo de contrato de UI futuro; não é um novo contrato de captura.
type HeaderSequencePresentation = {
  view: 'source' | 'normalized';
  transmission: 'confirmed' | 'unverified' | 'unavailable';
  sourceLabel: string;
  explanation: string;
  evidenceRef?: string;
};
```

“Sequência da fonte” é modo de visualização; não um nível intermediário entre confirmado e não verificado. `partial` deve continuar visível na explicação de “não verificada”. Normalizada é derivada e precisa de indicação sempre que selecionada.

Não mapear `HeaderPair.verification === 'verified'` diretamente para “ordem transmitida confirmada”. A verificação precisa se referir explicitamente à sequência, na direção/protocolo suportados e à evidência aprovada. A fixture atual contém verificação CDP que não deve se tornar uma promessa de ordem no fio. Se essa distinção não for recuperável da proveniência disponível, apresentar “não verificada” com motivo; não bloquear o inspetor nem enriquecer o backend apenas para sustentar o desenho.

O adaptador já recebe o v1 bruto. Campos de proveniência disponíveis mas hoje descartados para exibição podem ser expostos ao painel avançado sem mudar o formato persistido. Um atributo novo que certifique especificamente a ordem transmitida, se necessário, é evolução de contrato/core e deve ser aprovado em trabalho separado.

Trocar `SESSÃO REAL` por uma origem factual: “HAR importado”, “NetLog importado” ou “Captura local”. Estado “encerrada/parcial/gravando” não usa o mesmo tratamento do status HTTP. Demonstração tem indicação única e persistente. Atualizar mensagens/tooltips antigos que ainda dizem que a importação é demo até integrar o core: ela já está integrada.

**Aceite:** HAR sintético não é certificado como real; request h2/h3 parcial não aparece como transmissão confirmada; nenhum array é ordenado para fabricar uma sequência; enviado e recebido podem ter certezas diferentes; falta de dados não aparece como ausência legítima.

## 2. Recuperar a descoberta de chamadas importadas

A UI deve apresentar “tipo não informado” quando `request.resourceType` estiver ausente. O filtro Fetch/XHR não deve fazer a pessoa concluir que não houve API. Quando toda a sessão estiver sem tipo, mostrar explicação contextual e ação para limpar esse filtro.

Uma melhoria disponível com os dados existentes é filtro de MIME: “JSON”, contando respostas com Content-Type compatível. Não classificar JSON como Fetch, nem inferir o mecanismo de carregamento só por `/api/` na URL. Busca por URL/domínio continua independente.

**Dependência externa ao frontend:** preservar a extensão HAR `_resourceType` no campo `LogicalRequest.resource_type`. O teste sintético já fornece a extensão; o parser atual não a transporta. Não é requisito da especificação HAR básica e não resolve arquivos que legitimamente não contenham esse campo.

Na proposta, a classificação já vem em `proposal/fixtures/session.json`. O filtro Fetch/XHR funcional no protótipo **não demonstra que a importação de produção foi corrigida**. O filtro JSON e o estado de tipo ausente são recomendações documentadas, ainda não implementadas no protótipo.

**Aceite:** o HAR de teste preserva tipos quando informados; um HAR sem tipos não fabrica Fetch/XHR; tipo ausente e MIME podem ser filtrados separadamente; limpar filtros sempre recupera os 64 registros.

## 3. Transformar as três vistas em um espaço de inspeção

Manter o App e o contrato v1. Extrair, se necessário, componentes locais como `RequestList`, `RequestPreview`, `HeaderSequenceNote` e `CopyStatus`; são divisões de apresentação, não mudança de arquitetura.

Na entrada, usar estado de sessão ausente. A demonstração passa a ser escolha explícita. Reutilizar `start_session`, `import_har`, `import_netlog` e `open_session`; preservar diálogos e menus nativos.

No trabalho diário:

- Lista larga + prévia para localizar a chamada; seleção não navega imediatamente.
- Lista estreita + detalhe para inspeção. Busca/filtros ficam na coluna da lista.
- Comparação ocupa a área de dados, mantendo identificação da sessão, referências A/B e retorno à seleção anterior.
- Estado de filtros/seleção/aba e posição da lista sobrevive às trocas. Foco precisa ser restaurado em um controle existente, especialmente após filtrar e voltar.

Preservar a lista virtualizada. O protótipo usa 43 px com caminho e domínio em duas linhas; **não basta alterar a altura no CSS de produção**, pois `ROW_HEIGHT` e os cálculos de início/fim dependem dela. Escolher 41–43 px conforme o layout final e atualizar uma única constante usada pelo cálculo e estilo. Não adicionar altura variável às linhas virtualizadas sem necessidade.

Teclado: um ponto de Tab na seleção, setas para percorrer e atualizar prévia, Enter para detalhe, Escape para prévia, ←/→ nas abas, foco visível. Respeitar seleção de texto e manter ⌘C nativo; atalho explícito de URL pode ser ⌘⇧C, como no menu atual. ⌘F concentra a busca da lista sem desmontar o detalhe.

**Aceite:** repetir a tarefa de duas chamadas vizinhas sem voltar a uma tela anterior; seleção nunca fica perdida fora da região visível; 12 mil itens mantêm virtualização; busca vazia tem recuperação; navegação completa mouse/teclado em 1440 × 900 e 1280 × 800.

## 4. Tornar o detalhe legível sem reduzir dados

Reutilizar `HeaderBlock`, `BodyPanel` e a lógica de cookies. A proposta mantém:

| Região | Alteração de apresentação | Dados preservados |
|---|---|---|
| Cabeçalho | Caminho em destaque, URL completa selecionável e copiável, protocolo por chamada | URL exata, método, status, duração e protocolo |
| Headers | Busca por nome/valor; enviado/recebido; seletor fonte/normalizada | Índice original e multiplicidade; pseudoheaders em grupo próprio |
| Evidência | Uma linha contextual + explicação ao abrir | Fonte, evento, horário, método, limite e verificação por informação |
| Cookies | Tabela enviada + Cookie bruto + Set-Cookie independentes | Pares repetidos, atributos, erro de parse, wire lines quando disponíveis |
| Corpos | Estado e motivo próximos da prévia | Capturado/vazio/truncado/descartado/indisponível e anexos |
| Avançado | Evidência/Tentativas/Redirects/candidatos sob demanda | Dados atuais, inclusive ambiguidade e warnings importantes |

Na busca de header, manter o índice e a ocorrência **anteriores ao filtro**. Exemplo da fixture: buscar `text/plain` continua mostrando `#5`, accept, ocorrência 2 de 2. A visão normalizada pode ordenar uma cópia derivada; não mutar o array da fonte.

Pseudoheaders podem iniciar recolhidos, com “4 pseudoheaders · índices 0–3 · mostrar”. Busca por pseudoheader deve encontrá-lo sem exigir expansão manual. A indicação evita que o usuário leia o índice 4 como início original da sequência.

Mover `notice` de cópia para um status global, fora da condição `view === 'session'`. Erros de importação pertencem à sessão/operação, falhas HTTP pertencem à linha. Explicação de falha de clipboard oferece seleção manual.

**Aceite:** duplicatas, Cookie e Set-Cookie não são fundidos; nenhum valor é cortado no dado copiado; não inferir armazenamento a partir de Set-Cookie; não derivar protocolo de Alt-Svc; HTML capturado continua sendo texto.

## 5. Comparar a tarefa, mantendo a precisão do diff

Reaproveitar `diffHeaders` e `diffCookies`. O casamento por nome/valor/multiplicidade é uma base útil. Auditar casos de mesma chave repetida com valores idênticos; o índice de uma ocorrência não pode ser recuperado só com `findIndex` de nome/valor em produção. Preservar a identidade da ocorrência durante o casamento.

A seleção atual preenche A; selecionar B por busca na lista da sessão, com método/domínio/status. A proposta usa select nativo por ser uma fixture pequena; não levar uma lista de 12 mil URLs a um select de produção.

Contar diferenças por categoria, em vez de um total global parcial. A categoria Headers recebe enviado/recebido ou a resposta fica em categoria própria. Payload compara campos quando conteúdo JSON for capturado e parseável, com bruto disponível e indicação de visão derivada. Payload ausente/truncado/inacessível não vira objeto vazio. Conteúdo não JSON pode começar com diff textual, sem tentar inferir estrutura.

Exibir posições como diferenças na fonte quando a transmissão não estiver confirmada em ambos os lados. Comparar ordem relativa entre pares estáveis; inserir um header anterior não deve marcar todos os seguintes como reordenados. Distinguir alteração de valor e posição quando ambas ocorrerem, sem apagar informação. Evitar equiparar Host h1 e pseudoheaders h2 como campos regulares comuns.

**Aceite:** +adicionado, −removido, ~valor, ↕posição reconhecíveis sem cor; iguais consultáveis; URLs/valores longos não deslocam as colunas; Cookie removido, página alterada e protocolo diferente têm categorias visíveis; dados brutos são complemento; nenhum texto afirma causa do 403.

## 6. Completar o caminho até o código

Adicionar commands finos sobre `core::export` e entrada correspondente na ponte; reusar `read_attachment`/bundle para resolver corpos. Não criar outro exportador de produção no React.

“Código…” abre formato, prévia, avisos do exportador e ações de copiar/salvar. Não gerar pseudoheaders como headers regulares. Preservar headers repetidos quando o formato permitir, informar remoções necessárias e ausência/truncamento de corpo. Avisar que o cliente pode escolher outro protocolo/reorganizar headers. A ordem dos argumentos não é garantia de sequência na transmissão.

A demonstração só mostra cURL com dados sintéticos. Python e exportação do bundle são dependências futuras de integração já identificadas, não funcionalidades concluídas.

**Aceite:** comportamento consistente com o core atual; nenhum corpo ausente é fabricado; anexos não são interpretados como UI; códigos copiados correspondem à chamada escolhida e aos avisos apresentados.

## Tokens e regras visuais recomendadas

Reaproveitar as variáveis CSS de `.app`. Valores de referência do protótipo, ajustáveis na integração:

| Papel | Referência |
|---|---|
| Área de dados | `#ffffff` |
| Fundo auxiliar | `#f6f7f9` |
| Sidebar | `#eef0f3` |
| Texto | `#202a38` |
| Texto secundário | `#5d6b7e` |
| Divisor | `#dce1e7` |
| Ação/foco | `#245bdd` |
| Seleção | `#e9f0ff`, barra lateral e `aria-selected` |
| Sucesso/adição | `#17704e` + texto/símbolo |
| Falha/remoção | `#b32632` + texto/símbolo |
| Valor alterado | `#8d5c0c` + `~ Valor` |
| Tipografia | Sistema macOS para UI; SF Mono/Menlo para nomes/valores/URLs |
| Tamanhos | UI 13 px; dado prioritário 12 px; metadados 11 px; somente índices e rótulos auxiliares 10 px |
| Geometria | Divisores de 1 px; raio 5–6 px; evitar cartões envolvendo cada campo |

No Tauri, usar controles e barra de título nativos, sem círculos HTML decorativos duplicados. O protótipo web desenha um shell ilustrativo para avaliação. Manter claro/escuro existentes; resolver um tema primeiro, sem apagar a preferência do usuário.

## Dependências novas, separadas do frontend

| Item | Requer novo backend/dado? | Tratamento nesta entrega |
|---|---|---|
| Lista/detalhe, busca de header, foco, banners, diff por categoria | Não; usa v1 e cálculo local | Demonstrado com fixture |
| Filtro por MIME/JSON | Não, quando Content-Type já existe | Recomendado no plano; não prototipado |
| Preservar `_resourceType` do HAR | Sim, ajuste no parser existente | Problema reproduzido, não corrigido |
| Confirmar ordem quando proveniência não distingue a semântica | Talvez, metadado/contrato explícito | Sempre conservador; não inventar certeza |
| Exportar cURL/Python na UI | Integração Tauri nova, exportador já existe | Prévia cURL sintética no protótipo |
| Mostrar no Finder | Command já existe | Recomendação, sem serviço novo |
| Salvar cópia do bundle v1 | Operação/diálogo no shell | JSON próprio de demonstração, não bundle v1 |
| Histórico de recentes | Persistência de referências e tratamento de caminho ausente | Não desenhado como funcionalidade pronta |
| Cookies armazenados | Snapshot adicional, ausente neste modelo de tela | Indisponível; não inferir de enviados/recebidos |
| Corpos CDP reais | Captura/download ainda incompleto conforme README | Proposta respeita indisponível; não promete resolver |
| Comparar sessões independentes/importar somente B | Novo fluxo/estado e seleção cruzada | Fora do protótipo; #64 já faz parte da fixture |

## Verificação na implementação futura

Usar fixtures sintéticas/sanitizadas: h1 confirmado quando suportado pela matriz, h2/h3 parcial, HAR sem tipo, headers repetidos idênticos/diferentes, Cookie dividido, dois Set-Cookie, correlação ambígua e corpo indisponível. Verificar o critério de cada etapa antes de ampliar o escopo.

Testes prioritários são semânticos e de integração: limite de evidência, perda de `_resourceType`, preservação de ocorrências no diff, navegação da lista virtualizada e exportação de corpo/headers. Não há motivo para criar snapshots de CSS como prova de fidelidade HTTP.

Repetir a inspeção visual nas duas dimensões, com teclado, filtro ativo e valores longos. Para performance, repetir o cenário de 12 mil linhas após integrar as linhas de duas alturas de texto. Realizar a validação completa de captura posteriormente contra `testserver/`, sem perfis pessoais ou credenciais reais.
