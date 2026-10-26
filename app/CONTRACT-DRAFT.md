# Contrato de sessão — RASCUNHO (provisório, não oficial)

> **SUBSTITUÍDO na onda 2.** O contrato oficial é `docs/03-contratos.md`
> (formato de sessão v1), com decisões em `docs/01-decisoes.md`. A UI consome
> `src/v1/types.ts` + `src/v1/adapter.ts` desde o commit da onda 2. Este arquivo
> fica apenas como histórico da onda 1.

Status: **provisório**, escrito pelo dono de `app/` para destravar a fatia de UI.
Substitui nada: o contrato oficial será `docs/03-contratos.md` (dono: líder).
Quando o oficial existir, este arquivo é descartado e o adaptador em
`src/demo/adapter.ts` é o único ponto a reescrever.

Regra que este rascunho protege: **a UI nunca ordena, deduplica nem junta
headers por conta própria.** Ela recebe pares na sequência da fonte, com
duplicatas, e só o painel "normalizado" deriva outra visão — rotulada.

## 1. Unidades

```ts
type SourceId = "cdp" | "netlog" | "har" | "session";      // session = formato próprio
type Protocol = "HTTP/1.1" | "HTTP/2" | "HTTP/3";
type ResourceType = "document" | "stylesheet" | "script" | "xhr" | "fetch" | "image" | "font" | "other";

/** Par de header na ordem em que a fonte o entregou. `index` é a posição 0-based. */
interface HeaderPair {
  index: number;                 // posição na sequência da fonte (nunca reordenada na UI)
  name: string;                  // preserva caixa original quando a fonte preserva
  value: string;
  kind: "pseudo" | "regular";    // ":method", ":path" etc. são pseudo
  note?: string;                 // ex.: "duplicata", "valor concatenado pela fonte"
}
```

Headers são **arrays**, não mapas: `x-cache` pode aparecer duas vezes, `accept`
também, e `set-cookie` quase sempre. Pseudoheaders HTTP/2/3 entram no mesmo
array, com `kind: "pseudo"` e antes dos regulares — a UI mostra, não conserta.

```ts
interface CookiePair { name: string; value: string; index: number; }

interface ReceivedCookie extends CookiePair {
  attributes: { name: string; value?: string }[];  // Path, Domain, HttpOnly, SameSite...
  raw: string;                                     // linha Set-Cookie completa
}

interface BodyInfo {
  availability: "available" | "truncated" | "discarded" | "omitted" | "unavailable";
  contentType?: string;
  encodedSize?: number;
  decodedSize?: number;
  preview?: string;              // só texto/JSON; HTML nunca é renderizado como UI
  truncatedAt?: number;
  reason?: string;               // por que indisponível/truncado/descartado
  captureRef?: string;           // evento/arquivo de onde veio
}

interface RedirectHop {
  index: number;
  url: string;
  status: number;
  location?: string;
  protocol: Protocol;
}

interface EvidenceRef {
  source: SourceId;
  event: string;                 // ex.: "Network.responseReceivedExtraInfo"
  timestamp: string;             // ISO 8601 com ms
  method: string;                // como o dado foi obtido (ex.: "evento CDP bruto")
  eventRef?: string;             // id/handle para abrir o evento original
}

/** Estado de verificação POR INFORMAÇÃO, não por requisição. */
type Verification =
  | { status: "verified"; evidence: EvidenceRef }
  | { status: "partial"; evidence: EvidenceRef; missing: string }
  | { status: "unverified"; reason: string };   // sem evidência → UI escreve "não verificada"
```

```ts
interface RequestRecord {
  id: string;
  url: string;
  method: string;
  domain: string;
  path: string;
  status: number;
  statusText?: string;
  protocol: Protocol;
  type: ResourceType;
  startedAt: string;             // ISO 8601
  durationMs: number;
  initiator?: string;
  requestHeaders: HeaderPair[];
  responseHeaders: HeaderPair[];
  cookiesSent: CookiePair[];
  cookiesReceived: ReceivedCookie[];
  payload: BodyInfo;
  responseBody: BodyInfo;
  redirects: RedirectHop[];
  primarySource: SourceId;
  verification: {
    requestHeaders: Verification;
    responseHeaders: Verification;
    normalizedHeaders: Verification;   // derivada: nunca "verified" sozinha
    cookies: Verification;
    payload: Verification;
    responseBody: Verification;
    protocol: Verification;
    timings: Verification;
  };
}

interface SessionRecord {
  id: string;
  label: string;
  synthetic: boolean;            // true → a UI precisa mostrar "DEMO"
  createdAt: string;
  chromeVersion?: string;
  capture: { cdpEvents: number; netlogBytes?: number; status: "closed" | "partial" | "open" };
  requests: RequestRecord[];
  sources: SourceId[];
  notes?: string[];
}
```

## 2. Regras de exibição que a UI assume

1. `requestHeaders`/`responseHeaders` renderizados na ordem de `index`, incluindo
   duplicatas; nenhum `sort()`.
2. A visão normalizada é derivada e marcada: agrupa por nome, ordena por nome,
   mantém todos os valores, cita o número de duplicatas.
3. Toda informação carrega selo: **verificada**, **parcial** ou **não verificada**.
   Sem `EvidenceRef`, a UI não pode escrever "verificado".
4. Corpo com `availability != "available"` aparece com o motivo, nunca vazio mudo.
5. HTML capturado é exibido como texto (fonte), jamais injetado como interface.
6. Comparação casa pares repetidos por valor dentro do mesmo nome (multiconjunto),
   não por índice; "reordenado" só quando o par existe nos dois lados com o mesmo
   valor e posição diferente na sequência.
7. `synthetic: true` fixa o selo "DEMO — sessão sintética" no topo e no rodapé.

## 3. O que este rascunho não decide (fica para o contrato oficial)

- Forma canônica dos timestamps (ISO com ms aqui) e origem do relógio.
- Como o parser marca header concatenado pela fonte vs. duplicata real.
- Identidade estável de requisição entre CDP e NetLog.
- Persistência (`.scrapelens`), versionamento e migração.
- Streaming/importação incremental (esta fatia usa sessão em memória).
