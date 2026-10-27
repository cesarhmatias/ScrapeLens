# detran-pb — fixture do caso de referência (forma real, valores sintéticos)

Caso de aceite: reconstrução da sessão DETRAN-PB descrita em
`docs/05-caso-referencia-detran.md`. Esta fixture existe para os testes de
**importação, busca no corpo, agrupamento proteção × aplicação, campos
dinâmicos e correlação CDP×NetLog**.

**Rótulo:** `sanitized-shape-real-case` — a *forma* do fluxo veio do caso real;
todos os valores são sintéticos e **nenhum byte dos HARs originais foi
copiado** para o repositório.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `detran-pb-sanitized.har` | 13 entradas: entrada → NatLogon → SIM1000X → on_interceptor → VES0009X → cmd_filtro → cmd_consultar_placa → cmd_nova → cmd_consultar_placa |
| `detran-pb-blocked.har` | 3 entradas de bloqueio: 200 sem XML/STAMP, Connector sem modelo, 403 |
| `detran-pb.cdp.jsonl` | 47 eventos CDP sintéticos (`requestWillBeSent`, `requestWillBeSentExtraInfo` só nos POSTs, `responseReceived`, `loadingFinished`) |
| `detran-pb.netlog.json` | 52 eventos NetLog no formato de `fixtures/aceite` (URL_REQUEST, headers enviados/recebidos, stream job) |
| `manifest.json` | fluxo esperado, cadeia de STAMP, casos de busca, ambiguidade, listas de campos dinâmicos/estáticos |
| `build_fixtures.py` | gerador determinístico (relógio fixo 2026-10-26T23:00Z) |
| `validate.py` | verifica estrutura, fluxo, tamanhos, busca, ambiguidade e ausência de marcadores reais |

```sh
python3 fixtures/detran-pb/build_fixtures.py   # regenera
python3 fixtures/detran-pb/validate.py         # OK: 13 entradas, 8 Connector posts...
```

## O que a forma preserva

- Endpoints e páginas: `/servlet/easynat-app?op=S37`, `/cisnatural/NatLogon.html`,
  `/UIC-SERVICOS/SIM1000X.html`, `/UIC-SERVICOS/VES0009X.html`,
  `POST /servlet/Connector`. Ruído de proteção: `GET /TSPD/?type=18`.
- Formulário: `SESSIONID`, `PAGEINITPARAM`, `XML`, (`ERRORMESSAGE`), `STAMP` —
  `STAMP=INIT` na inicialização e o último STAMP nas demais chamadas.
- Protocolo textual no campo `XML` (não é XML): comprimentos em unidades
  UTF-16, opcodes de requisição `i/v/p/x` e de resposta `l/p/q/z/w/b/c/s/k/x`.
  O `delta` inicial é `inittini`; as respostas trazem delta novo a cada passo.
- Eventos: `on_interceptor` (S37 no item 1), `cmd_filtro`, `cmd_consultar_placa`,
  `cmd_nova`, `cmd_consultar_placa` (segunda placa).
- Corpo completo × delta: a primeira consulta traz `v_situacao_atual`
  (`Veículo Apreendido`) e histórico; a segunda **omite** `v_situacao_atual`,
  mantém `vp_situacao_atual=true` e as linhas `situacao_rows.items[...]`.
- Duas consultas com **mesma URL e método**, diferenciadas só pelo corpo/STAMP —
  caso de ambiguidade para correlação (não associar por URL).
- HTTP 200 que **não** é sucesso da aplicação (desafio/`request rejected`).

As respostas do Connector foram verificadas contra o decodificador de referência
do caso (`decode_stream`): decodificam na ordem, com os campos e o delta
esperados. O decodificador não faz parte desta fixture nem do MVP.

## Valores sintéticos

| Item | Valor |
|---|---|
| `SESSIONID` | `CSAN00000_000000000001` (22 caracteres, mesma forma) |
| `m_currentProcessId` | `100000000001` |
| placas | `TST0T00`, `TST0T01` (formato Mercosul, inexistentes por convenção `TST`) |
| STAMP | `INIT`, `2001`..`2008` |
| delta | `inittini`, `DLTA0001`..`DLTA0008` |
| cookies | `TS01a1b2c3=0189…f0` e `JSESSIONID=SYNTH…0001` |
| IP do servidor | `198.51.100.10` (TEST-NET-2) |
| modelo Natural | `SA90001_CSAN00000`, `SA90002_…`, `SA90003_…` |

Ausentes por construção: cookies/TS* reais, SESSIONID real, placas de terceiros,
tokens STAMP/delta reais, HTML original, IP real, dados pessoais, `Authorization`.
O gerador recusa qualquer valor vindo dos HARs; `validate.py` falha se um
marcador real aparecer (`CASA`, `NUPP`, `082b79`, nomes dos HARs etc.).

## Como usar nos testes

- **Busca no corpo**: `cmd_consultar_placa` deve achar as entradas 10 e 12;
  `cmd_nova` a 11; `on_interceptor` a 6. Busca por URL é insuficiente para as
  consultas.
- **Proteção × aplicação**: `/TSPD/` é ruído; o Connector é a aplicação.
  Uma resposta 200 com `challenge` e sem `XML`/`STAMP` não é sucesso.
- **Campos dinâmicos**: `SESSIONID`, `STAMP`, `delta`, timestamps do stream e
  `pageInitParam` mudam entre sessões; endpoints, eventos e nomes de campo não.
- **Correlação**: `requestId` do CDP ≠ `source.id` do NetLog; `time` do NetLog é
  em **microssegundos de ticks** e o relógio de parede é
  `timeTickOffset + time/1000` (ms) — comparar `time` cru com `wallTime` do CDP
  não correlaciona. As duas consultas
  têm a mesma URL, então a associação precisa de corpo/horário e deve poder
  declarar ambiguidade. `headersText` do `requestWillBeSentExtraInfo` preserva a
  ordem dos headers; o objeto `headers` do CDP não.
- **Timeline**: `cmd_nova` entre consultas é visível como passo próprio.

## Limites

- Não reproduz TSPD, CAPTCHA, cookies de proteção reais, TLS/JA3 nem ordem de
  headers transmitida (a matriz de fidelidade cobre isso com o `testserver/`).
- Os caminhos e nomes de evento são os do caso; qualquer semelhança de valor é
  coincidência dos formatos (placa, STAMP), não dado real.
- Fixture estática: não execute os endpoints nem navegue para o domínio real.
