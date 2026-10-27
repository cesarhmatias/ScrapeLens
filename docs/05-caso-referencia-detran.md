# Caso de referência: reconstrução de sessão DETRAN-PB

Caso real do usuário (2026-10-26), já resolvido manualmente via HAR + Python
(`curl_cffi`, `impersonate=chrome142`). Serve como cenário de aceite do
ScrapeLens: **identificar e analisar este caso com a ferramenta, sem Wireshark
e sem leitura manual de HAR.**

Fontes locais (NÃO copiar brutas para o repositório; conter cookies,
SESSIONID e placas de terceiros):
- `/Users/cesar/Projects/scripts/detran_scraper/detran_paraiba/inputs/sem_captcha.har`
- `/Users/cesar/Downloads/wsdetran.pb.gov.br.har.txt.har`
- `/Users/cesar/Downloads/wsdetran.fluxo.captcha.solve.pgEvy4.har.txt.har`

## Lições do caso → requisitos do produto

| Passo do caso | Capacidade exigida do ScrapeLens |
|---|---|
| 1. Separar proteção (/TSPD/, cookies TS*) da aplicação (Connector) | Agrupamento/rotulação de requisições por domínio+propósito; visão de "cadeia da aplicação" vs "ruído de proteção" |
| 2. Achar o POST que consulta a placa | Busca por corpo (cmd_consultar_placa em payload `x-www-form-urlencoded`), não só por URL |
| 3. Não dá para começar pela consulta (dependências) | Cadeia de iniciadores/dependências: quais eventos criaram SESSIONID/STAMP/delta/estado |
| 4. Priming (9 requisições mínimas) | Visualização da sequência lógica com eventos de aplicação; exportação do "script de priming" |
| 5. Valores dinâmicos por resposta | Marcar campos dinâmicos vs fixos na comparação de duas sessões da mesma página |
| 6. Protocolo textual "XML" (Natural for Ajax, comprimentos UTF-16) | MVP: payload preservado e visível como dados + acesso ao evento original. Decodificador do protocolo = extensão pós-MVP (plugin), nunca no core |
| 7. Perfil de navegador e ordem de headers | Matriz de fidelidade (onda 1): a ordem do DevTools/HAR é a transmitida? Sem evidência → "não verificada" na exportação |
| 8. cmd_nova entre placas | Ciclo de eventos visível na timeline |
| 9. Delta omite v_situacao_atual | Corpos completos vs delta explícitos na inspeção |
| 10. Validar antes do lote | Comparação requisição exportada × captura lado a lado |

## Requisitos derivados (entrar na aceite da onda 2/3)

1. Busca no corpo das requisições (não só URL/headers).
2. Cadeia de priming: dado um POST da aplicação, listar o que o produziu
   (initiator + eventos anteriores que geraram os campos do corpo).
3. Comparação de duas capturas da MESMA página: realçar campos dinâmicos
   (SESSIONID, STAMP, delta) vs estáticos — base para o usuário saber o que
   não copiar do HAR.
4. Exportação cURL/Python que use a sessão nova (cookies/valores dinâmicos
   marcados como "obter em runtime"), nunca valores congelados do HAR.
5. Distinguir sucesso HTTP de sucesso da aplicação: mostrar campos de
   resposta (XML/STAMP presentes? ERRORMESSAGE?) na inspeção.

## Fora do MVP (confirmado)

- Resolver/burlar CAPTCHA ou proteção /TSPD/ (o caso explicitamente não faz
  isso: reproduz o fluxo da aplicação).
- Decodificador do protocolo Natural for Ajax no core.

## Fixtures

O agente de Testes gera fixtures SANITIZADAS (mascarar SESSIONID, cookies,
STAMP reais, placas de terceiros) a partir dos HARs acima, identificadas como
"sanitizadas de caso real", OU versões sintéticas com a mesma forma
(easynat-app → NatLogon → SIM1000X → VES0009X → Connector). HAR bruto nunca
entra no repositório.
