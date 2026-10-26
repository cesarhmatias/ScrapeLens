# Matriz de fidelidade — ordem e repetição de headers

Pergunta central: **quais fontes e eventos preservam qual sequência de
headers em cada protocolo e versão do navegador?**

Preencher por experimento controlado. Cada linha exige evidência (arquivo de
experimento + captura). Sem evidência = "não verificada".

| Navegador/versão | Protocolo | Fonte/evento | Informação preservada | Transformações observadas | Limites | Evidência |
|---|---|---|---|---|---|---|
| (pendente) | | | | | | |

## Separação obrigatória por linha

1. Ordem apresentada pela fonte (ex.: objeto CDP, HAR).
2. Ordem da lista entregue ao codificador (ex.: headers → HPACK).
3. Ordem decodificada observada na transmissão (observação no servidor,
   antes de conversões que destruam ordem/repetição).

## Regras

- Não assumir: HAR preserva ordem; enumeração CDP = sequência transmitida;
  evento NetLog = sequência final; headers de biblioteca são enviados sem
  transformação; 403 vem da ordem de headers.
- Referência de servidor deve observar a ordem bruta no ponto de decodificação
  (dicionário normalizado não serve).
- Diferenciar ordem de headers de requisição de ordem de pacotes/frames/
  requisições concorrentes.
- Experimentos: HTTP/1.1, HTTP/2 e HTTP/3; headers repetidos, pseudoheaders,
  cookies.
- Se a sequência transmitida não puder ser comprovada: registrar "não
  verificada" e seguir com funcionalidades independentes.
