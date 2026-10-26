# Fixtures sintéticas do core

Todos os arquivos aqui são **sintéticos** e marcados como tal (`_comment` ou
`comment`). Não há tráfego real, cookies reais ou domínios registráveis:
apenas `.invalid` (RFC 2606) e endereços de documentação.

- `har-minimal.json` — HAR 1.2 com headers duplicados, Cookie, Set-Cookie,
  corpo de requisição/resposta e timings.
- `netlog-h2.json` — NetLog reduzido de h2 com:
  - cadeia explícita `HTTP_STREAM_JOB_BOUND_TO_REQUEST`;
  - pseudoheaders;
  - duplicatas de header;
  - repetições fundidas por `\x00` (expandidas pelo parser);
  - um evento de tipo desconhecido e uma linha de header inválida.

Os testes também leem, **sem modificar**, as capturas reais em
`../experiments/results/h1-page` e `h2-page` para validar a fidelidade contra a
matriz.
