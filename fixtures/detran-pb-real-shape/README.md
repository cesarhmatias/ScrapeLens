# detran-pb-real-shape — forma real do caso DETRAN-PB (rodada 6)

Rótulo: **sanitizado de caso real** (forma real, valores 100% fictícios). A *estrutura* foi tirada dos HARs
reais (somente leitura, sem copiar valores nem bytes); nenhum HAR bruto entra no repositório.

| Arquivo | Conteúdo |
|---|---|
| `real-shape-1round.har` | A: 1 rodada completa (23 entradas, 8 POSTs do Connector) |
| `real-shape-2rounds.har` | B: 2 rodadas completas (46 entradas, 16 POSTs), SESSIONID/STAMP/delta/placas diferentes por rodada |
| `manifest.json` | IDs lógicos (`har-NNNN`) por papel e as expectativas dos Aceite 1–4 de `docs/10-fidelidade-caso-real.md` |
| `build_real_shape.py` / `validate.py` | gerador determinístico / validação da forma |

Forma reproduzida: Connector = HTML (~9,8 KB) com script fictício antes (`<SYNTHETIC_GUARD_DO_NOT_TOUCH>`, no
lugar do F5), `<textarea name="XML">` com entidades HTML, `<textarea name="ERRORMESSAGE">` e
`<input type="hidden" name="STAMP" value>`; HAR de criador `WebInspector` sem Cookie/Set-Cookie/`cookies[]`;
ruído `/TSPD/…` entre os passos; `jquery-ui.min.js` e `CIS_V1_SYNTH.js` com constantes do protocolo (L3);
placa (`TST0T1x`) e CPF (`000000001xx`) fictícios dentro do XML; `v_renavam=12` fora de formato (L5); GETs sem
postData (L7).

Aceite: `python3 tests/aceite/check_real_shape.py` (falha até o Core fechar L1–L8). Revalidação nos HARs reais
do usuário (só agregados): `python3 tests/aceite/check_real_detran.py <har>…`.
