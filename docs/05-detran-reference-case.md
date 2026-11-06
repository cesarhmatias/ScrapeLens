# Reference case: DETRAN-PB session reconstruction

User's real case (2026-10-26), already solved manually via HAR + Python
(`curl_cffi`, `impersonate=chrome142`). It serves as an acceptance scenario for
ScrapeLens: **identify and analyze this case with the tool, without Wireshark
and without reading HAR by hand.**

Local sources (do NOT copy raw into the repository; they contain cookies,
SESSIONID and third-party plates). They are kept outside the repository and
are given to the checks through `SL_REAL_HARS` (see `tests/acceptance/check_timeline_validation.py`):
- the case's "without captcha" HAR (`sem_captcha`);
- the HAR of the plate query (`fluxo`) and the HAR of the captcha solve (`captcha.solve`).

## Lessons from the case → product requirements

| Step of the case | Capability required of ScrapeLens |
|---|---|
| 1. Separate protection (/TSPD/, TS* cookies) from the application (Connector) | Grouping/labeling of requests by domain+purpose; view of "application chain" vs "protection noise" |
| 2. Find the POST that queries the plate | Search by body (cmd_consultar_placa in an `x-www-form-urlencoded` payload), not only by URL |
| 3. Cannot start with the query (dependencies) | Chain of initiators/dependencies: which events created SESSIONID/STAMP/delta/state |
| 4. Priming (9 minimal requests) | Visualization of the logical sequence with application events; export of the "priming script" |
| 5. Dynamic values per response | Mark dynamic vs fixed fields when comparing two sessions of the same page |
| 6. Textual "XML" protocol (Natural for Ajax, UTF-16 lengths) | MVP: payload preserved and visible as data + access to the original event. Protocol decoder = post-MVP extension (plugin), never in the core |
| 7. Browser profile and header order | Fidelity matrix (wave 1): is the DevTools/HAR order the transmitted one? No evidence → "not verified" in the export |
| 8. cmd_nova between plates | Event cycle visible in the timeline |
| 9. Delta omits v_situacao_atual | Full bodies vs explicit deltas in the inspection |
| 10. Validate before the batch | Comparison of exported request × capture side by side |

## Derived requirements (to enter the wave 2/3 acceptance)

1. Search in the body of requests (not only URL/headers).
2. Priming chain: given an application POST, list what produced it
   (initiator + earlier events that generated the body fields).
3. Comparison of two captures of the SAME page: highlight dynamic fields
   (SESSIONID, STAMP, delta) vs static ones — basis for the user to know what
   not to copy from the HAR.
4. cURL/Python export that uses the new session (cookies/dynamic values
   marked as "obtain at runtime"), never frozen values from the HAR.
5. Distinguish HTTP success from application success: show response
   fields (XML/STAMP present? ERRORMESSAGE?) in the inspection.

## Out of the MVP (confirmed)

- Solving/bypassing CAPTCHA or /TSPD/ protection (the case explicitly does not do
  this: it reproduces the application flow).
- Natural for Ajax protocol decoder in the core.

## Fixtures

The Tests agent generates SANITIZED fixtures (masking real SESSIONID, cookies,
STAMP, third-party plates) from the HARs above, identified as
"sanitized from a real case", OR synthetic versions with the same shape
(easynat-app → NatLogon → SIM1000X → VES0009X → Connector). Raw HAR never
enters the repository.
