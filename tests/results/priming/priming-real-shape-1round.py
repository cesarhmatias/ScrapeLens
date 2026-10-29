#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Script de priming gerado pelo ScrapeLens para a requisição har-0026.
# Reprodução semântica: a ordem de headers e a fidelidade de transporte (TLS, HTTP/2, fingerprint) NÃO são garantidas.
# Não executado pelo ScrapeLens: quem roda é você, sob sua responsabilidade.
# Passos que alteram estado (POST/PUT/PATCH/DELETE) exigem --confirmar; sem ela o script imprime o plano e sai.
# Valores com origem observada são extraídos das respostas em runtime; nunca se usa o valor capturado no lugar de um extraído.
# Valores sensíveis ou redigidos são parâmetros obrigatórios, sem padrão.
# não resolvido: har-0026 x-requested-with (sem origem observada (valor já circulava em har-0010, har-0015, har-0017, har-0022, har-0024))
# não resolvido: har-0026 SESSIONID (sem origem observada; contém o valor de m_currentSessionId de har-0001 (prefixo) e parte sem fonte observada — provável composição no cliente (valor já circulava em har-0010, har-0015, har-0017, har-0022, …
# não resolvido: har-0024 x-requested-with (sem origem observada (valor já circulava em har-0010, har-0015, har-0017, har-0022))
# não resolvido: har-0024 SESSIONID (sem origem observada; contém o valor de m_currentSessionId de har-0001 (prefixo) e parte sem fonte observada — provável composição no cliente (valor já circulava em har-0010, har-0015, har-0017, har-0022))…
# não resolvido: har-0022 x-requested-with (sem origem observada (valor já circulava em har-0010, har-0015, har-0017))
# não resolvido: har-0022 SESSIONID (sem origem observada; contém o valor de m_currentSessionId de har-0001 (prefixo) e parte sem fonte observada — provável composição no cliente (valor já circulava em har-0010, har-0015, har-0017)) — montado…
# não resolvido: har-0021 page (sem origem observada)
# não resolvido: har-0017 x-requested-with (sem origem observada (valor já circulava em har-0010, har-0015))
# não resolvido: har-0017 SESSIONID (sem origem observada; contém o valor de m_currentSessionId de har-0001 (prefixo) e parte sem fonte observada — provável composição no cliente (valor já circulava em har-0010, har-0015)) — montado no client…
# não resolvido: har-0015 x-requested-with (sem origem observada (valor já circulava em har-0010))
# não resolvido: har-0015 SESSIONID (sem origem observada; contém o valor de m_currentSessionId de har-0001 (prefixo) e parte sem fonte observada — provável composição no cliente (valor já circulava em har-0010)) — montado no cliente: complet…
# não resolvido: har-0014 page (sem origem observada)
# não resolvido: har-0010 x-requested-with (sem origem observada)
# não resolvido: har-0010 SESSIONID (sem origem observada; contém o valor de m_currentSessionId de har-0001 (prefixo) e parte sem fonte observada — provável composição no cliente) — montado no cliente: complete aqui
# não resolvido: har-0008 page (sem origem observada)
# não resolvido: har-0001 op (sem origem observada)

import argparse
import html.parser
import json
import re
import sys
import urllib.parse


def fail(message):
    sys.exit('priming: ' + message)


class _Controls(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items = []
        self._area = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else '') for k, v in attrs}
        if tag == 'input' and 'name' in a:
            if a.get('type', '').lower() in ('checkbox', 'radio') and not any(k == 'checked' for k, _ in attrs):
                return
            self.items.append((a['name'], a.get('value', '')))
        elif tag == 'textarea' and 'name' in a:
            self._area = [a['name'], '']

    def handle_data(self, data):
        if self._area is not None:
            self._area[1] += data

    def handle_endtag(self, tag):
        if tag == 'textarea' and self._area is not None:
            self.items.append((self._area[0], self._area[1]))
            self._area = None


def html_control(resp, name, index, who):
    parser = _Controls()
    parser.feed(resp.text)
    parser.close()
    found = [v for k, v in parser.items if k == name]
    if index >= len(found):
        fail('controle HTML %r não encontrado na resposta de %s' % (name, who))
    return found[index]


def body_field(resp, name, who):
    text = resp.text
    try:
        stack = [json.loads(text)]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                if name in node:
                    return node[name] if isinstance(node[name], str) else json.dumps(node[name])
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    except ValueError:
        pass
    values = urllib.parse.parse_qs(text, keep_blank_values=True).get(name)
    if values:
        return values[0]
    fail('campo %r não encontrado na resposta de %s' % (name, who))


def get_cookie(session, name, who):
    value = session.cookies.get(name)
    if value is None:
        fail('cookie %r não está no cookie jar (%s)' % (name, who))
    return value


def get_header(resp, name, who):
    value = resp.headers.get(name)
    if value is None:
        fail('header %r ausente na resposta usada por %s' % (name, who))
    return value


def ctx_extract(text, before, after, who):
    pattern = (re.escape(before) if before else r'\A') + '(.+?)' + (re.escape(after) if after else r'\Z')
    match = re.search(pattern, text, re.S)
    if not match:
        fail('não achei o valor pelo contexto (%r ... %r) para %s' % (before, after, who))
    return match.group(1)


def checked(value, size, who):
    if len(value) != size:
        sys.stderr.write('priming: aviso: %s mudou de tamanho (%d -> %d); prefixos de comprimento do protocolo podem precisar de ajuste\n' % (who, size, len(value)))
    return value


def rebase(url, base):
    if base and url.startswith(CAPTURED_ORIGIN):
        return base.rstrip('/') + url[len(CAPTURED_ORIGIN):]
    return url

CAPTURED_ORIGIN = 'https://wsdetran.pb.gov.br'
TARGET = 'har-0026'
HAS_STATE_CHANGE = True
PLAN = [
    ('har-0001', 'GET', 'https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/easynat-app', 'fornece XML a har-0026 (ValueMatch); fornece XML a har-0024 (ValueMatch); fornece XML a har-0022 (ValueMatch); fornece XML a har-0017 (ValueMatch); fornece XML ', True),
    ('har-0008', 'GET', 'https://wsdetran.pb.gov.br/detran-portal-servicos/cisnatural/cscform.html', 'fornece XML a har-0010 (ValueMatch); fornece STAMP a har-0010 (SameField)', True),
    ('har-0010', 'POST', 'https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', 'fornece XML a har-0015 (ValueMatch)', False),
    ('har-0014', 'GET', 'https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/cscform.html', 'fornece XML a har-0017 (ValueMatch); fornece XML a har-0015 (ValueMatch); fornece STAMP a har-0015 (SameField)', True),
    ('har-0015', 'POST', 'https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', 'fornece XML a har-0017 (ValueMatch); fornece STAMP a har-0017 (SameField)', False),
    ('har-0017', 'POST', 'https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', 'fornece XML a har-0022 (ValueMatch)', False),
    ('har-0021', 'GET', 'https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/cscform.html', 'fornece XML a har-0026 (ValueMatch); fornece XML a har-0024 (ValueMatch); fornece XML a har-0022 (ValueMatch); fornece STAMP a har-0022 (SameField)', True),
    ('har-0022', 'POST', 'https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', 'fornece XML a har-0026 (ValueMatch); fornece XML a har-0024 (ValueMatch); fornece STAMP a har-0024 (SameField)', False),
    ('har-0024', 'POST', 'https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', 'fornece XML a har-0026 (ValueMatch); fornece STAMP a har-0026 (SameField)', False),
    ('har-0026', 'POST', 'https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', 'requisi\xe7\xe3o alvo', False),
]
PARAMS = [
    ('op', None, 'sem origem observada'),
    ('page', None, 'sem origem observada'),
    ('sessionid_cliente', None, 'montado no cliente'),
    ('page_2', None, 'sem origem observada'),
    ('page_3', None, 'sem origem observada'),
    ('placa', None, 'entrada do usu\xe1rio dentro de campo opaco'),
    ('cpf', None, 'entrada do usu\xe1rio dentro de campo opaco'),
]


def step_1(S, R, P, base):
    # passo 1: fornece XML a har-0026 (ValueMatch); fornece XML a har-0024 (ValueMatch); fornece XML a har-0022 (ValueMatch); fornece XML a har-0017 (ValueMatch); fornece XML a har-0015 (ValueMatch); fornece XML a har-0010 (ValueMatch)
    # passo 1: confiança possible
    # op: sem origem observada; parâmetro obrigatório, sem padrão
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/easynat-app', base) + '?' + urllib.parse.urlencode([('op', P['op'])])
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'}
    return S.request('GET', url, headers=headers, timeout=30)


def step_2(S, R, P, base):
    # passo 2: fornece XML a har-0010 (ValueMatch); fornece STAMP a har-0010 (SameField)
    # passo 2: confiança strong
    # page: sem origem observada; parâmetro obrigatório, sem padrão
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/cisnatural/cscform.html', base) + '?' + urllib.parse.urlencode([('page', P['page'])])
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/cisnatural/NatLogon.html', base)}
    return S.request('GET', url, headers=headers, timeout=30)


def step_3(S, R, P, base):
    # passo 3: fornece XML a har-0015 (ValueMatch)
    # passo 3: confiança possible
    # SESSIONID: montado no cliente: complete aqui (parte inicial extraída do produtor har-0001; o resto é o parâmetro sessionid_cliente, obrigatório)
    # XML: trecho 20..29 extraído em runtime (origem possível)
    # XML: trecho 42..74 extraído em runtime (origem possível)
    # XML: trecho 74..91 extraído em runtime (origem possível, ambíguo)
    # STAMP: extraído em runtime (origem forte)
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', base)
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/cisnatural/cscform.html?page=NatLogon', base), 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'origin': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos', base), 'x-requested-with': 'XMLHttpRequest'}
    data = urllib.parse.urlencode([
        ('SESSIONID', ctx_extract(R['har-0001'].text, ' = "', '"', 'SESSIONID (har-0010)') + P['sessionid_cliente']),
        ('PAGEINITPARAM', ''),
        ('XML', 'i2232001705025000005' + checked(ctx_extract(R['har-0001'].text, ' = "', '"', 'XML[20] (har-0010)'), 9, 'XML[20]') + P['sessionid_cliente'] + checked(ctx_extract(R['har-0001'].text, 'sId = "', '"', 'XML[42] (har-0010)'), 32, 'XML[42]') + checked(ctx_extract(R['har-0001'].text, 'Id("', '"', 'XML[74] (har-0010)'), 17, 'XML[74]') + 'dummy/cisnatural/NatLogon.htmlfalsep1300006pageInitParamop=S37p1500001pagePixelHeight0p1400001pagePixelWidth0p1400004timeZoneOffset-180x08inittini'),
        ('STAMP', html_control(R['har-0008'], 'STAMP', 0, 'STAMP (har-0010)'))
    ])
    return S.request('POST', url, headers=headers, data=data, timeout=30)


def step_4(S, R, P, base):
    # passo 4: fornece XML a har-0017 (ValueMatch); fornece XML a har-0015 (ValueMatch); fornece STAMP a har-0015 (SameField)
    # passo 4: confiança strong
    # page: sem origem observada; parâmetro obrigatório, sem padrão
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/cscform.html', base) + '?' + urllib.parse.urlencode([('page', P['page_2'])])
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/SIM1000X.html', base)}
    return S.request('GET', url, headers=headers, timeout=30)


def step_5(S, R, P, base):
    # passo 5: fornece XML a har-0017 (ValueMatch); fornece STAMP a har-0017 (SameField)
    # passo 5: confiança strong
    # SESSIONID: montado no cliente: complete aqui (parte inicial extraída do produtor har-0001; o resto é o parâmetro sessionid_cliente, obrigatório)
    # XML: trecho 20..29 extraído em runtime (origem possível)
    # XML: trecho 42..74 extraído em runtime (origem possível)
    # XML: trecho 74..91 extraído em runtime (origem possível, ambíguo)
    # XML: trecho 96..123 extraído em runtime (origem possível)
    # XML: trecho 222..233 extraído em runtime (origem possível)
    # STAMP: extraído em runtime (origem forte)
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', base)
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/cscform.html?page=SIM1000X', base), 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'origin': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos', base), 'x-requested-with': 'XMLHttpRequest'}
    data = urllib.parse.urlencode([
        ('SESSIONID', ctx_extract(R['har-0001'].text, ' = "', '"', 'SESSIONID (har-0015)') + P['sessionid_cliente']),
        ('PAGEINITPARAM', ''),
        ('XML', 'i2232001705027000005' + checked(ctx_extract(R['har-0001'].text, ' = "', '"', 'XML[20] (har-0015)'), 9, 'XML[20]') + P['sessionid_cliente'] + checked(ctx_extract(R['har-0001'].text, 'sId = "', '"', 'XML[42] (har-0015)'), 32, 'XML[42]') + checked(ctx_extract(R['har-0014'].text, 'el="', '"', 'XML[74] (har-0015)'), 17, 'XML[74]') + 'dummy' + checked(ctx_extract(html_control(R['har-0010'], 'XML', 0, 'XML[96] (har-0015)'), 'Page', 'k', 'XML[96] (har-0015)'), 27, 'XML[96]') + 'falsep1300000pageInitParamp1500001pagePixelHeight0p1400001pagePixelWidth0p1400004timeZoneOffset-180' + checked(ctx_extract(html_control(R['har-0010'], 'XML', 0, 'XML[222] (har-0015)'), '_tmp', '', 'XML[222] (har-0015)'), 11, 'XML[222]')),
        ('STAMP', html_control(R['har-0008'], 'STAMP', 0, 'STAMP (har-0015)'))
    ])
    return S.request('POST', url, headers=headers, data=data, timeout=30)


def step_6(S, R, P, base):
    # passo 6: fornece XML a har-0022 (ValueMatch)
    # passo 6: confiança possible
    # SESSIONID: montado no cliente: complete aqui (parte inicial extraída do produtor har-0001; o resto é o parâmetro sessionid_cliente, obrigatório)
    # XML: trecho 20..29 extraído em runtime (origem possível)
    # XML: trecho 42..74 extraído em runtime (origem possível)
    # XML: trecho 74..91 extraído em runtime (origem possível, ambíguo)
    # XML: trecho 96..123 extraído em runtime (origem possível)
    # XML: trecho 497..508 extraído em runtime (origem possível)
    # STAMP: extraído em runtime (origem forte)
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', base)
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/SIM1000X_JLIBS.html', base), 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'origin': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos', base), 'x-requested-with': 'XMLHttpRequest'}
    data = urllib.parse.urlencode([
        ('SESSIONID', ctx_extract(R['har-0001'].text, ' = "', '"', 'SESSIONID (har-0017)') + P['sessionid_cliente']),
        ('PAGEINITPARAM', ''),
        ('XML', 'v2232001705027000145' + checked(ctx_extract(R['har-0001'].text, ' = "', '"', 'XML[20] (har-0017)'), 9, 'XML[20]') + P['sessionid_cliente'] + checked(ctx_extract(R['har-0001'].text, 'sId = "', '"', 'XML[42] (har-0017)'), 32, 'XML[42]') + checked(ctx_extract(R['har-0014'].text, 'el="', '"', 'XML[74] (har-0017)'), 17, 'XML[74]') + 'dummy' + checked(ctx_extract(html_control(R['har-0010'], 'XML', 0, 'XML[96] (har-0017)'), 'Page', 'k', 'XML[96] (har-0017)'), 27, 'XML[96]') + 'on_interceptorfalsep2100005interceptor_is_activefalsep4500000interceptor_params.items[0].interceptor_valuep4500003interceptor_params.items[1].interceptor_valueS37p4500000interceptor_params.items[2].interceptor_valuep4500000interceptor_params.items[3].interceptor_valuep4500000interceptor_params.items[4].interceptor_valuep4500000interceptor_params.items[5].interceptor_value' + checked(ctx_extract(html_control(R['har-0015'], 'XML', 0, 'XML[497] (har-0017)'), '_tmp', '', 'XML[497] (har-0017)'), 11, 'XML[497]')),
        ('ERRORMESSAGE', ''),
        ('STAMP', html_control(R['har-0015'], 'STAMP', 0, 'STAMP (har-0017)'))
    ])
    return S.request('POST', url, headers=headers, data=data, timeout=30)


def step_7(S, R, P, base):
    # passo 7: fornece XML a har-0026 (ValueMatch); fornece XML a har-0024 (ValueMatch); fornece XML a har-0022 (ValueMatch); fornece STAMP a har-0022 (SameField)
    # passo 7: confiança strong
    # page: sem origem observada; parâmetro obrigatório, sem padrão
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/cscform.html', base) + '?' + urllib.parse.urlencode([('page', P['page_3'])])
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/VES0009X.html', base)}
    return S.request('GET', url, headers=headers, timeout=30)


def step_8(S, R, P, base):
    # passo 8: fornece XML a har-0026 (ValueMatch); fornece XML a har-0024 (ValueMatch); fornece STAMP a har-0024 (SameField)
    # passo 8: confiança strong
    # SESSIONID: montado no cliente: complete aqui (parte inicial extraída do produtor har-0001; o resto é o parâmetro sessionid_cliente, obrigatório)
    # XML: trecho 20..29 extraído em runtime (origem possível)
    # XML: trecho 42..74 extraído em runtime (origem possível)
    # XML: trecho 74..91 extraído em runtime (origem possível, ambíguo)
    # XML: trecho 96..123 extraído em runtime (origem possível)
    # XML: trecho 222..233 extraído em runtime (origem possível)
    # STAMP: extraído em runtime (origem forte)
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', base)
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/cscform.html?page=VES0009X', base), 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'origin': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos', base), 'x-requested-with': 'XMLHttpRequest'}
    data = urllib.parse.urlencode([
        ('SESSIONID', ctx_extract(R['har-0001'].text, ' = "', '"', 'SESSIONID (har-0022)') + P['sessionid_cliente']),
        ('PAGEINITPARAM', ''),
        ('XML', 'i2232001705027000005' + checked(ctx_extract(R['har-0001'].text, ' = "', '"', 'XML[20] (har-0022)'), 9, 'XML[20]') + P['sessionid_cliente'] + checked(ctx_extract(R['har-0001'].text, 'sId = "', '"', 'XML[42] (har-0022)'), 32, 'XML[42]') + checked(ctx_extract(R['har-0021'].text, 'el="', '"', 'XML[74] (har-0022)'), 17, 'XML[74]') + 'dummy' + checked(ctx_extract(html_control(R['har-0017'], 'XML', 0, 'XML[96] (har-0022)'), 'Page', 'k', 'XML[96] (har-0022)'), 27, 'XML[96]') + 'falsep1300000pageInitParamp1500001pagePixelHeight0p1400001pagePixelWidth0p1400004timeZoneOffset-180' + checked(ctx_extract(html_control(R['har-0017'], 'XML', 0, 'XML[222] (har-0022)'), '_tmp', '', 'XML[222] (har-0022)'), 11, 'XML[222]')),
        ('STAMP', html_control(R['har-0008'], 'STAMP', 0, 'STAMP (har-0022)'))
    ])
    return S.request('POST', url, headers=headers, data=data, timeout=30)


def step_9(S, R, P, base):
    # passo 9: fornece XML a har-0026 (ValueMatch); fornece STAMP a har-0026 (SameField)
    # passo 9: confiança strong
    # SESSIONID: montado no cliente: complete aqui (parte inicial extraída do produtor har-0001; o resto é o parâmetro sessionid_cliente, obrigatório)
    # XML: trecho 20..29 extraído em runtime (origem possível)
    # XML: trecho 42..74 extraído em runtime (origem possível)
    # XML: trecho 74..91 extraído em runtime (origem possível, ambíguo)
    # XML: trecho 96..123 extraído em runtime (origem possível)
    # XML: trecho 185..196 extraído em runtime (origem possível)
    # STAMP: extraído em runtime (origem forte)
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', base)
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/VES0009X_JLIBS.html', base), 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'origin': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos', base), 'x-requested-with': 'XMLHttpRequest'}
    data = urllib.parse.urlencode([
        ('SESSIONID', ctx_extract(R['har-0001'].text, ' = "', '"', 'SESSIONID (har-0024)') + P['sessionid_cliente']),
        ('PAGEINITPARAM', ''),
        ('XML', 'v2232001705027000105' + checked(ctx_extract(R['har-0001'].text, ' = "', '"', 'XML[20] (har-0024)'), 9, 'XML[20]') + P['sessionid_cliente'] + checked(ctx_extract(R['har-0001'].text, 'sId = "', '"', 'XML[42] (har-0024)'), 32, 'XML[42]') + checked(ctx_extract(R['har-0021'].text, 'el="', '"', 'XML[74] (har-0024)'), 17, 'XML[74]') + 'dummy' + checked(ctx_extract(html_control(R['har-0017'], 'XML', 0, 'XML[96] (har-0024)'), 'Page', 'k', 'XML[96] (har-0024)'), 27, 'XML[96]') + 'cmd_filtrofalsep1200003v_filtro_sel2.0p1300003#f12_selected2.0' + checked(ctx_extract(html_control(R['har-0022'], 'XML', 0, 'XML[185] (har-0024)'), '_tmp', '', 'XML[185] (har-0024)'), 11, 'XML[185]')),
        ('ERRORMESSAGE', ''),
        ('STAMP', html_control(R['har-0022'], 'STAMP', 0, 'STAMP (har-0024)'))
    ])
    return S.request('POST', url, headers=headers, data=data, timeout=30)


def step_10(S, R, P, base):
    # passo 10: requisição alvo
    # SESSIONID: montado no cliente: complete aqui (parte inicial extraída do produtor har-0001; o resto é o parâmetro sessionid_cliente, obrigatório)
    # XML: trecho 20..29 extraído em runtime (origem possível)
    # XML: trecho 42..74 extraído em runtime (origem possível)
    # XML: trecho 74..91 extraído em runtime (origem possível, ambíguo)
    # XML: trecho 96..123 extraído em runtime (origem possível)
    # XML: trecho 155..164 sem dígitos e origem só possível: tratado como constante do protocolo
    # XML: trecho 239..250 extraído em runtime (origem possível)
    # STAMP: extraído em runtime (origem forte)
    url = rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/servlet/Connector', base)
    headers = {'accept': '*/*', 'accept-language': 'pt-BR,pt;q=0.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'referer': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos/UIC-SERVICOS/VES0009X_JLIBS.html', base), 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'origin': rebase('https://wsdetran.pb.gov.br/detran-portal-servicos', base), 'x-requested-with': 'XMLHttpRequest'}
    data = urllib.parse.urlencode([
        ('SESSIONID', ctx_extract(R['har-0001'].text, ' = "', '"', 'SESSIONID (har-0026)') + P['sessionid_cliente']),
        ('PAGEINITPARAM', ''),
        ('XML', 'v2232001705027000195' + checked(ctx_extract(R['har-0001'].text, ' = "', '"', 'XML[20] (har-0026)'), 9, 'XML[20]') + P['sessionid_cliente'] + checked(ctx_extract(R['har-0001'].text, 'sId = "', '"', 'XML[42] (har-0026)'), 32, 'XML[42]') + checked(ctx_extract(R['har-0021'].text, 'el="', '"', 'XML[74] (har-0026)'), 17, 'XML[74]') + 'dummy' + checked(ctx_extract(html_control(R['har-0017'], 'XML', 0, 'XML[96] (har-0026)'), 'Page', 'k', 'XML[96] (har-0026)'), 27, 'XML[96]') + 'cmd_consultar_placafalsep1400000' + 'v_filtro_' + 'errorp0700007v_placa' + P['placa'] + 'p0500011v_cpf' + P['cpf'] + 'p1300003#f12_selected2.0' + checked(ctx_extract(html_control(R['har-0024'], 'XML', 0, 'XML[239] (har-0026)'), '_tmp', '', 'XML[239] (har-0026)'), 11, 'XML[239]')),
        ('ERRORMESSAGE', ''),
        ('STAMP', html_control(R['har-0024'], 'STAMP', 0, 'STAMP (har-0026)'))
    ])
    return S.request('POST', url, headers=headers, data=data, timeout=30)


STEPS = [step_1, step_2, step_3, step_4, step_5, step_6, step_7, step_8, step_9, step_10]


def main():
    parser = argparse.ArgumentParser(description='Script de priming (ScrapeLens)')
    parser.add_argument('--confirmar', action='store_true', help='executa os passos que alteram estado')
    parser.add_argument('--base-url', default=None, help='troca esquema/host/porta do alvo capturado (ex.: http://127.0.0.1:8791)')
    for name, default, note in PARAMS:
        parser.add_argument('--' + name.replace('_', '-'), dest='p_' + name, default=default,
                            required=False, help=(note + (' (obrigatório)' if default is None else ' (padrão: valor capturado)')).replace('%', '%%'))
    args = parser.parse_args()
    P = {name: getattr(args, 'p_' + name) for name, _, _ in PARAMS}
    base = args.base_url

    print('Plano de priming para %s (%d passos):' % (TARGET, len(PLAN)))
    for index, (rid, method, url, reason, idem) in enumerate(PLAN, 1):
        print('  %d. %s %s [%s]%s' % (index, method, rebase(url, base), rid, '' if idem else ' (altera estado)'))
        print('       %s' % reason)
    if HAS_STATE_CHANGE and not args.confirmar:
        print('Nada foi enviado: o plano tem passos que alteram estado. Use --confirmar para executar.')
        return 0
    missing = [name for name, default, _ in PARAMS if P[name] is None]
    if missing:
        fail('parâmetros obrigatórios ausentes: ' + ', '.join('--' + m.replace('_', '-') for m in missing))

    try:
        import requests
    except ImportError:
        fail('o pacote "requests" não está instalado (pip install requests)')
    S = requests.Session()
    R = {}
    for index, (step, (rid, method, url, _, _)) in enumerate(zip(STEPS, PLAN), 1):
        resp = step(S, R, P, base)
        R[rid] = resp
        print('  [%d/%d] %s %s -> HTTP %d' % (index, len(STEPS), method, rebase(url, base), resp.status_code))
        try:
            erro = html_control(resp, 'ERRORMESSAGE', 0, rid)
        except SystemExit:
            erro = ''
        if erro.strip():
            fail('a aplicação respondeu com ERRORMESSAGE no passo %d (%s): %s' % (index, rid, erro.strip()[:200]))
    print('Cadeia concluída; último HTTP %d.' % R[PLAN[-1][0]].status_code)
    return 0


if __name__ == '__main__':
    sys.exit(main())
