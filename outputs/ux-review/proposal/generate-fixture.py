import json
from pathlib import Path
out=Path(__file__).parent/'fixtures'
out.mkdir(exist_ok=True)
url='https://api.loja.invalid/api/v1/produtos/busca?colecao=outono-2026&canal=web&expand=precos,estoque,variantes'
payload={'busca':'waterproof jacket','pagina':1,'limite':24,'filtros':{'cor':['blue'],'disponivel':True}}
a=[[':method','POST'],[':scheme','https'],[':authority','api.loja.invalid'],[':path',url.split('invalid')[1]],['accept','application/json'],['accept','text/plain;q=0.8'],['accept-language','pt-BR,pt;q=0.9,en;q=0.8'],['user-agent','Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/156.0.0.0 Safari/537.36'],['content-type','application/json'],['cookie','session=demo_browser_a7f91c; locale=pt-BR'],['referer','https://loja.invalid/catalogo/outono?origem=colecao&campanha=casacos-impermeaveis-2026']]
b=[['host','api.loja.invalid'],['accept-language','pt-BR,pt;q=0.9,en;q=0.8'],['accept','application/json'],['user-agent','python-requests/2.32.5'],['content-type','application/json'],['cookie','locale=pt-BR'],['x-client','scraper-local']]
response=[[':status','200'],['content-type','application/json; charset=utf-8'],['cache-control','no-store'],['set-cookie','session=demo_browser_a7f91c; Path=/; Secure; HttpOnly; SameSite=Lax'],['set-cookie','experiment=outono_b; Path=/; Max-Age=3600; Secure; SameSite=Lax'],['alt-svc','h3=":443"; ma=86400']]
records=[]
for i in range(1,65):
    typ=['script','image','stylesheet','image','font','script'][i%6]
    host='cdn.loja.invalid'; path=f'/assets/{typ}/catalogo-outono-{i:02d}.v9c412.'+{'script':'js','image':'webp','stylesheet':'css','font':'woff2'}[typ]
    if i==1:typ='document';host='loja.invalid';path='/catalogo/outono'
    if i in (8,12,26,39,51,63):typ='fetch';host='api.loja.invalid';path=['/api/v1/filtros?colecao=outono','/api/v1/colecoes/outono','/api/v1/estoque?sku=JKT-8812','/api/v1/precos?sku=JKT-8812&moeda=BRL','/api/v1/sugestoes?q=jaqueta','/api/v1/frete?regiao=sul'][[8,12,26,39,51,63].index(i)]
    r={'id':i,'url':f'https://{host}{path}','method':'GET','type':typ,'protocol':'HTTP/3' if typ=='image' else 'HTTP/2','status':200,'duration':38+i*3,'size':f'{2+i*1.3:.1f} kB','source':'HAR','headers':[['accept','*/*']],'responseHeaders':[['content-type','application/json' if typ=='fetch' else 'application/octet-stream']],'payload':None,'response':{'ok':True} if typ=='fetch' else None,'evidence':'source'}
    if i in (18,64):
        scraper=i==64
        r.update(url=url,method='POST',type='fetch',protocol='HTTP/1.1' if scraper else 'HTTP/2',status=403 if scraper else 200,duration=87 if scraper else 214,size='0.1 kB' if scraper else '18.4 kB',source='HAR' if scraper else 'NetLog + CDP',headers=b if scraper else a,responseHeaders=[['content-type','application/json'],['cache-control','no-store']] if scraper else response,payload={**payload,'pagina':2} if scraper else payload,response={'erro':'session_required','mensagem':'Session cookie missing'} if scraper else {'total':148,'pagina':1,'produtos':[{'sku':'JKT-8812','nome':'Storm Blue Jacket','preco':349.90,'estoque':12}]},evidence='unverified' if scraper else 'source')
    records.append(r)
data={'name':'Catalog · autumn 2026','synthetic':True,'requests':records,'browserId':18,'scraperId':64}
(out/'session.json').write_text(json.dumps(data,ensure_ascii=False,indent=2))
entries=[]
for r in records:
    rh=[{'name':n,'value':v} for n,v in r['headers'] if not n.startswith(':')]
    sh=[{'name':n,'value':v} for n,v in r['responseHeaders'] if not n.startswith(':')]
    req={'method':r['method'],'url':r['url'],'httpVersion':r['protocol'],'headers':rh,'cookies':[],'queryString':[],'headersSize':-1,'bodySize':-1}
    if r['payload']:req['postData']={'mimeType':'application/json','text':json.dumps(r['payload'],ensure_ascii=False)}
    entries.append({'startedDateTime':f'2026-10-27T13:42:{(r["id"]-1)//2:02d}.000Z','time':r['duration'],'_resourceType':r['type'],'request':req,'response':{'status':r['status'],'statusText':'Forbidden' if r['status']==403 else 'OK','httpVersion':r['protocol'],'headers':sh,'cookies':[],'content':{'size':18400 if r['id']==18 else 100,'mimeType':'application/json' if r['type']=='fetch' else 'application/octet-stream','text':json.dumps(r['response'],ensure_ascii=False) if r['response'] else ''},'redirectURL':'','headersSize':-1,'bodySize':-1},'cache':{},'timings':{'send':1,'wait':r['duration']-3,'receive':2},'comment':'SYNTHETIC-FIXTURE UX review. No real traffic or credentials.'})
(out/'catalogo-sintetico.har').write_text(json.dumps({'log':{'version':'1.2','creator':{'name':'ScrapeLens UX synthetic-fixture','version':'1'},'comment':'synthetic-fixture — generated locally, never captured','entries':entries}},ensure_ascii=False,indent=2))
(out/'invalido.har').write_text('{"fixture":"synthetic-invalid-har"}')
print('64 synthetic records; generated proposal JSON and HAR 1.2')
