// Reproduzir imagens da proposta; não integra o frontend de produção.
import { chromium } from '../../../app/node_modules/playwright/index.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const out=path.resolve(here,'../after/recapture');
await fs.mkdir(out,{recursive:true});
const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1440,height:900},deviceScaleFactor:1,locale:'pt-BR',reducedMotion:'reduce'});
const views=[['01-entrada','?view=entry','.entry'],['02-sessao','?view=session','.preview'],['03-detalhe','?view=detail&id=18&tab=headers','.detail-tabs'],['04-comparacao','?view=compare','.diff-table']];
try{
  for(const [width,height] of [[1440,900],[1280,800]]){
    await page.setViewportSize({width,height});
    for(const [name,query,selector] of views){
      await page.goto('http://127.0.0.1:4174/'+query);
      await page.locator(selector).waitFor({state:'visible'});
      await page.evaluate(()=>document.fonts.ready);
      await page.screenshot({path:path.join(out,`${name}-${width}.png`),fullPage:false});
      const dims=await page.evaluate(()=>[innerWidth,innerHeight,document.documentElement.scrollWidth,document.documentElement.scrollHeight]);
      if(dims[2]>width||dims[3]>height)throw new Error(`Overflow ${name}: ${dims}`);
      process.stdout.write(`${name}-${width}: ${dims.join(' × ')}\n`);
    }
  }
}finally{await browser.close()}
