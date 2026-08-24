const fs = require('fs');
const path = require('path');
const puppeteer = require('/usr/local/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/puppeteer');

const CHROME = '/root/.cache/puppeteer/chrome/linux-151.0.7922.47/chrome-linux64/chrome';
const ICONS_DIR = path.resolve(__dirname, '..', 'icons');

const colors = {
  docker: '#2496ED',
  python: '#3776AB',
  ubuntu: '#E95420',
  git: '#F05032',
  elasticsearch: '#005EB8',
  logstash: '#005EB8',
  kibana: '#005EB8',
  beats: '#005EB8',
  fleet: '#005EB8',
  rabbitmq: '#FF6600',
  redis: '#DC382D',
  celery: '#37814A',
  nmap: '#1A1A1A',
  misp: '#C9342B',
  glpi: '#04427C',
  fastapi: '#009688',
  nvd: '#5B6B7B',
  epss: '#F5821F',
  kev: '#1E88E5',
  owasp: '#00A651',
  alert: '#F39C12',
  lock: '#34495E',
  terminal: '#34495E',
  os: '#34495E',
  scan: '#34495E',
};

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 640, height: 640, deviceScaleFactor: 2 });

  for (const file of fs.readdirSync(ICONS_DIR)) {
    if (!file.endsWith('.svg')) continue;
    const key = file.replace('.svg', '');
    let svg = fs.readFileSync(path.join(ICONS_DIR, file), 'utf8');
    svg = svg.replace(/%COLOR%/g, colors[key] || '#34495E');
    const data = 'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64');
    const html = `<body style="margin:0;background:transparent"><div id="box" style="width:256px;height:256px;display:flex;align-items:center;justify-content:center"><img src="${data}" style="width:88%;height:88%"/></div></body>`;
    await page.setContent(html);
    const el = await page.$('#box');
    const out = path.join(ICONS_DIR, `${key}.png`);
    await el.screenshot({ path: out, omitBackground: true });
    console.log('rendered', out);
  }

  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
