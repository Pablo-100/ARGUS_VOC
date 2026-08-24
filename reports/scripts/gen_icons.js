const fs = require('fs');
const path = require('path');

const BRANDS = '/usr/share/nodejs/@fortawesome/free-brands-svg-icons';
const SOLID = '/usr/share/nodejs/@fortawesome/free-solid-svg-icons';

const icons = {
  docker: { set: 'brands', name: 'faDocker' },
  python: { set: 'brands', name: 'faPython' },
  ubuntu: { set: 'brands', name: 'faUbuntu' },
  git: { set: 'brands', name: 'faGitAlt' },
  elasticsearch: { set: 'solid', name: 'faDatabase' },
  logstash: { set: 'solid', name: 'faServer' },
  kibana: { set: 'solid', name: 'faChartLine' },
  beats: { set: 'solid', name: 'faHeartbeat' },
  fleet: { set: 'solid', name: 'faNetworkWired' },
  rabbitmq: { set: 'solid', name: 'faExchangeAlt' },
  redis: { set: 'solid', name: 'faMemory' },
  celery: { set: 'solid', name: 'faClock' },
  nmap: { set: 'solid', name: 'faSearch' },
  misp: { set: 'solid', name: 'faShieldHalved' },
  glpi: { set: 'solid', name: 'faTicket' },
  fastapi: { set: 'solid', name: 'faRocket' },
  nvd: { set: 'solid', name: 'faBug' },
  epss: { set: 'solid', name: 'faMagnifyingGlassChart' },
  kev: { set: 'solid', name: 'faListCheck' },
  owasp: { set: 'solid', name: 'faUserShield' },
  alert: { set: 'solid', name: 'faBell' },
  lock: { set: 'solid', name: 'faLock' },
  terminal: { set: 'solid', name: 'faTerminal' },
  os: { set: 'solid', name: 'faEye' },
  scan: { set: 'solid', name: 'faCompass' },
};

function loadIcon(def) {
  const dir = def.set === 'brands' ? BRANDS : SOLID;
  const mod = require(path.join(dir, def.name));
  const d = mod.definition || mod;
  const w = d.icon[0];
  const h = d.icon[1];
  const paths = Array.isArray(d.icon[4]) ? d.icon[4] : [d.icon[4]];
  return { w, h, paths, name: d.iconName };
}

const out = path.resolve(__dirname, '..', 'icons');
fs.mkdirSync(out, { recursive: true });

for (const [key, def] of Object.entries(icons)) {
  const { w, h, paths } = loadIcon(def);
  const pathEls = paths.map((p) => `<path d="${p}" fill="%COLOR%"/>`).join('');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}">${pathEls}</svg>`;
  fs.writeFileSync(path.join(out, `${key}.svg`), svg);
  console.log(`wrote ${key}.svg (${w}x${h})`);
}
