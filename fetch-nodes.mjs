#!/usr/bin/env node
/**
 * fetch-nodes.mjs —— 免费节点订阅聚合器（零第三方依赖，Node 18+）
 * 虾佬同款 + 家宽筛查版（fork: hmtxj/node-sub-zixf）
 *
 * 流程：读 sources.txt → 并发抓取 → 自动识别 base64/明文 → 清洗广告节点
 *      → 按 (协议+服务器+端口+凭据) 去重 → TCP 连通性检测 → 家宽 ASN 筛查
 *      → 输出订阅文件
 *
 * 产出：
 *   sub/v2ray.txt        明文节点列表
 *   sub/base64.txt       base64 订阅（v2rayN 导入这个）
 *   sub/clash.yaml       Clash / Mihomo 可直接导入的完整配置
 *   sub/jia-kuan.txt     实测为住宅 ISP 的节点链接（美国优先）
 *   sub/us-residential.txt  美国真住宅节点链接
 *   sub/us-only.txt      美国全部节点链接
 *   sub/stats.json       本次抓取统计（含家宽计数）
 *   sub/ip-cache.json    ASN 检查缓存（下次只查新 IP，省额度）
 *
 * 家宽筛查方法：域名先 DNS 解析成 IP，再用 ipinfo.io（无 key）查国家/ASN/org，
 * 失败时用 ip-api.com（免费接口，限速 45 次/分钟）兜底。按 org 判断住宅 ISP
 * （Comcast/Charter/Cox/AT&T/Free/Orange/Fastweb/KT/SK 等）vs 机房
 * （GTHost/Datacamp/OVH/DigitalOcean 等）。没有单一官方“人类指数”，不编分数，
 * 查不到的标 unknown。ASN 是住宅 ISP 但使用者是机房的，单列为 static-isp。
 *
 * 可选：同时设置 GIST_ID 与 GH_TOKEN 环境变量时，顺手把订阅同步到该 gist。
 * 环境变量开关：TCP_CHECK=0 关连通性检测；MIN_NODES=20 低于此数认为抓取异常；
 *   RESIDENTIAL_CHECK=0 关家宽筛查；RESIDENTIAL_BUDGET_MS 家宽筛查总预算（默认 600000ms）；
 *   IP_CHECK_MAX 只查前 N 个唯一 IP（0=不限，用于本地快速验证）。
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import path from 'node:path';
import dns from 'node:dns';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(HERE, 'sub');
const SOURCES_FILE = path.join(HERE, 'sources.txt');
const IP_CACHE_FILE = path.join(OUT_DIR, 'ip-cache.json');

const TCP_CHECK = process.env.TCP_CHECK !== '0';
const TCP_TIMEOUT_MS = Number(process.env.TCP_TIMEOUT_MS || 3000);
const TCP_CONCURRENCY = Number(process.env.TCP_CONCURRENCY || 128);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 20000);
const PER_HOSTPORT_MAX = Number(process.env.PER_HOSTPORT_MAX || 2);
const MIN_NODES = Number(process.env.MIN_NODES || 20);

const RESIDENTIAL_CHECK = process.env.RESIDENTIAL_CHECK !== '0';
const RES_CONCURRENCY = Number(process.env.RESIDENTIAL_CONCURRENCY || 16);
const RES_BUDGET_MS = Number(process.env.RESIDENTIAL_BUDGET_MS || 600000);
const IP_CHECK_MAX = Number(process.env.IP_CHECK_MAX || 0);

const UA = 'Mozilla/5.0 (compatible; node-sub-aggregator/1.0; +https://github.com)';
const SCHEME_RE = /^(vmess|vless|trojan|ss|ssr|hysteria2?|hy2|tuic):\/\//i;

// 广告 / 通知 / 到期提醒类假节点（这类 remark 的"节点"连不上，属于机场引流信息）
const JUNK_RE = new RegExp(
  [
    '剩余流量', '流量', '到期', '过期', '官网', '订阅', '购买', '续费', '机场', '邀请',
    '注册', '试用', '广告', '加群', '客服', '通知', '禁止', '贩卖', '跑路', '白嫖',
    '优惠', '折扣', '套餐', '付费', '重置', '过期时间', 'tg频道', 'telegram', 't\\.me',
  ].join('|'),
  'i',
);

// 住宅 ISP（家庭宽带运营商）org 关键字，按小写子串匹配
const RESIDENTIAL_KEYWORDS = [
  'comcast', 'charter', 'spectrum', 'cox communications', 'at&t', 'at&t enterprises',
  'verizon', 'frontier', 'centurylink', 'lumen technologies', 'windstream',
  'consolidated communications', 'mediacom', 'optimum', 'altice', 'suddenlink',
  'sparklight', 'hargray', 'rural telephone', 'rainbow', 'carson', 'access media',
  'horry', 't-mobile', 'tmobile', 'free sas', 'orange', 'fastweb', 'vodafone',
  'korea telecom', 'kt corporation', 'sk broadband', 'china mobile', 'china telecom',
  'china unicom', 'british telecom', 'virgin media', 'talktalk', 'sky broadband',
  'plusnet', 'hyperoptic', 'softbank', 'bell canada', 'rogers', 'shaw', 'telus',
  'videotron', 'cogeco', 'j:com', 'aussie broadband', 'telenor', 'telia', 'elis',
  'sprint', 'cricket wireless',
];

// 机房 / 云厂商 / 托管商 org 关键字（先于住宅判断，避免静态 ISP 被误判为家宽）
const HOSTING_KEYWORDS = [
  'gthost', 'datacamp', 'ovh', 'digitalocean', 'zenlayer', 'hostpapa', 'leaseweb',
  'vultr', 'linode', 'hetzner', 'oracle', 'amazon', 'aws', 'google cloud', 'microsoft',
  'azure', 'alibaba', 'tencent cloud', 'baidu', 'kamatera', 'contabo', 'netcrafters',
  'lvnet', 'delta ltd', 'nexuswave', 'madeala', 'egihosting', 'bunny', 'hurricane electric',
  'm247', 'serverius', 'hostroyale', 'ace data', 'b2 net', 'getechbrothers',
  'heart internet', 'hosting', 'datacenter', 'data center', 'vps', 'dedicated server',
  'cloudflare', 'cloudcone', 'interserver', 'ionos', 'scaleway', 'upcloud',
];

const stats = {
  updated: new Date().toISOString(),
  sources: [],
  raw: 0,
  junk: 0,
  badHost: 0,
  duplicate: 0,
  hostCap: 0,
  dead: 0,
  total: 0,
  byProtocol: {},
  jiaKuan: 0,
  usResidential: 0,
  usTotal: 0,
  staticIsp: 0,
  datacenter: 0,
  ipUnknown: 0,
  ipChecked: 0,
  ipCacheHits: 0,
  byCountry: {},
  clashProxies: 0,
  clashSkipped: 0,
};

// ---------- 工具 ----------

function b64decode(input) {
  const t = String(input).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  if (!t) return '';
  const pad = t + '='.repeat((4 - (t.length % 4)) % 4);
  return Buffer.from(pad, 'base64').toString('utf8');
}

function tryB64(input) {
  const t = String(input || '').trim();
  if (!/^[A-Za-z0-9+/=_-]+$/.test(t) || t.length < 4) return '';
  try {
    const d = b64decode(t);
    if (!d || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(d)) return '';
    return d;
  } catch { return ''; }
}

/** 内容看起来是 base64 订阅就解码，否则原样返回 */
function maybeDecode(text) {
  const trimmed = text.trim();
  if (SCHEME_RE.test(trimmed)) return trimmed;
  if (/:\/\//.test(trimmed.slice(0, 300))) return trimmed; // 已经是明文列表
  if (!/^[A-Za-z0-9+/=_\s-]+$/.test(trimmed.slice(0, 2000))) return trimmed;
  const decoded = b64decode(trimmed);
  return decoded.includes('://') ? decoded : trimmed;
}

function remarkOf(uri, hash) {
  const raw = hash ? decodeURIComponent(hash.slice(1)) : '';
  return raw.trim();
}

function badHost(host) {
  if (!host) return false;
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (['localhost', 'example.com', '0.0.0.0', '::1', '1.1.1.1', '8.8.8.8', '::'].includes(h)) return true;
  if (/^(127|10)\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (/^169\.254\./.test(h)) return true;
  if (/^0\./.test(h)) return true;
  if (/\.(local|localhost|internal|test|invalid|example)$/i.test(h)) return true;
  return false;
}

/** 解析出 {key, host, port, remark}，解析失败则 key 用整条 uri */
function parseNode(uri) {
  const scheme = (uri.split('://')[0] || '').toLowerCase();
  const noHash = uri.split('#')[0];
  const result = { protocol: scheme, host: '', port: 0, remark: '', key: noHash };

  try {
    if (scheme === 'vmess') {
      const obj = JSON.parse(b64decode(uri.slice('vmess://'.length)));
      result.host = String(obj.add || '').trim();
      result.port = Number(obj.port) || 0;
      result.remark = String(obj.ps || '').trim();
      result.key = `vmess|${result.host}|${result.port}|${obj.id || ''}`;
      return result;
    }
    if (scheme === 'ssr') {
      const decoded = b64decode(uri.slice('ssr://'.length));
      const parts = decoded.split(':');
      result.host = parts[0] || '';
      result.port = Number(parts[1]) || 0;
      const q = decoded.split('/?')[1] || '';
      const m = /remarks=([^&]+)/.exec(q);
      if (m) result.remark = b64decode(m[1]);
      result.key = `ssr|${result.host}|${result.port}|${(parts.slice(2, 6).join(':') || '')}`;
      return result;
    }
    // vless / trojan / hysteria2 / hy2 / tuic / ss(SIP002)
    const url = new URL(uri);
    if (url.hostname) {
      result.host = url.hostname;
      result.port = Number(url.port || (url.protocol === 'https:' ? 443 : 0));
      result.remark = remarkOf(uri, url.hash);
      const id = url.searchParams.get('id') || url.searchParams.get('auth') || url.username || '';
      result.key = `${scheme}|${result.host}|${result.port}|${id}`;
      return result;
    }
  } catch {
    /* 继续走兜底 */
  }

  // 兜底：从字符串里抠 host:port
  const text = scheme === 'ss' || scheme === 'vmess' ? uri.replace(/^[a-z0-9]+:\/\//i, '') : uri;
  const m = /@?([A-Za-z0-9._-]+):(\d{2,5})/.exec(text);
  if (m) {
    result.host = m[1];
    result.port = Number(m[2]) || 0;
  }
  result.remark = remarkOf(uri, uri.includes('#') ? uri.slice(uri.indexOf('#')) : '');
  result.key = noHash;
  return result;
}

function fetchWithTimeout(url, ms) {
  return fetch(url, {
    headers: { 'User-Agent': UA, Accept: '*/*' },
    signal: AbortSignal.timeout(ms),
    redirect: 'follow',
  });
}

/** 直连失败时的镜像候选（GitHub Actions 在美国，基本用不到；本机在国内很有用） */
function mirrorUrls(url) {
  const list = [url];
  const m = /^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/.exec(url);
  if (m) {
    const [, owner, repo, branch, file] = m;
    const raw = `${owner}/${repo}/${branch}/${file}`;
    list.push(`https://raw.gitmirror.com/${raw}`);
    list.push(`https://ghproxy.net/https://raw.githubusercontent.com/${raw}`);
    list.push(`https://gh-proxy.com/https://raw.githubusercontent.com/${raw}`);
    list.push(`https://cdn.jsdelivr.net/gh/${owner}/${repo}@${branch}/${file}`);
  }
  return list;
}

function describeError(err) {
  return err?.cause?.code || err?.cause?.message || err?.message || String(err);
}

async function fetchSource(url, attempts = 3) {
  const candidates = mirrorUrls(url);
  const errors = [];
  for (const candidate of candidates) {
    for (let i = 1; i <= attempts; i++) {
      try {
        const res = await fetchWithTimeout(candidate, FETCH_TIMEOUT_MS);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        if (!text.trim()) throw new Error('空响应');
        return { text: maybeDecode(text), bytes: text.length, via: candidate };
      } catch (err) {
        const msg = describeError(err);
        errors.push(`${candidate === url ? '' : '[镜像] '}${candidate} → ${msg}`);
        if (i < attempts) await new Promise((r) => setTimeout(r, 800 * i));
      }
    }
  }
  throw new Error([...new Set(errors)].slice(0, 4).join(' ; '));
}

function tcpCheck(host, port) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch { /* ignore */ }
      resolve(ok);
    };
    const socket = net.connect({ host, port });
    socket.setTimeout(TCP_TIMEOUT_MS);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

async function filterAlive(nodes, concurrency) {
  const alive = [];
  let index = 0;
  const workers = Array.from({ length: Math.min(concurrency, nodes.length || 1) }, async () => {
    while (index < nodes.length) {
      const node = nodes[index++];
      if (!node.host || !node.port || node.port < 1 || node.port > 65535) {
        alive.push(node);
        continue;
      }
      if (await tcpCheck(node.host, node.port)) alive.push(node);
    }
  });
  await Promise.all(workers);
  return alive;
}

// ---------- URI → Clash proxy ----------

function cleanObj(o) {
  const out = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined || v === '' || v === null) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0) continue;
    out[k] = v;
  }
  return out;
}

function wsOpts(p, hostParam, pathParam) {
  if (!pathParam && !hostParam) return undefined;
  const headers = hostParam ? { Host: hostParam } : undefined;
  return cleanObj({ path: pathParam || undefined, headers });
}

function parseSS(uri) {
  // 返回 {method, password, plugin, pluginOpts}，解析失败返回 null
  try {
    const u = new URL(uri);
    const user = decodeURIComponent(u.username || '');
    const passPart = decodeURIComponent(u.password || '');
    let method = '';
    let password = '';
    const decUser = tryB64(user);
    if (decUser && decUser.includes(':')) {
      const i = decUser.indexOf(':');
      method = decUser.slice(0, i);
      password = decUser.slice(i + 1);
    } else if (user.includes(':')) {
      const i = user.indexOf(':');
      method = user.slice(0, i);
      password = user.slice(i + 1);
    } else {
      method = decUser || user;
      password = tryB64(passPart) || passPart;
    }
    if (!method) {
      // 整体 base64 形式：ss://base64(method:password@host:port)
      const body = uri.slice('ss://'.length).split('#')[0].split('?')[0];
      const dec = tryB64(body);
      if (dec && dec.includes('@')) {
        const [cred, hostport] = dec.split('@');
        const i = cred.indexOf(':');
        method = cred.slice(0, i);
        password = cred.slice(i + 1);
        const m = /:(\d+)$/.exec(hostport || '');
        if (m) return { method, password, port: Number(m[1]), plugin: u.searchParams.get('plugin') || undefined };
      }
      return null;
    }
    return { method, password, plugin: u.searchParams.get('plugin') || undefined };
  } catch { return null; }
}

/** 把一条节点链接转成 Clash proxy 对象；不支持的协议返回 null */
function toClash(node) {
  const uri = node.uri;
  const scheme = node.protocol;
  const name = node.remark || `${scheme}-${node.host}:${node.port}`;
  const base = { name, server: node.host, port: node.port };

  try {
    if (scheme === 'vless') {
      const u = new URL(uri);
      const p = u.searchParams;
      const security = (p.get('security') || '').toLowerCase();
      const network = (p.get('type') || 'tcp').toLowerCase();
      const obj = cleanObj({
        ...base, type: 'vless', uuid: decodeURIComponent(u.username || ''),
        alterId: 0, cipher: 'auto', udp: true,
        tls: security === 'tls' || security === 'reality',
        servername: p.get('sni') || p.get('servername') || undefined,
        'client-fingerprint': p.get('fp') || undefined,
        flow: p.get('flow') || undefined,
        network,
        'reality-opts': security === 'reality' && p.get('pbk')
          ? cleanObj({ 'public-key': p.get('pbk'), 'short-id': p.get('sid') || '' }) : undefined,
        'ws-opts': network === 'ws' ? wsOpts(0, p.get('host'), p.get('path')) : undefined,
        'grpc-opts': network === 'grpc' ? cleanObj({ 'grpc-service-name': p.get('serviceName') || undefined }) : undefined,
        'xhttp-opts': network === 'xhttp' ? cleanObj({ path: p.get('path') || undefined, host: p.get('host') || undefined, mode: p.get('mode') || undefined }) : undefined,
        alpn: p.get('alpn') ? p.get('alpn').split(',') : undefined,
      });
      if (!obj.uuid) return null;
      return obj;
    }
    if (scheme === 'vmess') {
      const o = JSON.parse(b64decode(uri.slice('vmess://'.length)));
      const net = String(o.net || 'tcp').toLowerCase();
      const tls = String(o.tls || '') === 'tls';
      return cleanObj({
        ...base, type: 'vmess', uuid: String(o.id || ''), alterId: Number(o.aid || 0),
        cipher: String(o.scy || 'auto'), udp: true, tls,
        servername: String(o.sni || o.host || '') || undefined,
        network: net,
        'ws-opts': net === 'ws' ? wsOpts(0, o.host, o.path) : undefined,
        'http-opts': net === 'http' ? cleanObj({ path: o.path ? [o.path] : undefined, headers: o.host ? { Host: [o.host] } : undefined }) : undefined,
        'grpc-opts': net === 'grpc' ? cleanObj({ 'grpc-service-name': o.path || undefined }) : undefined,
        'client-fingerprint': o.fp || undefined,
      });
    }
    if (scheme === 'ss') {
      const parsed = parseSS(uri);
      if (!parsed || !parsed.method) return null;
      const u = new URL(uri);
      const obj = cleanObj({
        ...base, type: 'ss', cipher: parsed.method, password: parsed.password, udp: true,
        plugin: parsed.plugin ? parsed.plugin.split(';')[0] : undefined,
        'plugin-opts': parsed.plugin && parsed.plugin.includes(';')
          ? Object.fromEntries(parsed.plugin.split(';').slice(1).map((kv) => { const [k, ...rest] = kv.split('='); return [k, rest.join('=')]; }))
          : undefined,
      });
      // 整体 base64 形式里端口可能在解码后才拿到
      if (parsed.port) obj.port = parsed.port;
      if (!obj.port) obj.port = node.port;
      return obj;
    }
    if (scheme === 'trojan') {
      const u = new URL(uri);
      const p = u.searchParams;
      const network = (p.get('type') || 'tcp').toLowerCase();
      return cleanObj({
        ...base, type: 'trojan', password: decodeURIComponent(u.username || ''), udp: true,
        sni: p.get('sni') || p.get('peer') || undefined,
        alpn: p.get('alpn') ? p.get('alpn').split(',') : undefined,
        fingerprint: p.get('fp') || undefined,
        network,
        'ws-opts': network === 'ws' ? wsOpts(0, p.get('host'), p.get('path')) : undefined,
        'grpc-opts': network === 'grpc' ? cleanObj({ 'grpc-service-name': p.get('serviceName') || undefined }) : undefined,
      });
    }
    if (scheme === 'hysteria2' || scheme === 'hy2') {
      const u = new URL(uri);
      const p = u.searchParams;
      return cleanObj({
        ...base, type: 'hysteria2',
        password: decodeURIComponent(u.username || '') || p.get('auth') || undefined,
        sni: p.get('sni') || undefined,
        obfs: p.get('obfs') || undefined,
        'obfs-password': p.get('obfs-password') || undefined,
        'skip-cert-verify': p.get('insecure') === '1' || undefined,
        alpn: p.get('alpn') ? p.get('alpn').split(',') : undefined,
        up: p.get('up') ? Number(p.get('up')) : undefined,
        down: p.get('down') ? Number(p.get('down')) : undefined,
      });
    }
    if (scheme === 'hysteria') {
      const u = new URL(uri);
      const p = u.searchParams;
      return cleanObj({
        ...base, type: 'hysteria',
        'auth-str': p.get('auth') || p.get('auth_str') || undefined,
        alpn: p.get('alpn') ? p.get('alpn').split(',') : undefined,
        protocol: 'udp',
        up: p.get('up') ? Number(p.get('up')) : undefined,
        down: p.get('down') ? Number(p.get('down')) : undefined,
        'skip-cert-verify': p.get('insecure') === '1' || undefined,
      });
    }
  } catch { return null; }
  return null; // ssr / tuic 等 Clash 不直接支持，留在 v2ray.txt 里
}

// ---------- 最小 YAML 输出（零依赖） ----------

function yamlScalar(v) {
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(String(v));
}

function yamlDump(value, indent) {
  const pad = ' '.repeat(indent);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return value.map((item) => {
      if (item && typeof item === 'object') {
        const inner = yamlDump(item, indent + 2).split('\n');
        return `${pad}- ${inner[0].trimStart()}\n${inner.slice(1).join('\n')}`;
      }
      return `${pad}- ${yamlScalar(item)}`;
    }).join('\n');
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).map(([k, v]) => {
      if (v && typeof v === 'object') {
        if (Array.isArray(v) && v.length === 0) return `${pad}${k}: []`;
        if (!Array.isArray(v) && Object.keys(v).length === 0) return `${pad}${k}: {}`;
        return `${pad}${k}:\n${yamlDump(v, indent + 2)}`;
      }
      return `${pad}${k}: ${yamlScalar(v)}`;
    }).join('\n');
  }
  return `${pad}${yamlScalar(value)}`;
}

function buildClashYaml(proxies) {
  const names = proxies.map((p) => p.name);
  const usNames = proxies.filter((p) => p._verdict === 'residential' && p._country === 'US').map((p) => p.name);
  const jkNames = proxies.filter((p) => p._verdict === 'residential').map((p) => p.name);
  const doc = {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'info',
    'external-controller': '127.0.0.1:9090',
    proxies,
    'proxy-groups': [
      { name: '🚀 节点选择', type: 'select', proxies: ['🇺🇸 美国住宅', '🏠 家宽', ...names.slice(0, 200)] },
      { name: '🇺🇸 美国住宅', type: 'select', proxies: usNames.length ? usNames : ['DIRECT'] },
      { name: '🏠 家宽', type: 'select', proxies: jkNames.length ? jkNames : ['DIRECT'] },
    ],
    rules: ['MATCH,🚀 节点选择'],
  };
  // 去掉内部标记字段后再输出
  const clean = JSON.parse(JSON.stringify(doc, (k, v) => (k.startsWith('_') ? undefined : v)));
  return '# Clash / Mihomo 配置 · 由 hmtxj/node-sub-zixf 每 6 小时自动生成\n'
    + '# 导入：Clash / Mihomo / Clash Verge / Stash → 配置文件 → 填 sub/clash.yaml 的 raw 链接\n'
    + yamlDump(clean, 0) + '\n';
}

// ---------- 家宽 ASN 筛查 ----------

function classifyIp(info) {
  const orgText = `${info.org || ''} ${info.asn || ''}`.toLowerCase();
  const ispText = `${info.isp || ''}`.toLowerCase();
  const hostingHit = HOSTING_KEYWORDS.some((k) => orgText.includes(k) || ispText.includes(k));
  const residentialHit = RESIDENTIAL_KEYWORDS.some((k) => orgText.includes(k));
  if (hostingHit && residentialHit) return 'static-isp'; // ASN 是住宅 ISP，使用者是机房
  if (hostingHit) return 'datacenter';
  if (residentialHit) return 'residential';
  return 'unknown';
}

let ipApiLastCall = 0;
async function checkIpApi(ip) {
  // ip-api.com 免费接口限速 45 次/分钟，这里按 1.4 秒间隔节流
  const wait = 1400 - (Date.now() - ipApiLastCall);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  ipApiLastCall = Date.now();
  try {
    const res = await fetchWithTimeout(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,isp,org,as,query`, 8000);
    if (!res.ok) return null;
    const j = await res.json();
    if (j.status !== 'success') return null;
    return { country: String(j.countryCode || '').toUpperCase(), org: String(j.as || j.org || ''), isp: String(j.isp || ''), asn: String(j.as || ''), source: 'ip-api' };
  } catch { return null; }
}

async function checkIpInfo(ip) {
  try {
    const res = await fetchWithTimeout(`https://ipinfo.io/${ip}/json`, 8000);
    if (!res.ok) return null;
    const j = await res.json();
    if (!j.country) return null;
    return { country: String(j.country).toUpperCase(), org: String(j.org || ''), isp: '', asn: String(j.org || ''), source: 'ipinfo' };
  } catch { return null; }
}

async function checkResidential(nodes) {
  const cache = {};
  if (existsSync(IP_CACHE_FILE)) {
    try { Object.assign(cache, JSON.parse(readFileSync(IP_CACHE_FILE, 'utf8'))); } catch { /* 缓存损坏就重建 */ }
  }
  const deadline = Date.now() + RES_BUDGET_MS;
  const hostToIp = new Map();
  const uniqueIps = [];
  const ipToNodes = new Map();
  for (const n of nodes) {
    if (!n.host) continue;
    let ip = net.isIP(n.host) ? n.host : hostToIp.get(n.host);
    if (!ip && !net.isIP(n.host)) {
      try { ip = (await dns.promises.lookup(n.host)).address; hostToIp.set(n.host, ip); }
      catch { ip = null; }
    }
    n.ip = ip || '';
    if (!ip) { n.verdict = 'unknown'; n.country = ''; continue; }
    if (!ipToNodes.has(ip)) { ipToNodes.set(ip, []); uniqueIps.push(ip); }
    ipToNodes.get(ip).push(n);
  }
  // 美国备注的 IP 优先查（IP_CHECK_MAX 限制时最有价值）
  uniqueIps.sort((a, b) => {
    const aUS = ipToNodes.get(a).some((n) => /美国|united states/i.test(n.remark || ''));
    const bUS = ipToNodes.get(b).some((n) => /美国|united states/i.test(n.remark || ''));
    return Number(bUS) - Number(aUS);
  });
  const toCheck = IP_CHECK_MAX > 0 ? uniqueIps.slice(0, IP_CHECK_MAX) : uniqueIps;
  let checked = 0;
  let cacheHits = 0;
  let index = 0;
  const workers = Array.from({ length: Math.min(RES_CONCURRENCY, toCheck.length || 1) }, async () => {
    while (index < toCheck.length) {
      if (Date.now() > deadline) break;
      const ip = toCheck[index++];
      let info = cache[ip];
      if (info) { cacheHits++; }
      else {
        info = (await checkIpInfo(ip)) || (await checkIpApi(ip));
        if (info) { info.checkedAt = new Date().toISOString(); cache[ip] = info; checked++; }
        else { info = { country: '', org: '', isp: '', asn: '', source: 'failed' }; }
      }
      const verdict = info.country ? classifyIp(info) : 'unknown';
      for (const n of ipToNodes.get(ip)) {
        n.verdict = verdict;
        n.country = info.country || '';
        n.org = info.org || '';
        n.asn = info.asn || '';
      }
    }
  });
  await Promise.all(workers);
  // 超出预算 / 超出 IP_CHECK_MAX 的标 unknown
  for (const ip of uniqueIps) {
    for (const n of ipToNodes.get(ip)) {
      if (!n.verdict) { n.verdict = 'unknown'; n.country = n.country || ''; }
    }
  }
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(IP_CACHE_FILE, JSON.stringify(cache, null, 2) + '\n', 'utf8');
  stats.ipChecked = checked;
  stats.ipCacheHits = cacheHits;
  console.log(`\n家宽筛查：唯一 IP ${uniqueIps.length} 个，本轮新查 ${checked} 个，缓存命中 ${cacheHits} 个`);
}

// ---------- 主流程 ----------

function readSources() {
  if (!existsSync(SOURCES_FILE)) throw new Error(`找不到 ${SOURCES_FILE}`);
  return readFileSync(SOURCES_FILE, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

async function main() {
  const sources = readSources();
  const seen = new Set();
  const perHostPort = new Map();
  const collected = [];

  for (const url of sources) {
    try {
      const { text, bytes, via } = await fetchSource(url);
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => SCHEME_RE.test(l));
      let kept = 0;
      for (const uri of lines) {
        stats.raw++;
        const node = parseNode(uri);
        node.uri = uri;
        if (node.remark && JUNK_RE.test(node.remark)) { stats.junk++; continue; }
        if (badHost(node.host)) { stats.badHost++; continue; }
        if (seen.has(node.key)) { stats.duplicate++; continue; }
        seen.add(node.key);
        const hp = `${node.host}:${node.port}`;
        const n = (perHostPort.get(hp) || 0) + 1;
        if (n > PER_HOSTPORT_MAX) { stats.hostCap++; continue; }
        perHostPort.set(hp, n);
        collected.push(node);
        kept++;
      }
      stats.sources.push({ url, ok: true, bytes, lines: lines.length, kept, via });
      console.log(`[ok]   ${kept.toString().padStart(5)} / ${lines.length.toString().padStart(5)}  ${url}${via === url ? '' : `  (via ${new URL(via).host})`}`);
    } catch (err) {
      stats.sources.push({ url, ok: false, error: String(err?.message || err) });
      console.log(`[FAIL] ${url}\n        ${err?.message || err}`);
    }
  }

  let nodes = collected;
  if (TCP_CHECK) {
    const before = nodes.length;
    nodes = await filterAlive(nodes, TCP_CONCURRENCY);
    stats.dead = before - nodes.length;
    console.log(`\nTCP 检测：${before} → ${nodes.length}（剔除 ${stats.dead}）`);
  }

  // 兜底：检测后太少就退回未检测的结果，避免把订阅清空
  if (nodes.length < MIN_NODES && collected.length >= MIN_NODES) {
    console.log(`存活数 ${nodes.length} 低于 ${MIN_NODES}，退回未检测结果 ${collected.length}`);
    stats.dead = 0;
    nodes = collected;
  }
  if (nodes.length < MIN_NODES) {
    throw new Error(`有效节点只有 ${nodes.length} 个，低于 ${MIN_NODES}，判定为抓取异常（保留上一版）`);
  }

  for (const node of nodes) {
    stats.byProtocol[node.protocol] = (stats.byProtocol[node.protocol] || 0) + 1;
  }
  stats.total = nodes.length;

  // ---- 家宽筛查（失败/超时不影响主订阅，只影响家宽分流） ----
  if (RESIDENTIAL_CHECK) {
    try { await checkResidential(nodes); }
    catch (err) { console.log(`[warn] 家宽筛查失败（主订阅不受影响）：${err?.message || err}`); }
  } else {
    for (const n of nodes) { n.verdict = 'unknown'; n.country = ''; }
  }
  const residential = nodes.filter((n) => n.verdict === 'residential');
  const usResidential = residential.filter((n) => n.country === 'US');
  const usOnly = nodes.filter((n) => n.country === 'US' || (n.country === '' && /美国|united states/i.test(n.remark || '')));
  stats.jiaKuan = residential.length;
  stats.usResidential = usResidential.length;
  stats.usTotal = usOnly.length;
  stats.staticIsp = nodes.filter((n) => n.verdict === 'static-isp').length;
  stats.datacenter = nodes.filter((n) => n.verdict === 'datacenter').length;
  stats.ipUnknown = nodes.filter((n) => n.verdict === 'unknown').length;
  for (const n of nodes) {
    if (n.country) stats.byCountry[n.country] = (stats.byCountry[n.country] || 0) + 1;
  }
  console.log(`家宽：${stats.jiaKuan} 条（其中美国 ${stats.usResidential} 条），美国全部 ${stats.usTotal} 条，静态 ISP ${stats.staticIsp} 条，机房 ${stats.datacenter} 条，未知 ${stats.ipUnknown} 条`);

  // ---- Clash YAML（美国住宅优先，其次其他家宽，其次其余；名字去重） ----
  const sorted = [...nodes].sort((a, b) => {
    const rank = (n) => (n.verdict === 'residential' && n.country === 'US' ? 0 : n.verdict === 'residential' ? 1 : n.verdict === 'static-isp' ? 2 : 3);
    return rank(a) - rank(b);
  });
  const nameSeen = new Map();
  const clashProxies = [];
  let skipped = 0;
  for (const n of sorted) {
    const p = toClash(n);
    if (!p) { skipped++; continue; }
    p._verdict = n.verdict || 'unknown';
    p._country = n.country || '';
    let name = p.name;
    if (nameSeen.has(name)) {
      const c = nameSeen.get(name) + 1;
      nameSeen.set(name, c);
      name = `${name} #${c}`;
      p.name = name;
    } else nameSeen.set(name, 1);
    clashProxies.push(p);
  }
  stats.clashProxies = clashProxies.length;
  stats.clashSkipped = skipped;

  // ---- 写出所有订阅文件 ----
  const lines = nodes.map((n) => n.uri);
  const plain = lines.join('\n') + '\n';
  const base64 = Buffer.from(plain, 'utf8').toString('base64');
  const jkSorted = [...residential].sort((a, b) => Number(b.country === 'US') - Number(a.country === 'US') || String(a.remark).localeCompare(String(b.remark)));

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(path.join(OUT_DIR, 'v2ray.txt'), plain, 'utf8');
  writeFileSync(path.join(OUT_DIR, 'base64.txt'), base64 + '\n', 'utf8');
  writeFileSync(path.join(OUT_DIR, 'clash.yaml'), buildClashYaml(clashProxies), 'utf8');
  writeFileSync(path.join(OUT_DIR, 'jia-kuan.txt'), (jkSorted.map((n) => n.uri).join('\n') + (jkSorted.length ? '\n' : '')), 'utf8');
  writeFileSync(path.join(OUT_DIR, 'us-residential.txt'), (usResidential.map((n) => n.uri).join('\n') + (usResidential.length ? '\n' : '')), 'utf8');
  writeFileSync(path.join(OUT_DIR, 'us-only.txt'), (usOnly.map((n) => n.uri).join('\n') + (usOnly.length ? '\n' : '')), 'utf8');
  writeFileSync(path.join(OUT_DIR, 'stats.json'), JSON.stringify(stats, null, 2) + '\n', 'utf8');

  // 可选：同步到 gist（v2rayN 需要公开可读的订阅地址时用）
  const gistId = process.env.GIST_ID;
  const ghToken = process.env.GH_TOKEN;
  if (gistId && ghToken) {
    const file = process.env.GIST_FILE || 'v2ray-base64.txt';
    const res = await fetch(`https://api.github.com/gists/${gistId}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${ghToken}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'User-Agent': UA,
      },
      body: JSON.stringify({ files: { [file]: { content: base64 } } }),
    });
    if (!res.ok) {
      console.log(`[warn] gist 同步失败：HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
    } else {
      console.log(`[ok]   已同步到 gist ${gistId} (${file})`);
    }
  }

  console.log(`\n总计 ${stats.total} 个节点：`);
  for (const [k, v] of Object.entries(stats.byProtocol).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${k.padEnd(10)} ${v}`);
  }
  console.log(`Clash：${stats.clashProxies} 条（跳过 ${stats.clashSkipped} 条不支持的协议）`);
  console.log(`\n输出目录 ${OUT_DIR}`);
}

main().catch((err) => {
  console.error(`\n[ERROR] ${err?.message || err}`);
  process.exit(1);
});
