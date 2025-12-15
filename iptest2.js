const IPPURE_URL = "https://my.ippure.com/v1/info";
// 强制 IPv4 的 API
const IPV4_API = "https://api4.ipify.org?format=json";

// 从环境参数获取节点名
const nodeName = $environment.params.node;

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    $httpClient.get({ url, node: nodeName, headers }, (err, resp, data) => {
      if (err) return reject(err);
      if (!data) return reject(new Error("empty response"));
      resolve({ resp, data });
    });
  });
}

function safeJsonParse(s) {
  try {
    return JSON.parse(s);
  } catch (_) {
    return null;
  }
}

function toInt(v) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n) : null;
}

// severity: 0=低 1=中 2=较高 3=高 4=极高
function severityMeta(sev) {
  if (sev >= 4) return { icon: "xmark.octagon.fill", color: "#8E0000" };
  if (sev >= 3) return { icon: "exclamationmark.triangle.fill", color: "#FF3B30" };
  if (sev >= 2) return { icon: "exclamationmark.circle.fill", color: "#FF9500" };
  if (sev >= 1) return { icon: "exclamationmark.circle", color: "#FFCC00" };
  return { icon: "checkmark.seal.fill", color: "#34C759" };
}

// ========== 各家评分函数 ==========

function gradeIppure(score) {
  const s = toInt(score);
  if (s === null) return { sev: 2, text: "IPPure：获取失败" };
  if (s >= 80) return { sev: 4, text: `IPPure：🛑 极高风险 (${s})` };
  if (s >= 70) return { sev: 3, text: `IPPure：⚠️ 高风险 (${s})` };
  if (s >= 40) return { sev: 1, text: `IPPure：🔶 中等风险 (${s})` };
  return { sev: 0, text: `IPPure：✅ 低风险 (${s})` };
}

// ipapi.is - 免费直接可用
function gradeIpapi(j) {
  if (!j || !j.company) return { sev: 2, text: "ipapi：获取失败" };
  
  const abuserScoreText = j.company.abuser_score;
  if (!abuserScoreText || typeof abuserScoreText !== "string") {
    return { sev: 2, text: "ipapi：无评分" };
  }
  const m = abuserScoreText.match(/([0-9.]+)\s*\(([^)]+)\)/);
  if (!m) return { sev: 2, text: `ipapi：${abuserScoreText}` };

  const ratio = Number(m[1]);
  const level = String(m[2] || "").trim();
  const pct = Number.isFinite(ratio) ? `${Math.round(ratio * 10000) / 100}%` : "?";

  const sevByLevel = { "Very Low": 0, Low: 0, Elevated: 2, High: 3, "Very High": 4 };
  const sev = sevByLevel[level] ?? 2;
  const label = sev >= 4 ? "🛑 极高风险" : sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "✅ 低风险";

  return { sev, text: `ipapi：${label} (${pct}, ${level})` };
}

// IP2Location - 抓 demo 页面解析 Usage Type 和 Fraud Score
function parseIp2location(html) {
  if (!html) return { usageType: null, fraudScore: null };
  
  // 解析 Usage Type（如 DCH, ISP, COM 等）
  const usageMatch = html.match(/Usage\s*Type[^<]*<[^>]*>([^<]+)</i) 
    || html.match(/"usage_type"\s*:\s*"([^"]+)"/i);
  const usageType = usageMatch ? usageMatch[1].trim() : null;
  
  // 解析 Fraud Score
  const fraudMatch = html.match(/Fraud\s*Score[^<]*<[^>]*>(\d+)/i)
    || html.match(/"fraud_score"\s*:\s*(\d+)/i);
  const fraudScore = fraudMatch ? toInt(fraudMatch[1]) : null;
  
  return { usageType, fraudScore };
}

function gradeIp2location(fraudScore) {
  const s = toInt(fraudScore);
  if (s === null) return { sev: 2, text: "IP2Location：获取失败" };
  // 来自 iptest.sh：<33 low, <66 medium, >=66 high
  if (s >= 66) return { sev: 3, text: `IP2Location：⚠️ 高风险 (${s})` };
  if (s >= 33) return { sev: 1, text: `IP2Location：🔶 中风险 (${s})` };
  return { sev: 0, text: `IP2Location：✅ 低风险 (${s})` };
}

// IP2Location 机房判断（只用这个来源）
function ip2locationHostingText(usageType) {
  if (!usageType) return "IP类型：未知（IP2Location 获取失败）";
  
  const usage = String(usageType).toUpperCase();
  
  // 各类型判断
  if (usage.startsWith("DCH") || usage === "WEB") {
    return `IP类型：🏢 数据中心/服务器 (${usage})`;
  }
  if (usage.startsWith("CDN")) {
    return `IP类型：🌐 CDN (${usage})`;
  }
  if (usage.startsWith("MOB")) {
    return `IP类型：📱 蜂窝移动网络 (${usage})`;
  }
  if (usage.startsWith("ISP")) {
    return `IP类型：🏠 家庭宽带 (${usage})`;
  }
  if (usage.startsWith("COM")) {
    return `IP类型：🏬 商业宽带 (${usage})`;
  }
  if (usage.startsWith("EDU")) {
    return `IP类型：🎓 教育网络 (${usage})`;
  }
  if (usage.startsWith("GOV")) {
    return `IP类型：🏛️ 政府网络 (${usage})`;
  }
  if (usage.startsWith("MIL")) {
    return `IP类型：🎖️ 军用网络 (${usage})`;
  }
  if (usage.startsWith("ORG")) {
    return `IP类型：🏢 组织机构 (${usage})`;
  }
  
  // 未知类型
  return `IP类型：❓ ${usage}`;
}

// DB-IP - 抓网页解析
function gradeDbip(html) {
  if (!html) return { sev: 2, text: "DB-IP：获取失败" };
  const riskTextMatch = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
  const riskText = (riskTextMatch ? riskTextMatch[1] : "").toLowerCase();
  if (!riskText) return { sev: 2, text: "DB-IP：获取失败" };

  if (riskText === "high") return { sev: 3, text: "DB-IP：⚠️ 高风险 (high)" };
  if (riskText === "medium") return { sev: 1, text: "DB-IP：🔶 中风险 (medium)" };
  if (riskText === "low") return { sev: 0, text: "DB-IP：✅ 低风险 (low)" };
  return { sev: 2, text: `DB-IP：${riskText}` };
}

// Scamalytics - 抓网页解析
function gradeScamalytics(html) {
  if (!html) return { sev: 2, text: "Scamalytics：获取失败" };
  // 页面上有 "Fraud Score: XX" 或 class="score" 里的数字
  const scoreMatch = html.match(/Fraud\s*Score[:\s]*(\d+)/i) 
    || html.match(/class="score"[^>]*>(\d+)/i)
    || html.match(/"score"\s*:\s*(\d+)/i);
  if (!scoreMatch) return { sev: 2, text: "Scamalytics：获取失败" };
  
  const s = toInt(scoreMatch[1]);
  if (s === null) return { sev: 2, text: "Scamalytics：获取失败" };
  if (s >= 90) return { sev: 4, text: `Scamalytics：🛑 极高风险 (${s})` };
  if (s >= 60) return { sev: 3, text: `Scamalytics：⚠️ 高风险 (${s})` };
  if (s >= 20) return { sev: 1, text: `Scamalytics：🔶 中风险 (${s})` };
  return { sev: 0, text: `Scamalytics：✅ 低风险 (${s})` };
}

// IPWhois - 免费 API
function gradeIpwhois(j) {
  if (!j || !j.security) return { sev: 2, text: "IPWhois：获取失败" };
  
  const sec = j.security;
  const items = [];
  if (sec.proxy === true) items.push("Proxy");
  if (sec.tor === true) items.push("Tor");
  if (sec.vpn === true) items.push("VPN");
  if (sec.hosting === true) items.push("Hosting");
  
  if (items.length === 0) {
    return { sev: 0, text: "IPWhois：✅ 低风险（无标记）" };
  }
  const sev = items.includes("Tor") ? 3 : items.length >= 2 ? 2 : 1;
  const label = sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "🔶 有标记";
  return { sev, text: `IPWhois：${label} (${items.join("/")})` };
}

function flagEmoji(code) {
  if (!code) return "";
  let c = String(code).toUpperCase();
  if (c === "TW") c = "CN";
  if (c.length !== 2) return "";
  return String.fromCodePoint(...c.split("").map((x) => 127397 + x.charCodeAt(0)));
}

// ========== 各家 API 请求（直接调用，不用聚合接口） ==========

async function fetchIpapi(ip) {
  // https://api.ipapi.is/?q=IP - 免费，无需 key
  const { data } = await httpGet(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`);
  return safeJsonParse(data);
}

async function fetchIp2locationHtml(ip) {
  // https://www.ip2location.com/demo/IP - 官方 demo 页面
  const { data } = await httpGet(`https://www.ip2location.com/demo/${encodeURIComponent(ip)}`);
  return String(data);
}

async function fetchDbipHtml(ip) {
  // https://db-ip.com/IP - 抓网页
  const { data } = await httpGet(`https://db-ip.com/${encodeURIComponent(ip)}`);
  return String(data);
}

async function fetchScamalyticsHtml(ip) {
  // https://scamalytics.com/ip/IP - 抓网页
  const { data } = await httpGet(`https://scamalytics.com/ip/${encodeURIComponent(ip)}`);
  return String(data);
}

async function fetchIpwhois(ip) {
  // https://ipwhois.io/widget?ip=IP - 免费
  const { data } = await httpGet(`https://ipwhois.io/widget?ip=${encodeURIComponent(ip)}&lang=en`, {
    "Referer": "https://ipwhois.io/",
    "Accept": "*/*",
  });
  return safeJsonParse(data);
}

// ========== 主逻辑 ==========

(async () => {
  // 1) 强制获取 IPv4 地址
  let ip = null;
  try {
    const { data: ipv4Data } = await httpGet(IPV4_API);
    const ipv4Json = safeJsonParse(ipv4Data);
    ip = ipv4Json?.ip || ipv4Data?.trim();
  } catch (_) {}

  // 2) 拿 ippure 基础信息（如果 IPv4 获取失败，用 ippure 的 IP 作为 fallback）
  const { data } = await httpGet(IPPURE_URL);
  const base = safeJsonParse(data);
  if (!base) {
    $done({ title: "IP 纯净度", content: "解析失败", icon: "exclamationmark.triangle.fill" });
    return;
  }

  // 如果 IPv4 API 失败，fallback 到 ippure 的 IP
  if (!ip) ip = base.ip;

  const asnText = base.asn ? `AS${base.asn} ${base.asOrganization || ""}`.trim() : (base.asOrganization || "");
  const flag = flagEmoji(base.countryCode);

  // 3) 并发请求各家免费 API（直接调用，不用聚合接口）
  const tasks = {
    ipapi: fetchIpapi(ip),
    ip2locHtml: fetchIp2locationHtml(ip),
    dbipHtml: fetchDbipHtml(ip),
    scamHtml: fetchScamalyticsHtml(ip),
    ipwhois: fetchIpwhois(ip),
  };

  const results = await Promise.allSettled(
    Object.keys(tasks).map((k) => tasks[k].then((v) => [k, v]))
  );

  const ok = {};
  for (const r of results) {
    if (r.status === "fulfilled") {
      const [k, v] = r.value;
      ok[k] = v;
    }
  }

  // 4) 解析 IP2Location（机房判断 + 评分）
  const ip2loc = parseIp2location(ok.ip2locHtml);
  const hostingLine = ip2locationHostingText(ip2loc.usageType);

  // 5) 各家评分
  const grades = [];
  grades.push(gradeIppure(base.fraudScore));
  grades.push(gradeIpapi(ok.ipapi));
  grades.push(gradeIp2location(ip2loc.fraudScore));
  grades.push(gradeScamalytics(ok.scamHtml));
  grades.push(gradeDbip(ok.dbipHtml));
  grades.push(gradeIpwhois(ok.ipwhois));

  // 6) 全局最危险等级
  const maxSev = grades.reduce((m, g) => Math.max(m, g.sev ?? 2), 0);
  const meta = severityMeta(maxSev);

  // 7) 风险因子
  const factorParts = [];
  if (ok.ipapi) {
    const items = [];
    if (ok.ipapi.is_proxy === true) items.push("Proxy");
    if (ok.ipapi.is_tor === true) items.push("Tor");
    if (ok.ipapi.is_vpn === true) items.push("VPN");
    if (ok.ipapi.is_datacenter === true) items.push("Datacenter");
    if (ok.ipapi.is_abuser === true) items.push("Abuser");
    if (ok.ipapi.is_crawler === true) items.push("Crawler");
    if (items.length) factorParts.push(`ipapi 因子：${items.join("/")}`);
  }
  if (ok.ipwhois && ok.ipwhois.security) {
    const sec = ok.ipwhois.security;
    const items = [];
    if (sec.proxy === true) items.push("Proxy");
    if (sec.tor === true) items.push("Tor");
    if (sec.vpn === true) items.push("VPN");
    if (sec.hosting === true) items.push("Hosting");
    if (items.length) factorParts.push(`IPWhois 因子：${items.join("/")}`);
  }
  const factorText = factorParts.length ? `\n\n——风险因子——\n${factorParts.join("\n")}` : "";

  // 8) 输出
  const riskLines = grades.map((g) => g.text).join("\n");

  $done({
    title: "节点 IP 风险汇总",
    content:
`IP：${ip}
ASN：${asnText || "-"}
位置：${flag} ${base.country || ""} ${base.city || ""}
${hostingLine}
节点：${nodeName || "-"}

——多源评分——
${riskLines}${factorText}`,
    icon: meta.icon,
    "title-color": meta.color,
  });
})().catch((e) => {
  $done({
    title: "IP 纯净度",
    content: `请求失败：${String(e && e.message ? e.message : e)}`,
    icon: "network.slash",
  });
});
