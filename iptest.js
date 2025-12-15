const IPPURE_URL = "https://my.ippure.com/v1/info";
const CHECKPLACE = "https://ipinfo.check.place";

// 从环境参数获取节点名
const nodeName = $environment.params.node;

function httpGet(url) {
  return new Promise((resolve, reject) => {
    $httpClient.get({ url, node: nodeName }, (err, resp, data) => {
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

// severity: 0=低 1=中 2=较高 3=高 4=极高/建议封禁
function severityMeta(sev) {
  if (sev >= 4) return { icon: "xmark.octagon.fill", color: "#8E0000" };
  if (sev >= 3) return { icon: "exclamationmark.triangle.fill", color: "#FF3B30" };
  if (sev >= 2) return { icon: "exclamationmark.circle.fill", color: "#FF9500" };
  if (sev >= 1) return { icon: "exclamationmark.circle", color: "#FFCC00" };
  return { icon: "checkmark.seal.fill", color: "#34C759" };
}

function gradeIppure(score) {
  const s = toInt(score);
  if (s === null) return { sev: 2, text: "IPPure：获取失败" };
  if (s >= 80) return { sev: 4, text: `IPPure：🛑 极高风险 (${s})` };
  if (s >= 70) return { sev: 3, text: `IPPure：⚠️ 高风险 (${s})` };
  if (s >= 40) return { sev: 1, text: `IPPure：🔶 中等风险 (${s})` };
  return { sev: 0, text: `IPPure：✅ 低风险 (${s})` };
}

function gradeIPQS(score) {
  const s = toInt(score);
  if (s === null) return { sev: 2, text: "IPQS：获取失败" };
  if (s >= 90) return { sev: 4, text: `IPQS：🛑 高风险 (${s})` };
  if (s >= 85) return { sev: 3, text: `IPQS：⚠️ 存在风险 (${s})` };
  if (s >= 75) return { sev: 2, text: `IPQS：🔶 可疑 (${s})` };
  return { sev: 0, text: `IPQS：✅ 低风险 (${s})` };
}

function gradeScamalytics(score) {
  const s = toInt(score);
  if (s === null) return { sev: 2, text: "Scamalytics：获取失败" };
  if (s >= 90) return { sev: 4, text: `Scamalytics：🛑 极高风险 (${s})` };
  if (s >= 60) return { sev: 3, text: `Scamalytics：⚠️ 高风险 (${s})` };
  if (s >= 20) return { sev: 1, text: `Scamalytics：🔶 中风险 (${s})` };
  return { sev: 0, text: `Scamalytics：✅ 低风险 (${s})` };
}

function gradeIP2Location(score) {
  const s = toInt(score);
  if (s === null) return { sev: 2, text: "IP2Location：获取失败" };
  if (s >= 66) return { sev: 3, text: `IP2Location：⚠️ 高风险 (${s})` };
  if (s >= 33) return { sev: 1, text: `IP2Location：🔶 中风险 (${s})` };
  return { sev: 0, text: `IP2Location：✅ 低风险 (${s})` };
}

function gradeAbuseIPDB(score) {
  const s = toInt(score);
  if (s === null) return { sev: 2, text: "AbuseIPDB：获取失败" };
  if (s >= 75) return { sev: 4, text: `AbuseIPDB：🛑 建议封禁 (${s})` };
  if (s >= 25) return { sev: 3, text: `AbuseIPDB：⚠️ 高风险 (${s})` };
  return { sev: 0, text: `AbuseIPDB：✅ 低风险 (${s})` };
}

function gradeIpapi(abuserScoreText) {
  if (!abuserScoreText || typeof abuserScoreText !== "string") {
    return { sev: 2, text: "ipapi：获取失败" };
  }
  const m = abuserScoreText.match(/([0-9.]+)\s*\(([^)]+)\)/);
  if (!m) return { sev: 2, text: `ipapi：${abuserScoreText}` };

  const ratio = Number(m[1]);
  const level = String(m[2] || "").trim();
  const pct = Number.isFinite(ratio) ? `${Math.round(ratio * 10000) / 100}%` : "?";

  const sevByLevel = {
    "Very Low": 0,
    Low: 0,
    Elevated: 2,
    High: 3,
    "Very High": 4,
  };
  const sev = sevByLevel[level] ?? 2;

  const label =
    sev >= 4 ? "🛑 极高风险" :
    sev >= 3 ? "⚠️ 高风险" :
    sev >= 2 ? "🔶 较高风险" :
    "✅ 低风险";

  return { sev, text: `ipapi：${label} (${pct}, ${level})` };
}

function buildCheckPlaceUrl(ip, db) {
  const enc = encodeURIComponent(ip);
  const qs = db ? `?db=${encodeURIComponent(db)}` : "";
  return `${CHECKPLACE}/${enc}${qs}`;
}

async function fetchCheckPlaceDb(ip, db) {
  const { data } = await httpGet(buildCheckPlaceUrl(ip, db));
  const j = safeJsonParse(data);
  if (!j) throw new Error(`bad json: ${db}`);
  return j;
}

async function fetchDbipHtml(ip) {
  const { data } = await httpGet(`https://db-ip.com/${encodeURIComponent(ip)}`);
  return String(data);
}

function gradeDbip(html) {
  const riskTextMatch = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
  const riskText = (riskTextMatch ? riskTextMatch[1] : "").toLowerCase();
  if (!riskText) return { sev: 2, text: "DB-IP：获取失败" };

  if (riskText === "high") return { sev: 3, text: "DB-IP：⚠️ 高风险 (high)" };
  if (riskText === "medium") return { sev: 1, text: "DB-IP：🔶 中风险 (medium)" };
  if (riskText === "low") return { sev: 0, text: "DB-IP：✅ 低风险 (low)" };
  return { sev: 2, text: `DB-IP：${riskText}` };
}

// 仅用 IP2Location 判断是否机房
function ip2locationHostingText(ip2) {
  const usage = String(ip2?.usage_type || "").toUpperCase();
  const asUsage = String(ip2?.as_info?.as_usage_type || "").toUpperCase();
  const isDc = ip2?.proxy?.is_data_center === true || ip2?.proxy?.is_public_proxy === true;

  const isHosting =
    isDc ||
    usage.startsWith("DCH") ||
    asUsage.startsWith("DCH") ||
    usage.startsWith("CDN") ||
    asUsage.startsWith("CDN");

  if (!usage && !asUsage && !isDc) return "是否机房：未知（IP2Location 获取失败）";

  const detail = [
    usage ? `usage:${usage}` : "",
    asUsage ? `as:${asUsage}` : "",
    isDc ? "dc:true" : "",
  ].filter(Boolean).join(", ");

  return isHosting
    ? `是否机房：🏢 是（${detail}）`
    : `是否机房：✅ 否（${detail}）`;
}

function flagEmoji(code) {
  if (!code) return "";
  let c = String(code).toUpperCase();
  if (c === "TW") c = "CN";
  if (c.length !== 2) return "";
  return String.fromCodePoint(...c.split("").map((x) => 127397 + x.charCodeAt(0)));
}

(async () => {
  // 1) 先拿 ippure（基础信息 + IP）
  const { data } = await httpGet(IPPURE_URL);
  const base = safeJsonParse(data);
  if (!base) {
    $done({ title: "IP 纯净度", content: "解析失败", icon: "exclamationmark.triangle.fill" });
    return;
  }

  const ip = base.ip;
  const asnText = base.asn ? `AS${base.asn} ${base.asOrganization || ""}`.trim() : (base.asOrganization || "");
  const flag = flagEmoji(base.countryCode);

  // 2) 并发拉多个来源
  const tasks = {
    ip2location: fetchCheckPlaceDb(ip, "ip2location"),
    ipqs: fetchCheckPlaceDb(ip, "ipqualityscore"),
    scamalytics: fetchCheckPlaceDb(ip, "scamalytics"),
    abuseipdb: fetchCheckPlaceDb(ip, "abuseipdb"),
    ipapi: fetchCheckPlaceDb(ip, "ipapi"),
    ipdata: fetchCheckPlaceDb(ip, "ipdata"),
    dbipHtml: fetchDbipHtml(ip),
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

  // 3) 机房判断：只用 IP2Location
  const hostingLine = ip2locationHostingText(ok.ip2location);

  // 4) 各家标准分别打分
  const grades = [];

  grades.push(gradeIppure(base.fraudScore));

  const ipqsScore = ok.ipqs ? toInt(ok.ipqs.fraud_score) : null;
  grades.push(gradeIPQS(ipqsScore));

  const scamScore = ok.scamalytics
    ? toInt(ok.scamalytics?.scamalytics?.scamalytics_score ?? ok.scamalytics?.scamalytics_score)
    : null;
  grades.push(gradeScamalytics(scamScore));

  const ip2Score = ok.ip2location ? toInt(ok.ip2location.fraud_score) : null;
  grades.push(gradeIP2Location(ip2Score));

  const abuseScore = ok.abuseipdb ? toInt(ok.abuseipdb?.data?.abuseConfidenceScore) : null;
  grades.push(gradeAbuseIPDB(abuseScore));

  const ipapiText = ok.ipapi ? ok.ipapi?.company?.abuser_score : null;
  grades.push(gradeIpapi(ipapiText));

  if (ok.dbipHtml) grades.push(gradeDbip(ok.dbipHtml));

  // 5) 全局最危险等级决定标题色/图标
  const maxSev = grades.reduce((m, g) => Math.max(m, g.sev ?? 2), 0);
  const meta = severityMeta(maxSev);

  // 6) 输出
  const riskLines = grades.map((g) => g.text).join("\n");

  // 附加：风险因子小结
  const factorParts = [];
  if (ok.ipdata && ok.ipdata.threat) {
    const t = ok.ipdata.threat;
    const items = [];
    if (t.is_proxy === true) items.push("Proxy");
    if (t.is_tor === true) items.push("Tor");
    if (t.is_vpn === true) items.push("VPN");
    if (t.is_threat === true || t.is_known_abuser === true || t.is_known_attacker === true) items.push("Abuse");
    if (items.length) factorParts.push(`ipdata 因子：${items.join("/")}`);
  }
  if (ok.ipqs) {
    const items = [];
    if (ok.ipqs.proxy === true) items.push("Proxy");
    if (ok.ipqs.tor === true) items.push("Tor");
    if (ok.ipqs.vpn === true) items.push("VPN");
    if (ok.ipqs.recent_abuse === true) items.push("RecentAbuse");
    if (ok.ipqs.bot_status === true) items.push("Bot");
    if (items.length) factorParts.push(`IPQS 因子：${items.join("/")}`);
  }
  const factorText = factorParts.length ? `\n\n——风险因子——\n${factorParts.join("\n")}` : "";

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
