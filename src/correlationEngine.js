// src/correlationEngine.js
// ─────────────────────────────────────────────────────────────────────────
// Real correlation scoring for OSINT findings — replaces the hardcoded
// matchPct values (80/55/50) in dashboard.jsx with an actual signal-based
// confidence score, and builds real node-to-node edges (not just a star
// graph from center → each node).
//
// Two signal types implemented here:
//   1. Identifier overlap  — same email / phone / username appears in
//      more than one finding
//   2. Text similarity     — how closely a finding's title/url text
//      matches the investigation target (Jaro-Winkler)
// ─────────────────────────────────────────────────────────────────────────


function normalize(str) {
  return String(str || "")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^\w\s@.+-]/g, "")
    .trim();
}

// Jaro-Winkler similarity, returns 0..1 (1 = identical).
// Chosen over plain Levenshtein because it's better suited for short
// strings like usernames/handles where prefix similarity matters more.
function jaroSimilarity(s1, s2) {
  if (s1 === s2) return 1;
  const len1 = s1.length, len2 = s2.length;
  if (!len1 || !len2) return 0;

  const matchDistance = Math.floor(Math.max(len1, len2) / 2) - 1;
  const s1Matches = new Array(len1).fill(false);
  const s2Matches = new Array(len2).fill(false);

  let matches = 0;
  for (let i = 0; i < len1; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(i + matchDistance + 1, len2);
    for (let j = start; j < end; j++) {
      if (s2Matches[j] || s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }
  if (!matches) return 0;

  let transpositions = 0, k = 0;
  for (let i = 0; i < len1; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }

  return (
    (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3
  );
}

function jaroWinklerSimilarity(a, b, prefixScale = 0.1) {
  const s1 = normalize(a), s2 = normalize(b);
  const jaro = jaroSimilarity(s1, s2);
  let prefixLen = 0;
  const maxPrefix = 4;
  for (let i = 0; i < Math.min(maxPrefix, s1.length, s2.length); i++) {
    if (s1[i] === s2[i]) prefixLen++;
    else break;
  }
  return jaro + prefixLen * prefixScale * (1 - jaro);
}

// ─── Identifier extraction ──────────────────────────────────────────────────

const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const PHONE_RE = /(?:\+?\d[\d\s().-]{7,}\d)/g;

function extractIdentifiers(finding) {
  const haystack = [
    finding.title, finding.description, finding.url, finding.snippet,
    finding.username, finding.handle,
  ].filter(Boolean).join(" ");

  const emails = (haystack.match(EMAIL_RE) || []).map((e) => e.toLowerCase());
  const phones = (haystack.match(PHONE_RE) || [])
    .map((p) => p.replace(/[\s().-]/g, ""))
    .filter((p) => p.replace(/\D/g, "").length >= 8);

  // Username-like token: prefer the profile URL's path segment (most
  // reliable), falling back to an @handle in text. The @handle regex uses a
  // negative lookbehind so it doesn't accidentally grab an email's domain
  // (e.g. "john@gmail.com" must NOT yield username "gmail.com").
  let username = null;
  if (finding.url) {
    try {
      const path = new URL(finding.url).pathname.replace(/\/+$/, "");
      const seg = path.split("/").filter(Boolean).pop();
      if (seg) username = seg.toLowerCase();
    } catch { /* not a valid URL, skip */ }
  }
  if (!username) {
    const handleMatch = haystack.match(/(?<![\w.])@([a-z0-9_]{2,30})\b/i);
    if (handleMatch) username = handleMatch[1].toLowerCase();
  }

  return { emails, phones, username };
}

// ─── Per-finding confidence score ──────────────────────────────────────────

// Weights — tune these as you validate against real cases.
const WEIGHTS = {
  exactUsernameMatch: 40,
  usernameSimilarity: 25, // scaled by similarity score (0..1)
  sharedIdentifier: 30,   // email or phone also seen in >=1 other finding
  titleMentionsTarget: 15,
  statusFound: 10,        // scraper explicitly confirmed vs. just "open_link"
};

/**
 * Compute a 0-100 confidence score for a single finding, given the
 * investigation target and the full list of sibling findings (needed to
 * detect shared identifiers across platforms).
 *
 * Returns { score, reasons } — reasons is a short audit trail you can
 * surface in the UI (e.g. on hover) so scores aren't a black box.
 */
export function computeMatchScore(finding, investigation, allFindings = []) {
  const target = normalize(investigation?.target);
  const reasons = [];
  let score = 0;

  const { emails, phones, username } = extractIdentifiers(finding);

  // 1. Username exact / fuzzy match against the investigation target
  if (username && target) {
    if (username === target) {
      score += WEIGHTS.exactUsernameMatch;
      reasons.push(`Exact username match: "${username}"`);
    } else {
      const sim = jaroWinklerSimilarity(username, target);
      if (sim >= 0.85) {
        score += WEIGHTS.usernameSimilarity * sim;
        reasons.push(`Username "${username}" is ${Math.round(sim * 100)}% similar to target`);
      }
    }
  }

  // 2. Shared identifiers across other findings in this investigation
  const others = allFindings.filter((f) => f !== finding);
  const sharesIdentifier = others.some((other) => {
    const o = extractIdentifiers(other);
    return (
      emails.some((e) => o.emails.includes(e)) ||
      phones.some((p) => o.phones.includes(p))
    );
  });
  if (sharesIdentifier) {
    score += WEIGHTS.sharedIdentifier;
    reasons.push("Shares an email/phone identifier with another finding");
  }

  // 3. Title/description text mentions the target directly
  const text = normalize(`${finding.title || ""} ${finding.description || ""}`);
  if (target && text.includes(target)) {
    score += WEIGHTS.titleMentionsTarget;
    reasons.push("Title/description mentions the target");
  }

  // 4. Scraper's own confirmation status
  if (finding.status === "found") {
    score += WEIGHTS.statusFound;
    reasons.push("Scraper marked this as a confirmed match");
  }

  return { score: Math.max(0, Math.min(100, Math.round(score))), reasons };
}

// ─── Node-to-node edges (real relationship graph, not just a star) ────────

/**
 * Build edges between findings that share an identifier or have high text
 * similarity — in addition to the existing center→node edges you already
 * have in dashboard.jsx. Each edge has a `strength` 0-100 you can map to
 * line thickness/opacity.
 */
export function buildCorrelationEdges(findings) {
  const edges = [];
  for (let i = 0; i < findings.length; i++) {
    for (let j = i + 1; j < findings.length; j++) {
      const a = extractIdentifiers(findings[i]);
      const b = extractIdentifiers(findings[j]);

      const sharedEmail = a.emails.find((e) => b.emails.includes(e));
      const sharedPhone = a.phones.find((p) => b.phones.includes(p));
      const usernameSim =
        a.username && b.username ? jaroWinklerSimilarity(a.username, b.username) : 0;

      let strength = 0;
      const reasons = [];
      if (sharedEmail) { strength = Math.max(strength, 90); reasons.push(`shared email`); }
      if (sharedPhone) { strength = Math.max(strength, 90); reasons.push(`shared phone`); }
      if (usernameSim >= 0.85) {
        strength = Math.max(strength, Math.round(usernameSim * 100));
        reasons.push(`similar username`);
      }

      if (strength > 0) {
        edges.push({
          from: `f${i}`,
          to: `f${j}`,
          strength,
          reasons,
        });
      }
    }
  }
  return edges;
}

/**
 * Convenience wrapper: scores every finding in an investigation at once.
 * Use this instead of calling computeMatchScore in a .map() so every call
 * sees the full sibling list for identifier-overlap detection.
 */
export function scoreAllFindings(investigation) {
  const findings = investigation?.findings || [];
  return findings.map((f) => ({
    ...f,
    ...computeMatchScore(f, investigation, findings),
  }));
}
