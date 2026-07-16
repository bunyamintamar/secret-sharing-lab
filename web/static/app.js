"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── Sekmeler ────────────────────────────────────────────────────────────────
$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    $$(".tab").forEach((t) => t.classList.remove("is-active"));
    $$(".panel").forEach((p) => p.classList.remove("is-active"));
    tab.classList.add("is-active");
    $(`.panel[data-panel="${tab.dataset.tab}"]`).classList.add("is-active");
  });
});

// ── Küçük yardımcılar ────────────────────────────────────────────────────────
function toast(msg) {
  let el = $(".toast");
  if (!el) {
    el = document.createElement("div");
    el.className = "toast";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove("show"), 1600);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Kopyalandı");
  } catch {
    // clipboard API yoksa geçici textarea ile
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    toast("Kopyalandı");
  }
}

async function api(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

// ── Canlı doğrulama (böl paneli) ─────────────────────────────────────────────
const secretEl = $("#secret");
const nEl = $("#n");
const kEl = $("#k");
const secretHint = $("#secret-hint");
const schemeHint = $("#scheme-hint");

function updateHints() {
  const bytes = new TextEncoder().encode(secretEl.value).length;
  secretHint.textContent = `${bytes} bayt (UTF-8)`;
  const n = parseInt(nEl.value, 10);
  const k = parseInt(kEl.value, 10);
  if (Number.isInteger(n) && Number.isInteger(k) && n >= 2 && k >= 2 && k <= n) {
    schemeHint.textContent = `${n} paydan herhangi ${k} tanesi sırrı geri getirir; ${k - 1} pay hiçbir şey söylemez.`;
    schemeHint.style.color = "";
  } else if (k > n) {
    schemeHint.textContent = "Eşik (k), pay sayısından (n) büyük olamaz.";
    schemeHint.style.color = "var(--err)";
  } else {
    schemeHint.textContent = "n ve k en az 2 olmalı.";
    schemeHint.style.color = "var(--err)";
  }
}
[secretEl, nEl, kEl].forEach((el) => el.addEventListener("input", updateHints));
updateHints();

// ── Böl ──────────────────────────────────────────────────────────────────────
let lastShares = [];

$("#do-split").addEventListener("click", async () => {
  const err = $("#split-error");
  const result = $("#split-result");
  err.hidden = true;
  const data = await api("/api/split", {
    secret: secretEl.value,
    n: parseInt(nEl.value, 10),
    k: parseInt(kEl.value, 10),
  }).catch(() => ({ ok: false, error: "Sunucuya ulaşılamadı." }));

  if (!data.ok) {
    err.textContent = data.error;
    err.hidden = false;
    result.hidden = true;
    return;
  }

  lastShares = data.shares;
  $("#split-summary").textContent =
    `${data.n} pay üretildi · eşik ${data.k} · set ${data.set_id}`;
  const ul = $("#shares");
  ul.innerHTML = "";
  data.shares.forEach((line, i) => {
    const li = document.createElement("li");
    li.className = "share";
    const idx = document.createElement("span");
    idx.className = "idx";
    idx.textContent = `Pay ${i + 1}`;
    const code = document.createElement("code");
    code.textContent = line;
    const copy = document.createElement("button");
    copy.className = "ghost copy";
    copy.textContent = "Kopyala";
    copy.addEventListener("click", () => copyText(line));
    li.append(idx, code, copy);
    ul.appendChild(li);
  });
  result.hidden = false;
});

$("#copy-all").addEventListener("click", () => copyText(lastShares.join("\n")));

$("#download-all").addEventListener("click", () => {
  const header = "# Shamir Secret Sharing payları\n" +
    "# Her satır bir pay. Birlestirme icin esik sayida pay gerekir.\n";
  const blob = new Blob([header + lastShares.join("\n") + "\n"], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "shamir-paylar.txt";
  a.click();
  URL.revokeObjectURL(a.href);
});

// ── Birleştir ─────────────────────────────────────────────────────────────────
const sharesIn = $("#shares-in");

$("#file-in").addEventListener("change", async (e) => {
  const files = [...e.target.files];
  const texts = await Promise.all(files.map((f) => f.text()));
  const lines = texts
    .join("\n")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  const existing = sharesIn.value.trim();
  sharesIn.value = (existing ? existing + "\n" : "") + lines.join("\n");
  e.target.value = "";
  toast(`${lines.length} pay eklendi`);
});

$("#do-combine").addEventListener("click", async () => {
  const err = $("#combine-error");
  const result = $("#combine-result");
  const warn = $("#combine-warn");
  err.hidden = true;
  const shares = sharesIn.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const data = await api("/api/combine", { shares }).catch(() => ({
    ok: false, error: "Sunucuya ulaşılamadı.",
  }));

  if (!data.ok) {
    err.textContent = data.error;
    err.hidden = false;
    result.hidden = true;
    return;
  }

  const out = $("#secret-out");
  if (data.is_text) {
    out.textContent = data.secret;
    out.style.color = "";
  } else {
    out.textContent = "Ham bayt (hex): " + data.secret;
  }
  if (data.warnings && data.warnings.length) {
    warn.textContent = data.warnings.join(" ");
    warn.hidden = false;
  } else {
    warn.hidden = true;
  }
  result.hidden = false;
});
