const $ = (id) => document.getElementById(id);

let lastResults = null;

function log(line) {
  const el = $("logs");
  el.textContent += line + "\n";
  el.scrollTop = el.scrollHeight;
}

function setProgress(stage, done, total) {
  const pct = total <= 0 ? 0 : Math.floor((done * 100) / total);
  if (stage === "A") {
    $("progA").value = pct;
    $("progAText").textContent = `${done}/${total} (${pct}%)`;
  } else {
    $("progB").value = pct;
    $("progBText").textContent = `${done}/${total} (${pct}%)`;
  }
}

function addValidRow({ ip, ms }) {
  const tr = document.createElement("tr");
  tr.innerHTML = `<td>${ip}</td><td>${ms.toFixed(2)}</td>`;
  $("validTable").appendChild(tr);
}

function readCidrsFromTextarea() {
  return $("cidrs")
    .value.split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

$("btnFetchFastly").onclick = async () => {
  try {
    log("Fetching Fastly CIDRs...");
    const cidrs = await window.api.fetchFastly();
    $("fastlyCount").textContent = `Fetched: ${cidrs.length}`;
    $("fastlyList").textContent = cidrs.join("\n");
    $("cidrs").value = cidrs.join("\n");
    log(`Fastly loaded (${cidrs.length})`);
  } catch (e) {
    log("Fastly fetch failed: " + (e?.message || e));
  }
};

$("btnOpenFile").onclick = async () => {
  const res = await window.api.openCidrFile();
  if (!res) return;
  $("cidrs").value = res.cidrs.join("\n");
  log(`Loaded CIDRs from file: ${res.filePath} (${res.cidrs.length})`);
};

$("btnStart").onclick = async () => {
  $("btnStart").disabled = true;
  $("btnSave").disabled = true;

  $("validTable").innerHTML = "";
  $("logs").textContent = "";
  $("stats").textContent = "";
  $("progA").value = 0;
  $("progB").value = 0;

  const config = {
    cidrs: readCidrsFromTextarea(),
    concurrency: Number($("concurrency").value),
    timeoutMs: Number($("timeoutMs").value),
    samplesPer24: Number($("samplesPer24").value),
    expandLimitPer24: Number($("expandLimitPer24").value),
    hostHeader: $("hostHeader").value.trim(),
    fallbackFile: "fastly-ip-cidr.txt"

  };

  log("Starting scan...");
  log("Config: " + JSON.stringify(config));

  try {
    const result = await window.api.startScan(config);
    lastResults = result;

    $("stats").textContent =
      `Hot /24 blocks: ${result.hotBlocks} / ${result.totalBlocks} | ` +
      `Valid IPs: ${result.validCount}`;

    $("btnSave").disabled = false;
    log("Scan finished.");
  } catch (e) {
    log("Scan failed: " + (e?.message || e));
  } finally {
    $("btnStart").disabled = false;
  }
};

$("btnSave").onclick = async () => {
  if (!lastResults) return;
  const res = await window.api.saveResults({
    txt: lastResults.txt,
    csv: lastResults.csv
  });
  if (!res) return;
  log(`Saved:\n- ${res.txtPath}\n- ${res.csvPath}`);
};

window.api.onStage((s) => {
  log(`== ${s.label} | total=${s.total}`);
});

window.api.onProgress((p) => {
  setProgress(p.stage, p.done, p.total);
});

window.api.onValid((v) => {
  addValidRow(v);
});

window.api.onLog((l) => log(l));
