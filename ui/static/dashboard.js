/* dashboard.js - SSE client + Chart.js real-time updates */

const COLORS = {
  ICMP_flood: "#1e90ff",
  SYN_flood: "#ff4757",
  UDP_flood: "#ffa502",
  HTTP_flood: "#a55eea",
  LAND_attack: "#00d4aa",
  SLOWLORIS: "#ff6b81",
  Unknown: "#4a5a6a",
  ip_banned: "#ff4757",
  port_blocked: "#ffa502",
  protocol_banned: "#a55eea",
};

function getColor(key) {
  return COLORS[key] || "#4a5a6a";
}

// ── Chart helpers ────────────────────────────────────────────

function makeChart(id, data, type = "doughnut") {
  const labels = Object.keys(data);
  const values = Object.values(data);

  const ctx = document.getElementById(id).getContext("2d");
  return new Chart(ctx, {
    type,
    data: {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: labels.map((l) => getColor(l) + "cc"),
          borderColor: labels.map((l) => getColor(l)),
          borderWidth: 1,
          hoverOffset: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#7a8a9a",
            font: { family: "JetBrains Mono", size: 11 },
            padding: 14,
            boxWidth: 12,
          },
        },
        tooltip: {
          backgroundColor: "#1a1f26",
          borderColor: "#2a3340",
          borderWidth: 1,
          titleColor: "#c8d3e0",
          bodyColor: "#7a8a9a",
          titleFont: { family: "Syne", size: 12, weight: "700" },
          bodyFont: { family: "JetBrains Mono", size: 11 },
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.parsed} events`,
          },
        },
      },
    },
  });
}

function updateChart(chart, newData) {
  const labels = Object.keys(newData);
  const values = Object.values(newData);
  chart.data.labels = labels;
  chart.data.datasets[0].data = values;
  chart.data.datasets[0].backgroundColor = labels.map(
    (l) => getColor(l) + "cc",
  );
  chart.data.datasets[0].borderColor = labels.map((l) => getColor(l));
  chart.update("none");
}

// ── Table update ─────────────────────────────────────────────

function buildRow(r, isNew = false) {
  const actionClass = r.action ? `tag-${r.action}` : "";
  const row = document.createElement("tr");
  if (isNew) row.classList.add("new-row");
  row.innerHTML = `
    <td class="mono">${r.timestamp}</td>
    <td><span class="tag tag-type">${r.attack_type}</span></td>
    <td class="mono">${r.protocole}</td>
    <td class="mono">${r.attacker}</td>
    <td class="mono">${r.victim}</td>
    <td class="mono">${r.port}</td>
    <td><span class="tag tag-action ${actionClass}">${r.action}</span></td>
    <td class="mono">${r.expiry}</td>
  `;
  return row;
}

function updateTable(recent) {
  const tbody = document.getElementById("events-body");
  if (!recent || recent.length === 0) return;

  // compare first row timestamp to detect new events
  const firstRow = tbody.querySelector("tr td");
  const firstTs = firstRow ? firstRow.textContent.trim() : null;
  const isNew = firstTs !== recent[0].timestamp;

  tbody.innerHTML = "";
  recent.forEach((r, i) => {
    tbody.appendChild(buildRow(r, isNew && i === 0));
  });
}

// ── Stat card updates ────────────────────────────────────────

function countTotal(typeMap) {
  return Object.values(typeMap).reduce((a, b) => a + b, 0);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function setStatus(live, text) {
  const dot = document.getElementById("status-dot");
  const span = document.getElementById("status-text");
  dot.className = "status-dot " + (live ? "live" : "err");
  span.textContent = text;
}

// ── SSE connection ───────────────────────────────────────────

let chartTypes = null;
let chartActions = null;
let eventSource = null;

function connect() {
  if (eventSource) eventSource.close();

  eventSource = new EventSource("/stream");

  eventSource.onopen = () => {
    setStatus(true, "Live");
  };

  eventSource.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.error) {
        setStatus(false, "Stream error");
        return;
      }

      // stat cards
      document.getElementById("total-attacks").textContent = countTotal(
        data.type_counts,
      ).toLocaleString();
      document.getElementById("dropped-count").textContent = (
        data.dropped_count || 0
      ).toLocaleString();
      document.getElementById("dropped-size").textContent = formatBytes(
        data.dropped_size || 0,
      );
      document.getElementById("active-bans").textContent = (
        data.active_bans || 0
      ).toString();
      document.getElementById("last-update").textContent =
        new Date().toLocaleTimeString();

      // charts
      if (chartTypes) updateChart(chartTypes, data.type_counts);
      if (chartActions) updateChart(chartActions, data.action_counts);

      // table
      updateTable(data.recent);

      setStatus(true, "Live");
    } catch (err) {
      console.error("SSE parse error:", err);
    }
  };

  eventSource.onerror = () => {
    setStatus(false, "Reconnecting...");
    eventSource.close();
    setTimeout(connect, 5000);
  };
}

// ── Init ─────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  // init charts from server-rendered data
  chartTypes = makeChart("chart-types", initialTypes || {});
  chartActions = makeChart("chart-actions", initialActions || {});

  // set initial total from page data
  const initialTotal = countTotal(initialTypes || {});
  document.getElementById("total-attacks").textContent =
    initialTotal.toLocaleString();

  // start SSE
  connect();
});

// clean up on page unload
window.addEventListener("beforeunload", () => {
  if (eventSource) eventSource.close();
});
