// Graphiques d'usage : chaque <canvas class="chart" data-usage="URL"> reçoit une courbe.
// data-stack="bucket" : une série empilée par bucket (vue d'ensemble) ; sinon les trois
// grandeurs d'un bucket. Aucun script en ligne (CSP script-src 'self').
(function () {
  "use strict";
  var palette = ["#2563eb", "#16a34a", "#d97706", "#9333ea", "#dc2626", "#0891b2", "#4b5563"];

  function draw(canvas) {
    if (canvas.dataset.drawn || typeof Chart === "undefined") return;
    canvas.dataset.drawn = "1";
    fetch(canvas.dataset.usage, { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (rows) {
        if (!rows.length) {
          var p = document.createElement("p");
          p.className = "muted";
          p.textContent = "Pas encore de statistique.";
          canvas.replaceWith(p);
          return;
        }
        var days = [], seen = {};
        rows.forEach(function (r) { if (!seen[r.day]) { seen[r.day] = 1; days.push(r.day); } });
        var datasets;
        if (canvas.dataset.stack === "bucket") {
          var by = {};
          rows.forEach(function (r) { (by[r.bucket] = by[r.bucket] || {})[r.day] = r.padded_gb + r.deleted_gb; });
          datasets = Object.keys(by).sort().map(function (b, i) {
            return { label: b, data: days.map(function (d) { return by[b][d] || 0; }), fill: true,
              borderColor: palette[i % palette.length], backgroundColor: palette[i % palette.length] + "33", pointRadius: 0, tension: 0.2 };
          });
        } else {
          var pick = function (k) { return rows.map(function (r) { return r[k]; }); };
          datasets = [
            { label: "Facturé (Go)", data: pick("padded_gb"), borderColor: palette[0], backgroundColor: palette[0] + "22", fill: true, pointRadius: 0, tension: 0.2 },
            { label: "Données (Go)", data: pick("raw_gb"), borderColor: palette[1], pointRadius: 0, tension: 0.2 },
            { label: "Supprimé encore facturé (Go)", data: pick("deleted_gb"), borderColor: palette[2], pointRadius: 0, tension: 0.2 }
          ];
        }
        new Chart(canvas, {
          type: "line",
          data: { labels: days, datasets: datasets },
          options: {
            responsive: true, animation: false, interaction: { mode: "index", intersect: false },
            scales: { y: { stacked: canvas.dataset.stack === "bucket", beginAtZero: true, title: { display: true, text: "Go" } },
                      x: { ticks: { maxTicksLimit: 12 } } },
            plugins: { legend: { position: "bottom" } }
          }
        });
      })
      .catch(function () { canvas.replaceWith(document.createTextNode("Graphique indisponible.")); });
  }

  function scan(root) { (root || document).querySelectorAll("canvas.chart[data-usage]").forEach(draw); }
  document.addEventListener("DOMContentLoaded", function () { scan(); });
  document.addEventListener("htmx:load", function (e) { scan(e.target); });
})();
