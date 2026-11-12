// aiscan hub page script. No dependencies, no network calls.
// Two jobs: show times in the viewer's zone, and the chart tooltip.
(function () {
  "use strict";

  var pad = function (n) { return n < 10 ? "0" + n : "" + n; };
  document.querySelectorAll("time[data-local]").forEach(function (el) {
    var d = new Date(el.getAttribute("datetime"));
    if (isNaN(d.getTime())) { return; }
    el.title = el.textContent;
    el.textContent = d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
      " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
  });

  var tip = document.getElementById("tip");
  if (!tip) { return; }

  // Scan data is untrusted text: build the tooltip with textContent only.
  function fill(data) {
    while (tip.firstChild) { tip.removeChild(tip.firstChild); }
    var title = document.createElement("div");
    title.className = "tip-title";
    title.textContent = data.title;
    tip.appendChild(title);
    (data.rows || []).forEach(function (row) {
      var line = document.createElement("div");
      line.className = "tip-row sev-" + String(row[2]).replace(/[^a-z]/g, "");
      line.appendChild(document.createElement("i"));
      var name = document.createElement("span");
      name.textContent = row[0];
      var value = document.createElement("b");
      value.textContent = Number(row[1]).toLocaleString();
      line.appendChild(name);
      line.appendChild(value);
      tip.appendChild(line);
    });
    var total = document.createElement("div");
    total.className = "tip-row total";
    var label = document.createElement("span");
    label.textContent = "Open";
    var sum = document.createElement("b");
    sum.textContent = Number(data.total).toLocaleString();
    total.appendChild(label);
    total.appendChild(sum);
    tip.appendChild(total);
  }

  function place(x, y) {
    var box = tip.getBoundingClientRect();
    var left = x + 14;
    if (left + box.width > window.innerWidth - 8) { left = x - box.width - 14; }
    var top = Math.min(Math.max(y - box.height / 2, 8), window.innerHeight - box.height - 8);
    tip.style.left = Math.max(left, 8) + "px";
    tip.style.top = top + "px";
  }

  function show(el, x, y) {
    var data;
    try { data = JSON.parse(el.getAttribute("data-tip")); } catch (e) { return; }
    fill(data);
    tip.hidden = false;
    place(x, y);
  }

  function hide() { tip.hidden = true; }

  document.querySelectorAll(".chart .col[data-tip]").forEach(function (el) {
    el.addEventListener("pointermove", function (ev) { show(el, ev.clientX, ev.clientY); });
    el.addEventListener("pointerleave", hide);
    el.addEventListener("focus", function () {
      var box = el.getBoundingClientRect();
      show(el, box.right, box.top + box.height / 2);
    });
    el.addEventListener("blur", hide);
  });
})();
