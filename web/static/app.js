// ANDS SOC Dashboard Real-Time Frontend Controller
document.addEventListener("DOMContentLoaded", () => {
    // State
    let modulesData = {};
    let activeModuleKey = null;
    let alertsData = [];
    let currentFilter = "ALL";
    let trafficChart = null;
    let protoChart = null;
    let eventSource = null;
    let activeModalAlert = null;

    // DOM Elements
    const toggleLiveBtn = document.getElementById("toggleLiveBtn");
    const liveBtnText = document.getElementById("liveBtnText");
    const ifaceSelect = document.getElementById("ifaceSelect");
    const topPps = document.getElementById("topPps");
    const topKbps = document.getElementById("topKbps");
    const topThreats = document.getElementById("topThreats");
    const topHosts = document.getElementById("topHosts");

    const kpiPps = document.getElementById("kpiPps");
    const kpiKbps = document.getElementById("kpiKbps");
    const kpiMedian = document.getElementById("kpiMedian");
    const kpiZscore = document.getElementById("kpiZscore");
    const kpiZstatus = document.getElementById("kpiZstatus");
    const kpiCritThreats = document.getElementById("kpiCritThreats");
    const kpiTotalThreats = document.getElementById("kpiTotalThreats");

    const alertList = document.getElementById("alertList");
    const alertSearch = document.getElementById("alertSearch");
    const clearAlertsBtn = document.getElementById("clearAlertsBtn");
    const inventoryBody = document.getElementById("inventoryBody");

    const moduleTree = document.getElementById("moduleTree");
    const moduleSearch = document.getElementById("moduleSearch");
    const selectedModTitle = document.getElementById("selectedModTitle");
    const modDoc = document.getElementById("modDoc");
    const modOptionsForm = document.getElementById("modOptionsForm");
    const executeModuleBtn = document.getElementById("executeModuleBtn");
    const terminalOutput = document.getElementById("terminalOutput");
    const clearTermBtn = document.getElementById("clearTermBtn");

    const whitelistTags = document.getElementById("whitelistTags");
    const bannedTags = document.getElementById("bannedTags");
    const newWhitelistIp = document.getElementById("newWhitelistIp");
    const addWhitelistBtn = document.getElementById("addWhitelistBtn");
    const newBanIp = document.getElementById("newBanIp");
    const manualBanBtn = document.getElementById("manualBanBtn");

    const alertModal = document.getElementById("alertModal");
    const closeModalBtn = document.getElementById("closeModalBtn");
    const modalAlertTitle = document.getElementById("modalAlertTitle");
    const modalAlertBody = document.getElementById("modalAlertBody");
    const modalBanBtn = document.getElementById("modalBanBtn");
    const modalWhitelistBtn = document.getElementById("modalWhitelistBtn");

    const genHtmlReportBtn = document.getElementById("genHtmlReportBtn");
    const genPdfReportBtn = document.getElementById("genPdfReportBtn");
    const reportStatusBox = document.getElementById("reportStatusBox");

    // TAB NAVIGATION
    document.querySelectorAll(".nav-tab").forEach(tabBtn => {
        tabBtn.addEventListener("click", () => {
            document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
            tabBtn.classList.add("active");
            const targetId = tabBtn.getAttribute("data-tab");
            document.getElementById(targetId).classList.add("active");
        });
    });

    // CHARTS INITIALIZATION (Black & White Minimalist Palette)
    function initCharts() {
        // Traffic Rate Chart
        const ctxTraffic = document.getElementById("trafficChart").getContext("2d");
        trafficChart = new Chart(ctxTraffic, {
            type: "line",
            data: {
                labels: Array(25).fill(""),
                datasets: [
                    {
                        label: "Packets / Sec (PPS)",
                        data: Array(25).fill(0),
                        borderColor: "#ffffff",
                        backgroundColor: "rgba(255, 255, 255, 0.08)",
                        borderWidth: 2,
                        tension: 0.2,
                        fill: true,
                        pointRadius: 2,
                        pointBackgroundColor: "#ffffff",
                    },
                    {
                        label: "Baseline Median (MAD)",
                        data: Array(25).fill(10),
                        borderColor: "#737373",
                        borderWidth: 1.5,
                        borderDash: [4, 4],
                        pointRadius: 0,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: "#a3a3a3", font: { size: 10, family: 'JetBrains Mono' } } }
                },
                scales: {
                    x: { grid: { color: "rgba(255,255,255,0.06)" }, ticks: { color: "#737373", font: { family: 'JetBrains Mono', size: 9 } } },
                    y: { grid: { color: "rgba(255,255,255,0.06)" }, ticks: { color: "#737373", font: { family: 'JetBrains Mono', size: 9 } }, min: 0 }
                }
            }
        });

        // Protocol Doughnut Chart (Monochrome Shading)
        const ctxProto = document.getElementById("protoChart").getContext("2d");
        protoChart = new Chart(ctxProto, {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS"],
                datasets: [{
                    data: [1, 1, 1, 1, 1, 1, 1],
                    backgroundColor: ["#ffffff", "#e5e5e5", "#d4d4d4", "#a3a3a3", "#737373", "#525252", "#262626"],
                    borderColor: "#000000",
                    borderWidth: 2,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "right", labels: { color: "#a3a3a3", font: { size: 9, family: 'JetBrains Mono' }, boxWidth: 10 } }
                },
                cutout: "68%"
            }
        });
    }

    // SERVER-SENT EVENTS (SSE) STREAM
    function startEventStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource("/api/stream");

        eventSource.addEventListener("telemetry", (e) => {
            const data = JSON.parse(e.data);
            updateDashboard(data);
        });

        eventSource.addEventListener("alert", (e) => {
            const alert = JSON.parse(e.data);
            if (alert.id) {
                alertsData.push(alert);
                renderAlerts();
            }
        });

        eventSource.addEventListener("clear_alerts", () => {
            alertsData = [];
            renderAlerts();
        });

        eventSource.onerror = () => {
            setTimeout(startEventStream, 3000);
        };
    }

    // UPDATE UI FROM TELEMETRY
    function updateDashboard(data) {
        const eng = data.engine || {};
        const isRunning = eng.running || false;

        // Toggle button state
        toggleLiveBtn.className = isRunning ? "cyber-btn btn-live-start running" : "cyber-btn btn-live-start";
        liveBtnText.textContent = isRunning ? "STOP LIVE SENTINEL" : "START LIVE SENTINEL";

        // Topbar
        topPps.textContent = eng.current_pps || "0.0";
        topKbps.textContent = `${eng.current_kbps || "0"} KB/s`;
        topThreats.textContent = data.threat_summary?.total_alerts || "0";
        topHosts.textContent = eng.hosts_discovered || "0";

        // KPIs
        kpiPps.innerHTML = `${eng.current_pps || "0.0"} <span class="unit">pkt/s</span>`;
        kpiKbps.textContent = `${eng.current_kbps || "0.0"} KB/s throughput`;
        kpiMedian.innerHTML = `${eng.baseline_median_pps || "10.0"} <span class="unit">pps</span>`;
        
        const crit = data.threat_summary?.critical || 0;
        const high = data.threat_summary?.high || 0;
        kpiCritThreats.textContent = `${crit} / ${high}`;
        kpiTotalThreats.textContent = `${data.threat_summary?.total_alerts || 0} Total Session Alerts`;

        // Update charts with traffic history
        if (data.traffic_points && data.traffic_points.length > 0 && trafficChart) {
            const pts = data.traffic_points;
            const labels = pts.map(p => p.timestamp);
            const ppsValues = pts.map(p => p.pps);
            const med = eng.baseline_median_pps || 10.0;
            const medValues = Array(pts.length).fill(med);

            trafficChart.data.labels = labels;
            trafficChart.data.datasets[0].data = ppsValues;
            trafficChart.data.datasets[1].data = medValues;
            trafficChart.update("none");

            const lastPoint = pts[pts.length - 1];
            kpiZscore.innerHTML = `${lastPoint.zscore.toFixed(2)} <span class="unit">Mod-Z</span>`;
            if (lastPoint.zscore >= 3.5) {
                kpiZstatus.textContent = "Status: VOLUMETRIC ANOMALY";
                kpiZstatus.style.color = "var(--accent-red)";
            } else {
                kpiZstatus.textContent = "Status: Normal Baseline";
                kpiZstatus.style.color = "var(--accent-emerald)";
            }
        }

        // Update Protocol Chart
        if (data.protocol_stats && protoChart) {
            const ps = data.protocol_stats;
            protoChart.data.datasets[0].data = [
                ps.TCP || 0, ps.UDP || 0, ps.ICMP || 0, ps.ARP || 0,
                ps.DNS || 0, ps.HTTP || 0, ps.TLS || 0
            ];
            protoChart.update("none");
        }

        // Render Whitelist & Banned Tags
        renderTags(whitelistTags, data.whitelist || [], "whitelist");
        renderTags(bannedTags, data.banned_ips || [], "banned");
    }

    // RENDER TAGS
    function renderTags(container, list, type) {
        if (!list || list.length === 0) {
            container.innerHTML = `<span style="font-size:12px;color:var(--text-muted);">None configured</span>`;
            return;
        }
        container.innerHTML = list.map(ip => `
            <div class="tag-pill">
                <span>${ip}</span>
                <span class="tag-remove" onclick="removeTag('${type}', '${ip}')">&times;</span>
            </div>
        `).join("");
    }

    window.removeTag = async (type, ip) => {
        if (type === "whitelist") {
            await fetch("/api/whitelist/action", { method: "POST", body: JSON.stringify({ action: "remove", ip }) });
        } else if (type === "banned") {
            await fetch("/api/firewall/action", { method: "POST", body: JSON.stringify({ action: "unblock", ip }) });
        }
    };

    // ALERTS RENDERING
    function renderAlerts() {
        const query = (alertSearch.value || "").toLowerCase();
        let filtered = alertsData.filter(a => {
            if (currentFilter !== "ALL" && a.severity !== currentFilter) return false;
            if (query) {
                const txt = `${a.type} ${a.source} ${a.destination} ${a.mitre_id} ${a.description}`.toLowerCase();
                return txt.includes(query);
            }
            return true;
        });

        if (filtered.length === 0) {
            alertList.innerHTML = `<div class="empty-state">No matching alerts recorded.</div>`;
            return;
        }

        alertList.innerHTML = filtered.slice(-50).reverse().map(a => {
            const sev = a.severity || "MEDIUM";
            const confPct = Math.round((a.confidence || 0.75) * 100);
            return `
                <div class="alert-card ${sev}" onclick="openAlertModal('${a.id}')">
                    <div class="alert-left">
                        <span class="sev-badge ${sev}">${sev}</span>
                        <div>
                            <div class="alert-main-title">${a.type.replace(/_/g, " ")}</div>
                            <div class="alert-desc">${a.description || ""}</div>
                        </div>
                    </div>
                    <div class="alert-meta">
                        <span class="mitre-badge">${a.mitre_id || "T1046"}</span>
                        <span><strong>${a.source || "N/A"}</strong> &rarr; ${a.destination || "N/A"}</span>
                        <span>${confPct}% Conf</span>
                        <span>${(a.timestamp || "").split(" ")[1] || ""}</span>
                    </div>
                </div>
            `;
        }).join("");
    }

    // MODAL INSPECTION
    window.openAlertModal = (id) => {
        const alert = alertsData.find(a => a.id === id);
        if (!alert) return;
        activeModalAlert = alert;

        modalAlertTitle.textContent = `🚨 ${alert.type.replace(/_/g, " ")} [${alert.severity}]`;
        modalAlertBody.innerHTML = `
            <div style="margin-bottom: 12px;"><strong>Timestamp:</strong> ${alert.timestamp}</div>
            <div style="margin-bottom: 12px;"><strong>MITRE ATT&CK:</strong> <span class="mitre-badge">${alert.mitre_id || "T1046"}</span></div>
            <div style="margin-bottom: 12px;"><strong>Attacker Source:</strong> <code style="color:var(--accent-cyan);font-weight:700;">${alert.source}</code></div>
            <div style="margin-bottom: 12px;"><strong>Destination Target:</strong> <code>${alert.destination}</code></div>
            <div style="margin-bottom: 12px;"><strong>Confidence Rating:</strong> ${Math.round((alert.confidence || 0.75)*100)}%</div>
            <div style="margin-bottom: 12px;"><strong>Description:</strong> ${alert.description}</div>
            <div style="background:#0f172a;padding:12px;border-radius:6px;border:1px solid var(--border-color);margin-top:14px;">
                <div style="font-size:11px;font-weight:700;color:var(--text-muted);margin-bottom:6px;">RAW FORENSIC DETAILS</div>
                <pre style="font-family:var(--font-mono);font-size:11px;color:#38bdf8;white-space:pre-wrap;">${JSON.stringify(alert.details || {}, null, 2)}</pre>
            </div>
        `;
        alertModal.classList.add("open");
    };

    closeModalBtn.addEventListener("click", () => alertModal.classList.remove("open"));
    alertModal.addEventListener("click", (e) => {
        if (e.target === alertModal) alertModal.classList.remove("open");
    });

    modalBanBtn.addEventListener("click", async () => {
        if (!activeModalAlert || !activeModalAlert.source) return;
        const src = activeModalAlert.source;
        const res = await fetch("/api/firewall/action", { method: "POST", body: JSON.stringify({ action: "block", ip: src }) });
        const data = await res.json();
        alert(data.success ? `Successfully blocked ${src} via iptables DROP.` : `Action note: ${data.ip}`);
        alertModal.classList.remove("open");
    });

    modalWhitelistBtn.addEventListener("click", async () => {
        if (!activeModalAlert || !activeModalAlert.source) return;
        const src = activeModalAlert.source;
        await fetch("/api/whitelist/action", { method: "POST", body: JSON.stringify({ action: "add", ip: src }) });
        alertModal.classList.remove("open");
    });

    // FILTER BUTTONS
    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFilter = btn.getAttribute("data-filter");
            renderAlerts();
        });
    });

    alertSearch.addEventListener("input", renderAlerts);

    clearAlertsBtn.addEventListener("click", async () => {
        await fetch("/api/alerts/clear", { method: "POST" });
        alertsData = [];
        renderAlerts();
    });

    // LOAD INVENTORY
    async function loadInventory() {
        const res = await fetch("/api/inventory");
        const data = await res.json();
        const hosts = data.hosts || [];
        
        if (hosts.length === 0) {
            inventoryBody.innerHTML = `<tr><td colspan="8" class="text-center">No active hosts detected on subnet yet.</td></tr>`;
            return;
        }

        inventoryBody.innerHTML = hosts.map(h => `
            <tr>
                <td><strong>${h.ip}</strong></td>
                <td><code style="color:var(--text-secondary)">${h.mac || "N/A"}</code></td>
                <td>${h.vendor || "Standard Hardware"}</td>
                <td><span style="background:rgba(56,189,248,0.1);color:#38bdf8;padding:2px 6px;border-radius:4px;font-size:11px;">${h.os_hint || "Unknown"}</span></td>
                <td><code style="color:var(--accent-cyan)">${(h.ports || []).slice(0, 5).join(",") || "None"}</code></td>
                <td>${(h.protocols || []).join(", ") || "IP"}</td>
                <td><strong style="color:${h.alerts > 0 ? 'var(--accent-red)' : 'var(--accent-emerald)'}">${h.alerts}</strong></td>
                <td>
                    <button class="cyber-btn btn-small" onclick="quickBan('${h.ip}')">Ban IP</button>
                </td>
            </tr>
        `).join("");
    }

    window.quickBan = async (ip) => {
        await fetch("/api/firewall/action", { method: "POST", body: JSON.stringify({ action: "block", ip }) });
    };

    // LOAD MODULES
    async function loadModules() {
        const res = await fetch("/api/modules");
        const data = await res.json();
        modulesData = data.categories || {};
        renderModuleTree();
    }

    function renderModuleTree() {
        const query = (moduleSearch.value || "").toLowerCase();
        let html = "";

        for (const [cat, mods] of Object.entries(modulesData)) {
            const filteredMods = mods.filter(m => !query || m.path.toLowerCase().includes(query) || m.name.toLowerCase().includes(query));
            if (filteredMods.length > 0) {
                html += `<div class="cat-header">${cat.toUpperCase()} (${filteredMods.length})</div>`;
                filteredMods.forEach(m => {
                    const isAct = m.path === activeModuleKey ? "active" : "";
                    html += `<div class="mod-item ${isAct}" onclick="selectModule('${m.path}')">📁 ${m.name}</div>`;
                });
            }
        }
        moduleTree.innerHTML = html;
    }

    moduleSearch.addEventListener("input", renderModuleTree);

    window.selectModule = (path) => {
        activeModuleKey = path;
        renderModuleTree();

        let targetMod = null;
        for (const mods of Object.values(modulesData)) {
            const found = mods.find(m => m.path === path);
            if (found) { targetMod = found; break; }
        }

        if (!targetMod) return;

        selectedModTitle.textContent = `⚙️ ${targetMod.path}`;
        modDoc.textContent = targetMod.doc || "No documentation provided for this module.";

        // Render Options Form
        let formHtml = "";
        for (const [optName, optInfo] of Object.entries(targetMod.options || {})) {
            formHtml += `
                <div class="form-group">
                    <label class="form-label">${optName} ${optInfo.required ? '<span style="color:var(--accent-red)">*</span>' : ''}</label>
                    <input type="text" id="opt_${optName}" class="cyber-input" value="${optInfo.value || ''}" placeholder="${optInfo.desc || ''}">
                    <span class="form-desc">${optInfo.desc || ''}</span>
                </div>
            `;
        }
        modOptionsForm.innerHTML = formHtml;
    };

    // EXECUTE MODULE
    executeModuleBtn.addEventListener("click", async () => {
        if (!activeModuleKey) {
            alert("Please select a module first from the catalog on the left.");
            return
        }

        // Collect options
        const options = {};
        modOptionsForm.querySelectorAll("input").forEach(inp => {
            const key = inp.id.replace("opt_", "");
            options[key] = inp.value;
        });

        terminalOutput.textContent += `\n\nands (${activeModuleKey}) > run\n[*] Executing ${activeModuleKey}...\n`;
        executeModuleBtn.disabled = true;
        executeModuleBtn.textContent = "⏳ RUNNING...";

        try {
            const res = await fetch("/api/modules/run", {
                method: "POST",
                body: JSON.stringify({ module: activeModuleKey, options })
            });
            const data = await res.json();
            
            terminalOutput.textContent += data.output || "";
            if (data.error) {
                terminalOutput.textContent += `\n[-] Module Error: ${data.error}\n`;
            } else {
                terminalOutput.textContent += `\n[+] Completed in ${data.elapsed_seconds}s.\n`;
            }
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
        } catch (e) {
            terminalOutput.textContent += `\n[-] Network request failure: ${e}\n`;
        } finally {
            executeModuleBtn.disabled = false;
            executeModuleBtn.textContent = "▶ RUN MODULE";
        }
    });

    clearTermBtn.addEventListener("click", () => {
        terminalOutput.textContent = "ands > Terminal cleared.\n";
    });

    // SIMULATION PRESET BUTTONS
    document.querySelectorAll(".sim-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            const mod = btn.getAttribute("data-mod");
            const opts = JSON.parse(btn.getAttribute("data-opts") || "{}");
            
            // Switch to studio tab
            document.querySelector("[data-tab='studioTab']").click();
            window.selectModule(mod);

            // Populate opts
            for (const [k, v] of Object.entries(opts)) {
                const el = document.getElementById(`opt_${k}`);
                if (el) el.value = v;
            }

            executeModuleBtn.click();
        });
    });

    // TOGGLE LIVE ENGINE
    toggleLiveBtn.addEventListener("click", async () => {
        const isRunning = toggleLiveBtn.classList.contains("running");
        const action = isRunning ? "stop" : "start";
        const iface = ifaceSelect.value;

        await fetch("/api/live/toggle", {
            method: "POST",
            body: JSON.stringify({ action, interface: iface })
        });
    });

    // ADD WHITELIST / BANNED
    addWhitelistBtn.addEventListener("click", async () => {
        const ip = newWhitelistIp.value.trim();
        if (ip) {
            await fetch("/api/whitelist/action", { method: "POST", body: JSON.stringify({ action: "add", ip }) });
            newWhitelistIp.value = "";
        }
    });

    manualBanBtn.addEventListener("click", async () => {
        const ip = newBanIp.value.trim();
        if (ip) {
            await fetch("/api/firewall/action", { method: "POST", body: JSON.stringify({ action: "block", ip }) });
            newBanIp.value = "";
        }
    });

    // REPORTS GENERATION
    genHtmlReportBtn.addEventListener("click", async () => {
        reportStatusBox.innerHTML = `<span style="color:var(--accent-blue)">Generating HTML report...</span>`;
        const res = await fetch("/api/report/generate", { method: "POST", body: JSON.stringify({ format: "html" }) });
        const data = await res.json();
        reportStatusBox.innerHTML = `<span style="color:var(--accent-emerald)">✓ HTML Report Generated! <a href="/api/report/download/html" target="_blank" style="color:var(--accent-cyan);text-decoration:underline;">Download HTML Report</a></span>`;
    });

    genPdfReportBtn.addEventListener("click", async () => {
        reportStatusBox.innerHTML = `<span style="color:var(--accent-blue)">Generating PDF report...</span>`;
        const res = await fetch("/api/report/generate", { method: "POST", body: JSON.stringify({ format: "pdf" }) });
        const data = await res.json();
        reportStatusBox.innerHTML = `<span style="color:var(--accent-emerald)">✓ PDF Report Generated in reports/report.pdf</span>`;
    });

    document.querySelectorAll(".export-siem-btn").forEach(b => {
        b.addEventListener("click", async () => {
            const fmt = b.getAttribute("data-fmt");
            const siemStatusBox = document.getElementById("siemStatusBox");
            siemStatusBox.innerHTML = `<span style="color:var(--accent-blue)">Exporting SIEM ${fmt.toUpperCase()} feed...</span>`;
            await fetch("/api/modules/run", {
                method: "POST",
                body: JSON.stringify({ module: "report/json_export", options: { FORMAT: fmt } })
            });
            siemStatusBox.innerHTML = `<span style="color:var(--accent-emerald)">✓ Exported to reports/alerts_siem.${fmt === 'json' ? 'json' : (fmt === 'cef' ? 'cef' : 'jsonl')}</span>`;
        });
    });

    // INITIAL LOAD
    initCharts();
    loadModules();
    loadInventory();
    startEventStream();
    setInterval(loadInventory, 5000);
});
