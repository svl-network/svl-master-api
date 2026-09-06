/**
 * Sunveil Secret Admin Control Center — Dashboard Client Logic
 */

// Security Hygiene: Purge any legacy unencrypted tokens from browser storage
try {
  localStorage.removeItem("svl_jwt_token");
  localStorage.removeItem("svl_realms_session_jwt");
  localStorage.removeItem("svl_admin_jwt");
  sessionStorage.removeItem("svl_admin_jwt");
} catch {}

let adminToken = "";
let globalServers = [];
let globalLicenses = [];
let globalAuditLogs = [];
let autoRefreshTimer = null;

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
  initAdminApp();
});

function initAdminApp() {
  const gateForm = document.getElementById("gate-form");
  if (gateForm) {
    gateForm.addEventListener("submit", handleAdminLogin);
  }

  const logoutBtn = document.getElementById("btn-admin-logout");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", handleAdminLogout);
  }

  const refreshBtn = document.getElementById("btn-refresh-all");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      loadAllAdminData(true);
    });
  }

  // Tab Switching
  const tabBtns = document.querySelectorAll(".admin-tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      const targetTab = btn.getAttribute("data-tab");
      document.querySelectorAll(".admin-tab-pane").forEach(pane => {
        pane.classList.add("hidden");
      });
      const activePane = document.getElementById(targetTab);
      if (activePane) activePane.classList.remove("hidden");
    });
  });

  // Filters
  const serverSearch = document.getElementById("filter-servers");
  if (serverSearch) {
    serverSearch.addEventListener("input", renderServersTable);
  }
  const serverStatusSelect = document.getElementById("filter-server-status");
  if (serverStatusSelect) {
    serverStatusSelect.addEventListener("change", renderServersTable);
  }

  const licenseSearch = document.getElementById("filter-licenses");
  if (licenseSearch) {
    licenseSearch.addEventListener("input", renderLicensesTable);
  }

  // Create License Modal
  const openLicBtn = document.getElementById("btn-open-create-license");
  const closeLicBtn = document.getElementById("btn-close-license-modal");
  const licModal = document.getElementById("modal-create-license");
  const licForm = document.getElementById("form-create-license");

  if (openLicBtn && licModal) {
    openLicBtn.addEventListener("click", () => licModal.classList.remove("hidden"));
  }
  if (closeLicBtn && licModal) {
    closeLicBtn.addEventListener("click", () => licModal.classList.add("hidden"));
  }
  if (licForm) {
    licForm.addEventListener("submit", handleCreateLicense);
  }

  // Inspect Modal
  const closeInspectBtn = document.getElementById("btn-close-inspect-modal");
  const inspectModal = document.getElementById("modal-inspect-server");
  if (closeInspectBtn && inspectModal) {
    closeInspectBtn.addEventListener("click", () => inspectModal.classList.add("hidden"));
  }

  // Probe existing HttpOnly cookie session
  verifyAndLaunchAdmin();
}

async function handleAdminLogin(e) {
  e.preventDefault();
  const secretInput = document.getElementById("input-admin-secret");
  const alertBox = document.getElementById("gate-alert");
  const submitBtn = document.getElementById("btn-gate-submit");

  const secret = secretInput ? secretInput.value.trim() : "";
  if (!secret) return;

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerText = "Authenticating...";
  }
  if (alertBox) alertBox.classList.add("hidden");

  try {
    const res = await fetch("/api/v1/admin/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ secretKey: secret })
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.message || "Invalid administrative secret.");
    }

    adminToken = data.token || "";
    showToast("Authenticated as Root Administrator.");

    showAdminView();
    loadAllAdminData();
  } catch (err) {
    if (alertBox) {
      alertBox.innerText = err.message || "Authentication error.";
      alertBox.className = "alert-box alert-error";
      alertBox.classList.remove("hidden");
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerText = "Authenticate & Unlock Console";
    }
  }
}

async function handleAdminLogout() {
  adminToken = "";
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);

  try {
    await fetch("/api/v1/admin/logout", {
      method: "POST",
      credentials: "include"
    });
  } catch {}

  document.getElementById("admin-main-view").classList.add("hidden");
  document.getElementById("admin-auth-gate").classList.remove("hidden");
  showToast("Administrative session closed.");
}

async function verifyAndLaunchAdmin() {
  try {
    const headers = {};
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const res = await fetch("/api/v1/admin/overview", {
      headers,
      credentials: "include"
    });

    if (!res.ok) {
      return;
    }

    showAdminView();
    loadAllAdminData();
  } catch {
    // Guest / unauthenticated state is fine on initial load
  }
}

function showAdminView() {
  document.getElementById("admin-auth-gate").classList.add("hidden");
  document.getElementById("admin-main-view").classList.remove("hidden");

  if (!autoRefreshTimer) {
    autoRefreshTimer = setInterval(() => {
      loadAllAdminData(false);
    }, 10000);
  }
}

async function loadAllAdminData(showNotice = false) {
  try {
    const headers = {};
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const [overviewRes, serversRes, licensesRes, auditRes] = await Promise.all([
      fetch("/api/v1/admin/overview", { headers, credentials: "include" }),
      fetch("/api/v1/admin/servers", { headers, credentials: "include" }),
      fetch("/api/v1/admin/licenses", { headers, credentials: "include" }),
      fetch("/api/v1/admin/audit-logs", { headers, credentials: "include" })
    ]);

    if (overviewRes.status === 401 || overviewRes.status === 403) {
      handleAdminLogout();
      return;
    }

    const overviewData = await overviewRes.json();
    const serversData = await serversRes.json();
    const licensesData = await licensesRes.json();
    const auditData = await auditRes.json();

    renderOverview(overviewData.stats);

    globalServers = serversData.servers || [];
    renderServersTable();

    globalLicenses = licensesData.licenses || [];
    renderLicensesTable();

    globalAuditLogs = auditData.logs || [];
    renderAuditTable();

    if (showNotice) showToast("Admin data refreshed.");
  } catch (err) {
    console.error("Failed to load admin data:", err);
  }
}

function renderOverview(stats) {
  if (!stats) return;
  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.innerText = val;
  };

  setVal("kpi-total-servers", stats.totalServers || 0);
  setVal("kpi-online-servers", stats.onlineServers || 0);
  setVal("kpi-online-players", stats.onlinePlayers || 0);
  setVal("kpi-banned-servers", stats.bannedServers || 0);
  setVal("kpi-total-licenses", stats.totalLicenses || 0);
  setVal("kpi-memory", `${stats.memoryUsageMB || 0} MB`);
}

function renderServersTable() {
  const tbody = document.getElementById("servers-table-body");
  if (!tbody) return;

  const searchInput = document.getElementById("filter-servers");
  const query = searchInput ? searchInput.value.trim().toLowerCase() : "";
  const statusFilter = document.getElementById("filter-server-status")?.value || "all";

  const filtered = globalServers.filter(srv => {
    if (statusFilter === "online" && !srv.online) return false;
    if (statusFilter === "banned" && !srv.isBanned) return false;
    if (statusFilter === "sponsored" && !srv.sponsored) return false;

    if (!query) return true;
    const matchKey = srv.serverKey?.toLowerCase().includes(query);
    const matchName = srv.name?.toLowerCase().includes(query);
    const matchOwner = srv.ownerEmail?.toLowerCase().includes(query);
    const matchIp = srv.ip?.toLowerCase().includes(query);
    return matchKey || matchName || matchOwner || matchIp;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #71717a; padding: 24px;">No matching servers found.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(srv => {
    const isBanned = Boolean(srv.isBanned);
    const isOnline = Boolean(srv.online);
    const statusHtml = isBanned
      ? `<span class="status-badge status-offline" style="background: rgba(239, 68, 68, 0.2); color: #f87171;">🚫 BANNED</span>`
      : (isOnline
          ? `<span class="status-badge status-online">🟢 Online</span>`
          : `<span class="status-badge status-offline">⚪ Offline</span>`);

    const mcVer = escapeHtml(srv.version?.minecraft || "1.21.1");
    const loader = escapeHtml(srv.version?.loader || "vanilla");
    const versionStr = `${mcVer} (${loader})`;
    const boostsBadge = srv.sponsored
      ? `<span class="badge-subtle accent-text">👑 Sponsored (${Number(srv.boosts) || 0})</span>`
      : `<span style="color: #a1a1aa;">${Number(srv.boosts) || 0}</span>`;

    const safeKey = escapeHtml(srv.serverKey || "");
    const safeName = escapeHtml(srv.name || "Minecraft Server");
    const safeMotd = escapeHtml(srv.status?.motd || "No MOTD");
    const safeIp = escapeHtml(srv.ip || "127.0.0.1");
    const safePort = Number(srv.port) || 25565;
    const safeOwner = escapeHtml(srv.ownerEmail || "unclaimed");
    const players = Number(srv.status?.players) || 0;
    const maxPlayers = Number(srv.status?.maxPlayers) || 0;
    const trustScore = Number(srv.trustScore) || 85;
    const trustLevel = escapeHtml(srv.trustLevel || "TRUSTED");
    const serverSlots = Number(srv.serverSlots) || 1;

    return `
      <tr>
        <td>${statusHtml}</td>
        <td><strong style="font-family: monospace; color: #38bdf8;">${safeKey}</strong></td>
        <td>
          <div style="font-weight: 700; color: #fff;">${safeName}</div>
          <div style="font-size: 11px; color: #71717a;">${safeMotd}</div>
        </td>
        <td style="font-family: monospace; font-size: 12px;">${safeIp}:${safePort}</td>
        <td style="font-size: 12px;">${versionStr}</td>
        <td><strong style="color: #10b981;">${players}</strong> / ${maxPlayers}</td>
        <td style="font-size: 12px; color: #a1a1aa;">
          <div>${safeOwner}</div>
          ${srv.ownerEmail && srv.ownerEmail !== "unclaimed" ? `
            <div style="font-size: 10px; margin-top: 4px; display: flex; gap: 4px; align-items: center;">
              <span class="status-badge ${trustScore >= 80 ? 'status-online' : 'status-offline'}" style="padding: 1px 6px; font-size: 10px; ${trustScore < 80 ? 'background: rgba(245,158,11,0.2); color: #fbbf24;' : ''}">
                🛡️ ${trustScore} (${trustLevel})
              </span>
              <span style="color: #818cf8; font-family: monospace;">[${serverSlots}/4 slots]</span>
            </div>
          ` : ''}
        </td>
        <td>${boostsBadge}</td>
        <td>
          <div class="action-btn-group">
            <button class="btn-action btn-action-secondary" onclick="inspectServer('${safeKey}')" title="Inspect telemetry & players">
              🔍 Inspect
            </button>
            ${isBanned
              ? `<button class="btn-action btn-action-success" onclick="toggleBanServer('${safeKey}', false)">Unban</button>`
              : `<button class="btn-action btn-action-danger" onclick="toggleBanServer('${safeKey}', true)">🚫 Ban</button>`}
            <button class="btn-action btn-action-danger" onclick="deleteServer('${safeKey}')" title="Delete server entry">🗑️</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

function renderLicensesTable() {
  const tbody = document.getElementById("licenses-table-body");
  if (!tbody) return;

  const searchInput = document.getElementById("filter-licenses");
  const query = searchInput ? searchInput.value.trim().toLowerCase() : "";

  const filtered = globalLicenses.filter(lic => {
    if (!query) return true;
    return (
      lic.licenseKey?.toLowerCase().includes(query) ||
      lic.ownerEmail?.toLowerCase().includes(query) ||
      lic.tier?.toLowerCase().includes(query)
    );
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #71717a; padding: 24px;">No licenses found.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(lic => {
    const status = escapeHtml(lic.status || "active");
    const statusBadge = lic.status === "active"
      ? `<span class="status-badge status-online">Active</span>`
      : `<span class="status-badge status-offline">${status.toUpperCase()}</span>`;

    const createdStr = lic.createdAt ? escapeHtml(new Date(lic.createdAt).toLocaleDateString()) : "—";
    const safeKey = escapeHtml(lic.licenseKey || "");
    const safeTier = escapeHtml(lic.tier || "FREE");
    const safeEmail = escapeHtml(lic.ownerEmail || "Unassigned");
    const safeServerKey = escapeHtml(lic.serverKey || "—");
    const safeNotes = escapeHtml(lic.notes || "—");

    return `
      <tr>
        <td style="font-family: monospace; font-weight: 700; color: #fff;">${safeKey}</td>
        <td><span class="tier-badge tier-${safeTier}">${safeTier}</span></td>
        <td>${statusBadge}</td>
        <td style="color: #a1a1aa;">${safeEmail}</td>
        <td style="font-family: monospace; font-size: 12px; color: #38bdf8;">${safeServerKey}</td>
        <td style="font-size: 12px; color: #71717a;">${safeNotes}</td>
        <td style="font-size: 12px; color: #71717a;">${createdStr}</td>
        <td>
          <div class="action-btn-group">
            <button class="btn-action btn-action-secondary" onclick="copyText('${safeKey}')">📋 Copy</button>
            ${lic.status === "active"
              ? `<button class="btn-action btn-action-danger" onclick="toggleLicenseStatus('${safeKey}', 'revoked')">Revoke</button>`
              : `<button class="btn-action btn-action-success" onclick="toggleLicenseStatus('${safeKey}', 'active')">Restore</button>`}
            <button class="btn-action btn-action-danger" onclick="deleteLicense('${safeKey}')">🗑️</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

function renderAuditTable() {
  const tbody = document.getElementById("audit-table-body");
  if (!tbody) return;

  if (globalAuditLogs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #71717a; padding: 24px;">No audit events recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = globalAuditLogs.slice(0, 100).map(log => {
    const timeStr = escapeHtml(new Date(log.timestamp).toLocaleTimeString());
    const action = escapeHtml(log.action || "");
    const actionColor = action.includes("BAN") || action.includes("DELETE") || action.includes("UNAUTHORIZED") ? "#f87171" : "#34d399";
    const target = escapeHtml(log.target || "");
    const actor = escapeHtml(log.actor || "");
    const ip = escapeHtml(log.ip || "");
    const details = escapeHtml(log.details || "—");

    return `
      <tr>
        <td style="font-family: monospace; font-size: 12px; color: #71717a;">${timeStr}</td>
        <td><strong style="color: ${actionColor}; font-size: 12px;">${action}</strong></td>
        <td style="font-family: monospace; color: #38bdf8; font-size: 12px;">${target}</td>
        <td style="font-size: 12px;">${actor}</td>
        <td style="font-family: monospace; font-size: 12px; color: #a1a1aa;">${ip}</td>
        <td style="font-size: 12px; color: #cbd5e1;">${details}</td>
      </tr>
    `;
  }).join("");
}

// Server Actions
window.toggleBanServer = async function(serverKey, shouldBan) {
  let reason = "Violation of Terms of Service & Safety Guidelines";
  if (shouldBan) {
    const inputReason = prompt(`Enter ban reason for server '${serverKey}':`, "Severe ToS violation / Prohibited files");
    if (inputReason === null) return;
    if (inputReason.trim()) reason = inputReason.trim();
  }

  try {
    const headers = { "Content-Type": "application/json" };
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const res = await fetch(`/api/v1/admin/servers/${encodeURIComponent(serverKey)}/ban`, {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({ banned: shouldBan, reason })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Failed to update ban status.");

    showToast(shouldBan ? `🚫 Server '${serverKey}' BANNED.` : `🟢 Server '${serverKey}' unbanned.`);
    loadAllAdminData();
  } catch (err) {
    alert(err.message);
  }
};

window.deleteServer = async function(serverKey) {
  if (!confirm(`Are you absolutely sure you want to permanently DELETE server '${serverKey}'? This action cannot be undone.`)) {
    return;
  }

  try {
    const headers = {};
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const res = await fetch(`/api/v1/admin/servers/${encodeURIComponent(serverKey)}`, {
      method: "DELETE",
      headers,
      credentials: "include"
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Failed to delete server.");

    showToast(`Server '${serverKey}' purged.`);
    loadAllAdminData();
  } catch (err) {
    alert(err.message);
  }
};

window.adjustUserSlots = async function(userId, currentSlots = 1) {
  const newSlotsStr = prompt(`Set server slots (1 to 4) for user/owner '${userId}':`, currentSlots);
  if (newSlotsStr === null) return;
  const newSlots = parseInt(newSlotsStr, 10);
  if (isNaN(newSlots) || newSlots < 1 || newSlots > 4) {
    alert("Server slots must be between 1 and 4.");
    return;
  }

  try {
    const headers = { "Content-Type": "application/json" };
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const res = await fetch(`/api/v1/admin/users/${encodeURIComponent(userId)}/slots`, {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({ serverSlots: newSlots })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || "Failed to update slots.");

    showToast(`Server slots for '${userId}' set to ${newSlots}.`);
    loadAllAdminData();
  } catch (err) {
    alert(err.message);
  }
};

window.adjustUserTrust = async function(userId, currentScore = 85) {
  const newScoreStr = prompt(`Set Trust Score (0 to 100) for user/owner '${userId}':`, currentScore);
  if (newScoreStr === null) return;
  const newScore = parseInt(newScoreStr, 10);
  if (isNaN(newScore) || newScore < 0 || newScore > 100) {
    alert("Trust score must be between 0 and 100.");
    return;
  }

  try {
    const headers = { "Content-Type": "application/json" };
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const res = await fetch(`/api/v1/admin/users/${encodeURIComponent(userId)}/trust`, {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({ trustScore: newScore })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || "Failed to update trust score.");

    showToast(`Trust score for '${userId}' set to ${newScore} (${data.user?.trustLevel || 'UPDATED'}).`);
    loadAllAdminData();
  } catch (err) {
    alert(err.message);
  }
};

window.inspectServer = function(serverKey) {
  const srv = globalServers.find(s => s.serverKey === serverKey);
  if (!srv) return;

  const modal = document.getElementById("modal-inspect-server");
  const title = document.getElementById("inspect-server-title");
  const content = document.getElementById("inspect-server-content");

  const safeName = escapeHtml(srv.name || "Minecraft Server");
  const safeKey = escapeHtml(srv.serverKey || "");
  const safeIp = escapeHtml(srv.ip || "127.0.0.1");
  const safePort = Number(srv.port) || 25565;
  const safeOwner = escapeHtml(srv.ownerEmail || "unclaimed");
  const safeOwnerId = escapeHtml(srv.ownerId || "");
  const safeHwid = escapeHtml(srv.hwid || "No hardware print recorded");
  const safeBanReason = escapeHtml(srv.banReason || "Administrative action");
  const modsCount = Number(srv.modsCount !== undefined ? srv.modsCount : (srv.mods ? srv.mods.length : 0));
  const trustScore = Number(srv.trustScore) || 85;
  const trustLevel = escapeHtml(srv.trustLevel || "TRUSTED");
  const serverSlots = Number(srv.serverSlots) || 1;

  if (title) title.innerText = `Inspector: ${srv.name || "Server"} (${srv.serverKey})`;

  const perf = srv.performance || { cpuPercent: 0, ramUsedMB: 0, ramMaxMB: 8192, tps: 20.0, uptimeSeconds: 0 };
  const pList = Array.isArray(srv.playerList) ? srv.playerList : [];

  const playersHtml = pList.length > 0
    ? pList.map(p => {
        const rawName = typeof p === "string" ? p : (p?.name || "Player");
        const safePName = escapeHtml(rawName);
        const pingVal = typeof p === "object" && p?.ping !== undefined ? `${Number(p.ping)}ms` : "Good";
        return `
          <div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.06); padding: 6px 12px; border-radius: 8px; margin: 4px;">
            <img src="https://mc-heads.net/avatar/${encodeURIComponent(rawName)}/20" alt="${safePName}" style="width: 18px; height: 18px; border-radius: 4px;">
            <span style="font-weight: 700;">${safePName}</span>
            <span style="color: #10b981; font-size: 11px; font-family: monospace;">${escapeHtml(pingVal)}</span>
          </div>
        `;
      }).join("")
    : `<span style="color: #71717a; font-style: italic;">No players connected.</span>`;

  if (content) {
    content.innerHTML = `
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 18px;">
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--admin-border); padding: 12px; border-radius: 8px;">
          <div style="font-size: 11px; color: #a1a1aa;">Tick Rate</div>
          <div style="font-size: 20px; font-weight: 800; color: #10b981;">${(Number(perf.tps) || 20).toFixed(1)} TPS</div>
        </div>
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--admin-border); padding: 12px; border-radius: 8px;">
          <div style="font-size: 11px; color: #a1a1aa;">RAM Allocated</div>
          <div style="font-size: 20px; font-weight: 800; color: #38bdf8;">${((Number(perf.ramUsedMB) || 0) / 1024).toFixed(1)} / ${((Number(perf.ramMaxMB) || 8192) / 1024).toFixed(1)} GB</div>
        </div>
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--admin-border); padding: 12px; border-radius: 8px;">
          <div style="font-size: 11px; color: #a1a1aa;">CPU Usage</div>
          <div style="font-size: 20px; font-weight: 800; color: #c084fc;">${Number(perf.cpuPercent) || 0}%</div>
        </div>
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--admin-border); padding: 12px; border-radius: 8px;">
          <div style="font-size: 11px; color: #a1a1aa;">Connected Players</div>
          <div style="font-size: 20px; font-weight: 800; color: #fbbf24;">${Number(srv.status?.players) || 0} / ${Number(srv.status?.maxPlayers) || 0}</div>
        </div>
      </div>

      <div style="margin-bottom: 16px;">
        <h4 style="margin: 0 0 8px 0; font-size: 13px; text-transform: uppercase; color: #a1a1aa;">Connected Players Online</h4>
        <div style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; border: 1px solid var(--admin-border); min-height: 48px;">
          ${playersHtml}
        </div>
      </div>

      <div style="margin-bottom: 16px;">
        <h4 style="margin: 0 0 8px 0; font-size: 13px; text-transform: uppercase; color: #a1a1aa;">Owner Account &amp; Trust Sentinel</h4>
        <div class="data-table" style="background: rgba(0,0,0,0.25); border: 1px solid var(--admin-border); border-radius: 8px; padding: 8px;">
          <div class="data-row">
            <span class="data-label">Trust Score &amp; Level</span>
            <span class="data-value">
              <span class="status-badge ${trustScore >= 80 ? 'status-online' : 'status-offline'}" style="padding: 2px 8px;">
                🛡️ ${trustScore} / 100 (${trustLevel})
              </span>
              ${safeOwnerId ? `<button class="btn-action btn-action-secondary" style="margin-left: 8px;" onclick="adjustUserTrust('${safeOwnerId}', ${trustScore})">⚙️ Adjust Trust</button>` : ''}
            </span>
          </div>
          <div class="data-row">
            <span class="data-label">Server Slots Capacity</span>
            <span class="data-value">
              <span style="font-weight: 800; color: #818cf8;">${serverSlots} / 4 Allowed Slots</span>
              ${safeOwnerId ? `<button class="btn-action btn-action-secondary" style="margin-left: 8px;" onclick="adjustUserSlots('${safeOwnerId}', ${serverSlots})">➕ Set Slots (1-4)</button>` : ''}
            </span>
          </div>
          <div class="data-row">
            <span class="data-label">Linked Hardware Fingerprint</span>
            <span class="data-value code-text">${safeHwid}</span>
          </div>
        </div>
      </div>

      <div>
        <h4 style="margin: 0 0 8px 0; font-size: 13px; text-transform: uppercase; color: #a1a1aa;">Server Details</h4>
        <div class="data-table">
          <div class="data-row"><span class="data-label">Server Key</span><span class="data-value code-text">${safeKey}</span></div>
          <div class="data-row"><span class="data-label">Endpoint IP:Port</span><span class="data-value code-text">${safeIp}:${safePort}</span></div>
          <div class="data-row"><span class="data-label">Owner Email</span><span class="data-value">${safeOwner}</span></div>
          <div class="data-row"><span class="data-label">Mods / Manifest Jars</span><span class="data-value">${modsCount} jar packages</span></div>
          <div class="data-row"><span class="data-label">Ban Status</span><span class="data-value">${srv.isBanned ? `<span style="color: #ef4444; font-weight: 700;">BANNED (${safeBanReason})</span>` : "Clean / Permitted"}</span></div>
        </div>
      </div>
    `;
  }

  modal.classList.remove("hidden");
};

// License Actions
async function handleCreateLicense(e) {
  e.preventDefault();
  const tier = document.getElementById("lic-tier")?.value || "FREE";
  const ownerEmail = document.getElementById("lic-email")?.value.trim();
  const customKey = document.getElementById("lic-custom-key")?.value.trim();
  const notes = document.getElementById("lic-notes")?.value.trim();

  try {
    const headers = { "Content-Type": "application/json" };
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const res = await fetch("/api/v1/admin/licenses/create", {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({ tier, ownerEmail, customKey, notes })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Failed to create license.");

    showToast(`🔑 License '${data.license.licenseKey}' created!`);
    document.getElementById("modal-create-license").classList.add("hidden");
    loadAllAdminData();
  } catch (err) {
    alert(err.message);
  }
}

window.toggleLicenseStatus = async function(licenseKey, newStatus) {
  let reason = "Administrative Status Update";
  if (newStatus === "revoked") {
    reason = prompt(`Enter revocation reason for key '${licenseKey}':`, "License invalidated by administrator");
    if (reason === null) return;
  }

  try {
    const headers = { "Content-Type": "application/json" };
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const res = await fetch(`/api/v1/admin/licenses/${encodeURIComponent(licenseKey)}/revoke`, {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({ status: newStatus, reason })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Failed to update license.");

    showToast(`License '${licenseKey}' set to ${newStatus}.`);
    loadAllAdminData();
  } catch (err) {
    alert(err.message);
  }
};

window.deleteLicense = async function(licenseKey) {
  if (!confirm(`Delete license key '${licenseKey}' permanently?`)) return;

  try {
    const headers = {};
    if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

    const res = await fetch(`/api/v1/admin/licenses/${encodeURIComponent(licenseKey)}`, {
      method: "DELETE",
      headers,
      credentials: "include"
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Failed to delete license.");

    showToast(`License '${licenseKey}' deleted.`);
    loadAllAdminData();
  } catch (err) {
    alert(err.message);
  }
};

window.copyText = function(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`Copied to clipboard: ${text}`);
  }).catch(() => {
    prompt("Copy key:", text);
  });
};

function showToast(message, duration = 3000) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast toast-visible";
  toast.innerText = message;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.remove("toast-visible");
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, duration);
}
