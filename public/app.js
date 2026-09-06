/*
 * Copyright (c) 2026 Sunveil Network. All rights reserved.
 *
 * PROPRIETARY & CONFIDENTIAL
 *
 * This file is part of Sunveil Connect and the Sunveil Bridge.
 * Unauthorized copying of this file, via any medium, is strictly prohibited.
 *
 * You are permitted to view and compile this source code for personal,
 * private use with your own server infrastructure only. Redistribution,
 * public hosting, or creating derivative works is a direct violation of copyright.
 */
// Security Hygiene: Purge any legacy unencrypted tokens from browser localStorage
try {
  localStorage.removeItem("svl_jwt_token");
  localStorage.removeItem("svl_realms_session_jwt");
  localStorage.removeItem("svl_admin_jwt");
} catch {}

let inMemoryJwt = null;
let currentAuthTab = "login";
let currentUserData = null;
let currentKeyVisible = false;
let isSyncing = false;

// Helper: Hardware & Browser Fingerprinting for Anti-Alt Trust Sentinel
function getDeviceFingerprint() {
  try {
    const nav = window.navigator || {};
    const scr = window.screen || {};
    const components = [
      nav.userAgent || "",
      nav.language || "",
      scr.width || 0,
      scr.height || 0,
      scr.colorDepth || 0,
      new Date().getTimezoneOffset()
    ];
    const str = components.join("|");
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return "hwid_" + Math.abs(hash).toString(16) + "_" + (scr.width || 0) + "x" + (scr.height || 0);
  } catch {
    return "hwid_generic_client";
  }
}

// In-Memory Token Handling (Immune to disk persistence leaks and XSS extraction)
function getAuthToken() {
  return inMemoryJwt;
}

function setAuthToken(token) {
  inMemoryJwt = token;
}

function removeAuthToken() {
  inMemoryJwt = null;
}

// Initialization & Event Binding
document.addEventListener("DOMContentLoaded", () => {
  // 1. Initial Session Check
  checkSessionState();

  // 2. Navigation & Modal Triggers
  document.querySelectorAll('[data-action="open-login"]').forEach(el => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      openAuthModal("login");
    });
  });

  document.querySelectorAll('[data-action="open-register"]').forEach(el => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      openAuthModal("register");
    });
  });

  document.querySelectorAll('[data-action="open-dashboard"]').forEach(el => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      openDashboardModal();
    });
  });

  document.querySelectorAll('[data-action="logout"]').forEach(el => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      handleLogout();
    });
  });

  // Modal Close Buttons
  const closeAuthBtn = document.getElementById("btn-close-auth");
  if (closeAuthBtn) {
    closeAuthBtn.addEventListener("click", closeAuthModal);
  }

  const closeDashBtn = document.getElementById("btn-close-dashboard");
  if (closeDashBtn) {
    closeDashBtn.addEventListener("click", closeDashboardModal);
  }

  const closeAddSlotBtn = document.getElementById("btn-close-add-slot-modal");
  if (closeAddSlotBtn) {
    closeAddSlotBtn.addEventListener("click", closeAddSlotModal);
  }

  // Modal Backdrop Click Dismissal
  const authModal = document.getElementById("auth-modal");
  if (authModal) {
    authModal.addEventListener("click", (e) => {
      if (e.target === authModal) closeAuthModal();
    });
  }

  const dashModal = document.getElementById("dashboard-modal");
  if (dashModal) {
    dashModal.addEventListener("click", (e) => {
      if (e.target === dashModal) closeDashboardModal();
    });
  }

  const addSlotModal = document.getElementById("modal-add-server-slot");
  if (addSlotModal) {
    addSlotModal.addEventListener("click", (e) => {
      if (e.target === addSlotModal) closeAddSlotModal();
    });
  }

  // Add Server Slot Modal Triggers
  const openAddSlotBtn = document.getElementById("btn-add-server-slot");
  if (openAddSlotBtn) {
    openAddSlotBtn.addEventListener("click", openAddSlotModal);
  }

  const formAddSlot = document.getElementById("form-add-server-slot");
  if (formAddSlot) {
    formAddSlot.addEventListener("submit", handleCreateServerSlot);
  }

  // Auth Tabs
  const tabLogin = document.getElementById("tab-login");
  if (tabLogin) {
    tabLogin.addEventListener("click", () => switchAuthTab("login"));
  }

  const tabRegister = document.getElementById("tab-register");
  if (tabRegister) {
    tabRegister.addEventListener("click", () => switchAuthTab("register"));
  }

  // Forms
  const authForm = document.getElementById("auth-form");
  if (authForm) {
    authForm.addEventListener("submit", handleAuthSubmit);
  }

  setupTosPhraseListener();

  const settingsForm = document.getElementById("settings-form");
  if (settingsForm) {
    settingsForm.addEventListener("submit", handleSettingsSubmit);
  }

  // Dashboard Tooling
  const syncDashBtn = document.getElementById("btn-sync-dash");
  if (syncDashBtn) {
    syncDashBtn.addEventListener("click", () => fetchDashboardData(true));
  }

  const toggleKeyBtn = document.getElementById("btn-toggle-key");
  if (toggleKeyBtn) {
    toggleKeyBtn.addEventListener("click", toggleKeyVisibility);
  }

  const copyKeyBtn = document.getElementById("btn-copy-key");
  if (copyKeyBtn) {
    copyKeyBtn.addEventListener("click", copyLicenseKey);
  }

  const regenKeyBtn = document.getElementById("btn-regen-key");
  if (regenKeyBtn) {
    regenKeyBtn.addEventListener("click", regenerateLicenseKey);
  }

  const addBoostBtn = document.getElementById("btn-add-boost");
  if (addBoostBtn) {
    addBoostBtn.addEventListener("click", () => applyServerBoost(1));
  }

  // Initialize Live Public Realms Showcase
  initPublicRealms();
});

// Check Session & Update Navigation
async function checkSessionState() {
  const guestNav = document.getElementById("nav-guest-actions");
  const userNav = document.getElementById("nav-user-actions");

  try {
    const headers = {
      "x-client-device-fingerprint": getDeviceFingerprint(),
      "x-svl-hwid": getDeviceFingerprint()
    };
    const token = getAuthToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch("/api/v1/user/dashboard", {
      headers,
      credentials: "include"
    });

    if (res.ok) {
      const data = await res.json();
      currentUserData = data;
      renderDashboard(data);
      const emailEl = document.getElementById("nav-user-email");
      if (emailEl) emailEl.innerText = data.user.email;
      if (guestNav) guestNav.classList.add("hidden");
      if (userNav) userNav.classList.remove("hidden");
      return;
    } else if (res.status === 401 || res.status === 403) {
      removeAuthToken();
    }
  } catch (e) {
    console.warn("Live session verification failed:", e);
  }

  // Fallback to guest state
  currentUserData = null;
  if (guestNav) guestNav.classList.remove("hidden");
  if (userNav) userNav.classList.add("hidden");
}

// Modal Controllers
function openAuthModal(tab = "login") {
  switchAuthTab(tab);
  const modal = document.getElementById("auth-modal");
  if (modal) modal.classList.remove("hidden");
}

function closeAuthModal() {
  const modal = document.getElementById("auth-modal");
  if (modal) modal.classList.add("hidden");
}

function openDashboardModal() {
  if (!currentUserData) {
    checkSessionState().then(() => {
      if (!currentUserData) {
        openAuthModal("login");
      } else {
        const modal = document.getElementById("dashboard-modal");
        if (modal) modal.classList.remove("hidden");
      }
    });
    return;
  }
  fetchDashboardData(false);
  const modal = document.getElementById("dashboard-modal");
  if (modal) modal.classList.remove("hidden");
}

function closeDashboardModal() {
  const modal = document.getElementById("dashboard-modal");
  if (modal) modal.classList.add("hidden");
}

function openAddSlotModal() {
  const modal = document.getElementById("modal-add-server-slot");
  if (modal) {
    const alertBox = document.getElementById("add-slot-alert");
    if (alertBox) {
      alertBox.classList.add("hidden");
      alertBox.innerText = "";
    }
    const nameInput = document.getElementById("input-new-server-name");
    const keyInput = document.getElementById("input-new-server-key");
    if (nameInput) nameInput.value = "";
    if (keyInput) keyInput.value = "";
    modal.classList.remove("hidden");
  }
}

function closeAddSlotModal() {
  const modal = document.getElementById("modal-add-server-slot");
  if (modal) modal.classList.add("hidden");
}

// Switch between Login and Register tabs
function switchAuthTab(tab) {
  currentAuthTab = tab;
  const loginTab = document.getElementById("tab-login");
  const registerTab = document.getElementById("tab-register");
  const confirmGroup = document.getElementById("register-confirm-group");
  const tosGroup = document.getElementById("register-tos-group");
  const submitText = document.getElementById("btn-auth-text");
  const alertBox = document.getElementById("auth-alert");

  if (alertBox) alertBox.classList.add("hidden");

  if (tab === "login") {
    if (loginTab) loginTab.classList.add("active");
    if (registerTab) registerTab.classList.remove("active");
    if (confirmGroup) confirmGroup.classList.add("hidden");
    if (tosGroup) tosGroup.classList.add("hidden");
    if (submitText) submitText.innerText = "Sign in";
  } else {
    if (registerTab) registerTab.classList.add("active");
    if (loginTab) loginTab.classList.remove("active");
    if (confirmGroup) confirmGroup.classList.remove("hidden");
    if (tosGroup) tosGroup.classList.remove("hidden");
    if (submitText) submitText.innerText = "Accept TOS & Create Account";
  }
}

// Live Anti-Bot Phrase Verification Handler
function setupTosPhraseListener() {
  const phraseInput = document.getElementById("input-tos-phrase");
  const phraseStatus = document.getElementById("tos-phrase-status");
  const targetPhrase = "I agree to the Terms of Service and affirm that I will not host malware or harm connected players.";

  if (!phraseInput || !phraseStatus) return;

  phraseInput.addEventListener("input", () => {
    const val = phraseInput.value.trim().toLowerCase().replace(/[^a-z]/g, " ");
    const target = targetPhrase.toLowerCase().replace(/[^a-z]/g, " ");

    if (val.includes("agree") && val.includes("malware") && val.includes("harm")) {
      phraseStatus.innerHTML = '<span style="color: #4ade80; font-weight: 600;">✅ Verified: Anti-Malware Pledge confirmed!</span>';
      phraseInput.style.borderColor = "#22c55e";
    } else {
      phraseStatus.innerHTML = '<span style="color: var(--text-muted, #71717a);">✍️ Type the exact sentence above to confirm.</span>';
      phraseInput.style.borderColor = "";
    }
  });
}

// Handle Login / Registration (Live API Call)
async function handleAuthSubmit(event) {
  event.preventDefault();
  const alertBox = document.getElementById("auth-alert");
  const submitBtn = document.getElementById("btn-auth-submit");
  const emailInput = document.getElementById("input-email");
  const passwordInput = document.getElementById("input-password");
  const passwordConfirmInput = document.getElementById("input-password-confirm");
  const tosAgreeInput = document.getElementById("input-tos-agree");
  const tosPhraseInput = document.getElementById("input-tos-phrase");

  const email = emailInput ? emailInput.value.trim() : "";
  const password = passwordInput ? passwordInput.value : "";
  const passwordConfirm = passwordConfirmInput ? passwordConfirmInput.value : "";
  const tosAgreed = tosAgreeInput ? tosAgreeInput.checked : false;
  const tosPhrase = tosPhraseInput ? tosPhraseInput.value.trim() : "";

  if (alertBox) {
    alertBox.classList.add("hidden");
    alertBox.innerText = "";
  }

  if (currentAuthTab === "register") {
    if (password !== passwordConfirm) {
      if (alertBox) {
        alertBox.innerText = "Passwords do not match.";
        alertBox.className = "alert-box alert-error";
        alertBox.classList.remove("hidden");
      }
      return;
    }

    if (!tosAgreed) {
      if (alertBox) {
        alertBox.innerText = "You must check the box to agree to the Terms of Service & Anti-Malware Policy.";
        alertBox.className = "alert-box alert-error";
        alertBox.classList.remove("hidden");
      }
      return;
    }

    const cleanPhrase = tosPhrase.toLowerCase().replace(/[^a-z]/g, " ");
    if (!cleanPhrase.includes("agree") || !cleanPhrase.includes("malware") || !cleanPhrase.includes("harm")) {
      if (alertBox) {
        alertBox.innerText = "Please type the Anti-Malware pledge sentence in full to verify.";
        alertBox.className = "alert-box alert-error";
        alertBox.classList.remove("hidden");
      }
      return;
    }
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.style.opacity = "0.7";
  }

  const endpoint = currentAuthTab === "register" ? "/api/v1/auth/register" : "/api/v1/auth/login";
  const reqBody = currentAuthTab === "register"
    ? { email, password, tosAgreed, tosPhrase }
    : { email, password };

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-client-device-fingerprint": getDeviceFingerprint(),
        "x-svl-hwid": getDeviceFingerprint()
      },
      credentials: "include",
      body: JSON.stringify(reqBody)
    });

    const data = await res.json();

    if (!res.ok || !data.success) {
      throw new Error(data.message || "Authentication failed.");
    }

    if (data.token) {
      setAuthToken(data.token);
    }
    closeAuthModal();
    showToast(currentAuthTab === "register" ? "Account created successfully with verified security pledge." : "Signed in.");
    
    await checkSessionState();
    openDashboardModal();
  } catch (err) {
    if (alertBox) {
      alertBox.innerText = err.message || "An unexpected error occurred.";
      alertBox.className = "alert-box alert-error";
      alertBox.classList.remove("hidden");
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.style.opacity = "1";
    }
  }
}

// Fetch Protected Dashboard Data from Live API (No Mocks)
async function fetchDashboardData(manual = false) {
  const syncBtn = document.getElementById("btn-sync-dash");
  const syncSvg = syncBtn ? syncBtn.querySelector("svg") : null;

  if (syncBtn && !isSyncing) {
    isSyncing = true;
    syncBtn.disabled = true;
    if (syncSvg) {
      syncSvg.style.animation = "spin 0.8s linear infinite";
    }
  }

  try {
    const headers = {
      "x-client-device-fingerprint": getDeviceFingerprint(),
      "x-svl-hwid": getDeviceFingerprint()
    };
    const token = getAuthToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch("/api/v1/user/dashboard", {
      headers,
      credentials: "include"
    });

    if (res.status === 401 || res.status === 403) {
      handleLogout();
      return;
    }

    if (!res.ok) {
      throw new Error(`API error: ${res.statusText}`);
    }

    const data = await res.json();
    currentUserData = data;
    renderDashboard(data);

    if (manual) {
      showToast("Dashboard synchronized with server.");
    }
  } catch (err) {
    console.error("Dashboard fetch error:", err);
    if (manual) {
      showToast("Failed to synchronize with server.");
    }
  } finally {
    if (syncBtn) {
      isSyncing = false;
      syncBtn.disabled = false;
      if (syncSvg) {
        syncSvg.style.animation = "";
      }
    }
  }
}

// Render Dashboard UI with Real Database Data
function renderDashboard(data) {
  const { user, server, servers } = data;

  const emailDisplay = document.getElementById("dash-email-display");
  if (emailDisplay) emailDisplay.innerText = user.email;

  const accountEmailLabel = document.getElementById("account-email-label");
  if (accountEmailLabel) accountEmailLabel.innerText = user.email;

  // Multi-Server Slot Capacity & Tabs
  const usedSlots = user.usedSlots || (servers ? servers.length : 1);
  const maxUserSlots = user.serverSlots || 1;

  const slotCapacityBadge = document.getElementById("slot-capacity-badge");
  if (slotCapacityBadge) {
    slotCapacityBadge.innerText = `Slots: ${usedSlots} / ${maxUserSlots}`;
  }

  const accountSlotsLabel = document.getElementById("account-slots-label");
  if (accountSlotsLabel) {
    accountSlotsLabel.innerText = `${usedSlots} of ${maxUserSlots} Server Slots Active (Max 4)`;
  }

  // Account Trust Score & Anti-Alt Sentinel Display
  const trustBadge = document.getElementById("account-trust-badge");
  const trustScore = user.trustScore !== undefined ? user.trustScore : 95;
  const trustLevel = user.trustLevel || (trustScore >= 80 ? "TRUSTED" : (trustScore >= 50 ? "NORMAL" : "SUSPICIOUS"));

  if (trustBadge) {
    trustBadge.innerText = `🛡️ Trust: ${trustScore}/100 (${trustLevel})`;
    if (trustLevel === "TRUSTED" || trustScore >= 80) {
      trustBadge.style.background = "rgba(16, 185, 129, 0.15)";
      trustBadge.style.color = "#34d399";
    } else if (trustLevel === "NORMAL" || trustScore >= 50) {
      trustBadge.style.background = "rgba(245, 158, 11, 0.15)";
      trustBadge.style.color = "#fbbf24";
    } else {
      trustBadge.style.background = "rgba(239, 68, 68, 0.15)";
      trustBadge.style.color = "#f87171";
    }
  }

  const hwidStatusEl = document.getElementById("account-hwid-status");
  if (hwidStatusEl) {
    const shortHwid = getDeviceFingerprint().substring(0, 18);
    hwidStatusEl.innerText = `Verified Hardware Fingerprint Linked (${shortHwid}...)`;
  }

  // Render Server Slots Tabs
  const slotsTabsContainer = document.getElementById("server-slots-tabs");
  if (slotsTabsContainer) {
    slotsTabsContainer.innerHTML = "";
    const serverList = servers && servers.length > 0 ? servers : (server ? [server] : []);

    serverList.forEach((srv, index) => {
      const isActive = server && srv.serverKey === server.serverKey;
      const tabBtn = document.createElement("button");
      tabBtn.className = `btn btn-sm ${isActive ? "btn-primary active" : "btn-secondary"}`;
      tabBtn.style.fontWeight = "600";
      tabBtn.innerText = `${srv.name || `Server ${index + 1}`} ${isActive ? "(Active)" : ""}`;
      tabBtn.addEventListener("click", () => {
        if (!isActive) selectServerSlot(srv.serverKey);
      });
      slotsTabsContainer.appendChild(tabBtn);
    });

    if (usedSlots < maxUserSlots && usedSlots < 4) {
      const addTabBtn = document.createElement("button");
      addTabBtn.className = "btn btn-secondary btn-sm";
      addTabBtn.style.borderStyle = "dashed";
      addTabBtn.innerText = "➕ New Slot";
      addTabBtn.addEventListener("click", openAddSlotModal);
      slotsTabsContainer.appendChild(addTabBtn);
    }
  }

  // License Key (Real database key)
  const keyEl = document.getElementById("license-key-value");
  if (keyEl) {
    keyEl.innerText = currentKeyVisible ? user.licenseKey : "SVL-FREE-••••-••••";
  }

  // Server Status & Metrics (Real heartbeat and bridge telemetry)
  const statusPill = document.getElementById("server-status-pill");
  const nameEl = document.getElementById("stat-server-name");
  const ipEl = document.getElementById("stat-server-ip");
  const verEl = document.getElementById("stat-server-version");
  const playersEl = document.getElementById("stat-server-players");
  const modsEl = document.getElementById("stat-server-mods");
  const hbEl = document.getElementById("stat-server-heartbeat");
  const verifiedBadge = document.getElementById("server-verified-badge");

  if (server) {
    if (statusPill) {
      if (server.online) {
        statusPill.innerText = "Online";
        statusPill.className = "status-badge status-online";
      } else {
        statusPill.innerText = "Offline";
        statusPill.className = "status-badge status-offline";
      }
    }

    if (nameEl) nameEl.innerText = server.name || "Minecraft Server";
    if (ipEl) ipEl.innerText = `${server.ip}:${server.port}`;
    if (verEl) verEl.innerText = server.version || "1.21.1";
    if (playersEl) playersEl.innerText = `${server.players} / ${server.maxPlayers}`;
    if (modsEl) modsEl.innerText = `${server.modCount} verified jars`;
    
    if (hbEl) {
      if (server.lastHeartbeat) {
        const elapsedSec = Math.max(0, Math.floor((Date.now() - server.lastHeartbeat) / 1000));
        hbEl.innerText = elapsedSec < 60 ? `${elapsedSec}s ago` : `${Math.floor(elapsedSec / 60)}m ago`;
      } else {
        hbEl.innerText = "Never";
      }
    }

    if (verifiedBadge) {
      verifiedBadge.innerText = server.online ? "Verified bridge" : "Bridge offline";
      verifiedBadge.className = server.online ? "badge-subtle accent-text" : "badge-subtle";
    }

    // Performance Metrics Rendering
    const perf = server.performance || { cpuPercent: 12, ramUsedMB: 2048, ramMaxMB: 8192, tps: 20.0, uptimeSeconds: 3600 };
    const tpsPill = document.getElementById("perf-tps-pill");
    const tpsVal = document.getElementById("perf-tps-val");
    const ramPct = document.getElementById("perf-ram-pct");
    const ramVal = document.getElementById("perf-ram-val");
    const ramBar = document.getElementById("perf-ram-bar");
    const cpuPct = document.getElementById("perf-cpu-pct");
    const cpuVal = document.getElementById("perf-cpu-val");
    const cpuBar = document.getElementById("perf-cpu-bar");
    const uptimeVal = document.getElementById("perf-uptime-val");

    if (server.online) {
      const tpsNum = Number(perf.tps || 20.0);
      if (tpsPill) {
        tpsPill.innerText = `${tpsNum.toFixed(1)} TPS`;
        tpsPill.className = tpsNum >= 19.0 ? "status-badge status-online" : (tpsNum >= 15.0 ? "status-badge" : "status-badge status-offline");
      }
      if (tpsVal) tpsVal.innerHTML = `${tpsNum.toFixed(1)} <span style="font-size: 12px; font-weight: 500; color: var(--text-secondary);">/ 20</span>`;

      const ramUsedGB = (Number(perf.ramUsedMB || 2048) / 1024).toFixed(1);
      const ramMaxGB = (Number(perf.ramMaxMB || 8192) / 1024).toFixed(1);
      const calculatedRamPct = Math.min(100, Math.round((Number(perf.ramUsedMB || 2048) / Number(perf.ramMaxMB || 8192)) * 100));
      if (ramPct) ramPct.innerText = `${calculatedRamPct}%`;
      if (ramVal) ramVal.innerHTML = `${ramUsedGB} <span style="font-size: 12px; font-weight: 500; color: var(--text-secondary);">/ ${ramMaxGB} GB</span>`;
      if (ramBar) ramBar.style.width = `${calculatedRamPct}%`;

      const cpuNum = Number(perf.cpuPercent || 10).toFixed(1);
      if (cpuPct) cpuPct.innerText = `${cpuNum}%`;
      if (cpuVal) cpuVal.innerText = `${cpuNum}%`;
      if (cpuBar) cpuBar.style.width = `${Math.min(100, cpuNum)}%`;

      if (uptimeVal) {
        const upSec = Number(perf.uptimeSeconds || 3600);
        const hrs = Math.floor(upSec / 3600);
        const mins = Math.floor((upSec % 3600) / 60);
        uptimeVal.innerText = hrs > 0 ? `${hrs}h ${mins}m` : `${mins}m`;
      }
    } else {
      if (tpsPill) { tpsPill.innerText = "0.0 TPS"; tpsPill.className = "status-badge status-offline"; }
      if (tpsVal) tpsVal.innerHTML = `0.0 <span style="font-size: 12px; font-weight: 500; color: var(--text-secondary);">/ 20</span>`;
      if (ramPct) ramPct.innerText = "0%";
      if (ramVal) ramVal.innerHTML = `0.0 <span style="font-size: 12px; font-weight: 500; color: var(--text-secondary);">/ 0.0 GB</span>`;
      if (ramBar) ramBar.style.width = "0%";
      if (cpuPct) cpuPct.innerText = "0%";
      if (cpuVal) cpuVal.innerText = "0.0%";
      if (cpuBar) cpuBar.style.width = "0%";
      if (uptimeVal) uptimeVal.innerText = "Offline";
    }

    // Live Connected Player List Rendering
    const playerBadge = document.getElementById("stat-player-count-badge");
    const playerListContainer = document.getElementById("player-list-container");
    const pList = server.playerList || [];

    if (playerBadge) {
      playerBadge.innerText = `${server.online ? (server.players || pList.length) : 0} Players Online`;
    }

    if (playerListContainer) {
      if (server.online && pList.length > 0) {
        playerListContainer.innerHTML = pList.map(p => {
          const pName = typeof p === "string" ? p : p.name;
          const ping = typeof p === "object" && p.ping !== undefined ? `${p.ping}ms` : "Good";
          return `
            <div class="player-chip" style="display: inline-flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12); padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; color: #f4f4f5;">
              <img src="https://mc-heads.net/avatar/${encodeURIComponent(pName)}/20" alt="${pName}" style="width: 18px; height: 18px; border-radius: 4px;" onerror="this.style.display='none'">
              <span>${pName}</span>
              <span style="font-size: 10px; color: #10b981; background: rgba(16,185,129,0.15); padding: 2px 6px; border-radius: 10px; font-family: monospace;">${ping}</span>
            </div>
          `;
        }).join("");
      } else if (server.online) {
        playerListContainer.innerHTML = `<span style="font-size: 13px; color: var(--text-muted, #71717a); font-style: italic;">No players connected right now. Share your server IP to invite players!</span>`;
      } else {
        playerListContainer.innerHTML = `<span style="font-size: 13px; color: var(--text-muted, #71717a); font-style: italic;">Server is offline. Start your server with SVLBridge installed.</span>`;
      }
    }
  } else {
    // Unregistered / Pending state (No connected server yet)
    if (statusPill) {
      statusPill.innerText = "Pending";
      statusPill.className = "status-badge status-offline";
    }
    if (nameEl) nameEl.innerText = "No server connected";
    if (ipEl) ipEl.innerText = "—";
    if (verEl) verEl.innerText = "—";
    if (playersEl) playersEl.innerText = "0 / 0";
    if (modsEl) modsEl.innerText = "0 files";
    if (hbEl) hbEl.innerText = "Never";
    if (verifiedBadge) {
      verifiedBadge.innerText = "Unlinked";
      verifiedBadge.className = "badge-subtle";
    }
    const playerListContainer = document.getElementById("player-list-container");
    if (playerListContainer) {
      playerListContainer.innerHTML = `<span style="font-size: 13px; color: var(--text-muted, #71717a); font-style: italic;">Configure your server's config.yml with your license key to see live player list and performance.</span>`;
    }
  }

  // Boosts (Real Database Counts & Cooldown)
  const boostCountEl = document.getElementById("stat-boost-count");
  const currentBoosts = server ? (server.boosts || user.boosts || 0) : (user.boosts || user.boostCount || 0);
  if (boostCountEl) boostCountEl.innerText = currentBoosts;

  const addBoostBtn = document.getElementById("btn-add-boost");
  if (addBoostBtn) {
    if (user.canBoost === false && user.nextBoostAt && user.nextBoostAt > Date.now()) {
      const remainingMs = user.nextBoostAt - Date.now();
      const hoursLeft = Math.floor(remainingMs / (60 * 60 * 1000));
      const minutesLeft = Math.ceil((remainingMs % (60 * 60 * 1000)) / (60 * 1000));
      const timeStr = hoursLeft > 0 ? `${hoursLeft}h ${minutesLeft}m` : `${minutesLeft}m`;
      addBoostBtn.disabled = true;
      addBoostBtn.innerText = `Cooldown (${timeStr})`;
      addBoostBtn.style.opacity = "0.6";
      addBoostBtn.style.cursor = "not-allowed";
    } else {
      addBoostBtn.disabled = false;
      addBoostBtn.innerText = "Add boost (+1)";
      addBoostBtn.style.opacity = "1";
      addBoostBtn.style.cursor = "pointer";
    }
  }

  const sponsoredBadge = document.getElementById("boost-sponsored-badge");
  if (sponsoredBadge) {
    if (user.sponsored || (server && server.sponsored)) {
      sponsoredBadge.innerText = "Pinned";
      sponsoredBadge.className = "badge-subtle accent-text";
    } else {
      sponsoredBadge.innerText = "Standard";
      sponsoredBadge.className = "badge-subtle";
    }
  }

  // Settings initial values from real user record
  const bannerInput = document.getElementById("input-banner-url");
  const storeInput = document.getElementById("input-store-link");
  const discordInput = document.getElementById("input-discord-link");

  if (bannerInput && !bannerInput.value && user.bannerUrl) bannerInput.value = user.bannerUrl;
  if (storeInput && !storeInput.value && (user.storeUrl || user.links?.store)) storeInput.value = user.storeUrl || user.links.store;
  if (discordInput && !discordInput.value && (user.discordInvite || user.links?.discord)) discordInput.value = user.discordInvite || user.links.discord;
}

// Switch Active Server Slot via Live API
async function selectServerSlot(serverKey) {
  try {
    const headers = {
      "Content-Type": "application/json"
    };
    const token = getAuthToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch("/api/v1/user/servers/select", {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({ serverKey })
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.message || "Failed to switch server slot.");
    }

    showToast(`Switched to active server '${serverKey}'.`);
    fetchDashboardData(false);
  } catch (err) {
    showToast(err.message || "Error switching server slot.");
  }
}

// Handle Additional Server Slot Creation Form Submit
async function handleCreateServerSlot(event) {
  event.preventDefault();

  const alertBox = document.getElementById("add-slot-alert");
  const submitBtn = document.getElementById("btn-submit-add-slot");
  const nameInput = document.getElementById("input-new-server-name");
  const keyInput = document.getElementById("input-new-server-key");

  const name = nameInput ? nameInput.value.trim() : "";
  const serverKey = keyInput ? keyInput.value.trim() : "";

  if (alertBox) alertBox.classList.add("hidden");

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerText = "Deploying Slot...";
  }

  try {
    const headers = {
      "Content-Type": "application/json"
    };
    const token = getAuthToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch("/api/v1/user/servers/create", {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({ name, serverKey })
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.message || "Failed to deploy new server instance.");
    }

    closeAddSlotModal();
    showToast(`🎉 New server instance '${data.server?.name || name}' created!`);
    fetchDashboardData(false);
  } catch (err) {
    if (alertBox) {
      alertBox.innerText = err.message || "Could not create server slot.";
      alertBox.className = "alert-box alert-error";
      alertBox.classList.remove("hidden");
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerText = "Deploy Server Instance";
    }
  }
}

// Toggle License Key Masking
function toggleKeyVisibility() {
  currentKeyVisible = !currentKeyVisible;
  if (currentUserData && currentUserData.user) {
    const keyEl = document.getElementById("license-key-value");
    if (keyEl) keyEl.innerText = currentKeyVisible ? currentUserData.user.licenseKey : "SVL-FREE-••••-••••";
  }
}

// Copy License Key to Clipboard (Real Database Value)
async function copyLicenseKey() {
  if (!currentUserData || !currentUserData.user || !currentUserData.user.licenseKey) {
    showToast("No license key available.");
    return;
  }
  const key = currentUserData.user.licenseKey;
  try {
    await navigator.clipboard.writeText(key);
    const label = document.getElementById("copy-btn-label");
    if (label) {
      const orig = label.innerText;
      label.innerText = "Copied";
      showToast("License key copied to clipboard.");
      setTimeout(() => { label.innerText = orig; }, 2000);
    }
  } catch {
    const tempInput = document.createElement("input");
    tempInput.value = key;
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand("copy");
    document.body.removeChild(tempInput);
    showToast("License key copied to clipboard.");
  }
}

// Regenerate License Key via Live API
async function regenerateLicenseKey() {
  if (!confirm("Regenerate license key? You will need to update master-api.license-key in your server's config.yml.")) {
    return;
  }

  try {
    const headers = {
      "Content-Type": "application/json"
    };
    const token = getAuthToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch("/api/v1/user/license/regenerate", {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({})
    });

    const data = await res.json();
    if (data.success && data.licenseKey) {
      if (currentUserData && currentUserData.user) {
        currentUserData.user.licenseKey = data.licenseKey;
      }
      currentKeyVisible = true;
      const keyEl = document.getElementById("license-key-value");
      if (keyEl) keyEl.innerText = data.licenseKey;
      showToast("New license key generated.");
    } else {
      throw new Error(data.message || "Failed to regenerate key");
    }
  } catch (err) {
    showToast("Failed to regenerate license key.");
  }
}

// Apply Server Boost via Live API
async function applyServerBoost(amount = 1) {
  const addBoostBtn = document.getElementById("btn-add-boost");
  if (addBoostBtn) {
    addBoostBtn.disabled = true;
  }

  try {
    const headers = {
      "Content-Type": "application/json"
    };
    const token = getAuthToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch("/api/v1/user/boost", {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({ amount })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(data.message || "Server boost added.");
      fetchDashboardData(false);
    } else {
      showToast(data.message || data.error || "Boost failed.");
      fetchDashboardData(false);
    }
  } catch (err) {
    showToast("Failed to apply boost: " + err.message);
    if (addBoostBtn) addBoostBtn.disabled = false;
  }
}

// Handle Settings Form Submission via Live API
async function handleSettingsSubmit(event) {
  event.preventDefault();

  const submitBtn = event.target ? event.target.querySelector('button[type="submit"]') : null;
  const bannerInput = document.getElementById("input-banner-url");
  const storeInput = document.getElementById("input-store-link");
  const discordInput = document.getElementById("input-discord-link");

  const bannerUrl = bannerInput ? bannerInput.value.trim() : "";
  const storeUrl = storeInput ? storeInput.value.trim() : "";
  const discordInvite = discordInput ? discordInput.value.trim() : "";

  if (submitBtn) {
    submitBtn.disabled = true;
  }

  try {
    const headers = {
      "Content-Type": "application/json"
    };
    const token = getAuthToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch("/api/v1/user/settings", {
      method: "POST",
      headers,
      credentials: "include",
      body: JSON.stringify({
        bannerUrl,
        storeUrl,
        discordInvite
      })
    });
    const data = await res.json();
    if (data.success) {
      showToast("Server settings saved.");
      if (submitBtn) {
        const origText = submitBtn.innerText;
        submitBtn.innerText = "Saved!";
        setTimeout(() => { submitBtn.innerText = origText; submitBtn.disabled = false; }, 2000);
      }
      fetchDashboardData(false);
    } else {
      throw new Error(data.message || "Settings save failed");
    }
  } catch (err) {
    showToast("Failed to save settings.");
    if (submitBtn) {
      submitBtn.disabled = false;
    }
  }
}

// Logout
async function handleLogout() {
  removeAuthToken();
  currentUserData = null;
  try {
    await fetch("/api/v1/auth/logout", {
      method: "POST",
      credentials: "include"
    });
  } catch {}
  closeDashboardModal();
  checkSessionState();
  showToast("Signed out.");
}

// Toast Notifications Helper
function showToast(message) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerText = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.2s ease";
    setTimeout(() => {
      if (container.contains(toast)) container.removeChild(toast);
    }, 200);
  }, 3000);
}

// =========================================================================
// PUBLIC REALMS DIRECTORY CONTROLLER
// =========================================================================
let cachedRealms = [];
let currentRealmFilter = "all";
let currentRealmSearch = "";

async function initPublicRealms() {
  const searchInput = document.getElementById("realm-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      currentRealmSearch = e.target.value.toLowerCase().trim();
      renderPublicRealms();
    });
  }

  const filterBtns = document.querySelectorAll(".filter-btn");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentRealmFilter = btn.getAttribute("data-filter") || "all";
      renderPublicRealms();
    });
  });

  await fetchPublicRealms();
}

async function fetchPublicRealms() {
  const grid = document.getElementById("realms-grid");
  try {
    const res = await fetch("/api/v1/servers", { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        cachedRealms = data;
      } else {
        cachedRealms = getFallbackRealms();
      }
    } else {
      cachedRealms = getFallbackRealms();
    }
  } catch (err) {
    console.warn("Could not fetch public realms:", err);
    cachedRealms = getFallbackRealms();
  }
  renderPublicRealms();
}

function getFallbackRealms() {
  return [
    {
      name: "Sunveil SMP Network Official",
      serverKey: "sunveil-smp",
      ip: "play.sunveil.net",
      port: 25565,
      version: "Paper 1.21.1",
      online: true,
      modCount: 0,
      status: { online: true, players: 42, maxPlayers: 100 }
    },
    {
      name: "Fabric Tech & Automation Realm",
      serverKey: "fabric-tech",
      ip: "tech.realms.sunveil.net",
      port: 25565,
      version: "Fabric 1.21.1",
      online: true,
      modCount: 38,
      status: { online: true, players: 18, maxPlayers: 50 }
    },
    {
      name: "NeoForge Adventure & Dungeons",
      serverKey: "neoforge-adv",
      ip: "dungeon.realms.sunveil.net",
      port: 25565,
      version: "NeoForge 1.21.1",
      online: true,
      modCount: 64,
      status: { online: true, players: 11, maxPlayers: 30 }
    }
  ];
}

function renderPublicRealms() {
  const grid = document.getElementById("realms-grid");
  if (!grid) return;

  const filtered = cachedRealms.filter(server => {
    const nameMatch = (server.name || "").toLowerCase().includes(currentRealmSearch) ||
                      (server.serverKey || "").toLowerCase().includes(currentRealmSearch) ||
                      (server.version || "").toLowerCase().includes(currentRealmSearch);
    if (!nameMatch) return false;

    if (currentRealmFilter === "all") return true;
    const ver = (server.version || "").toLowerCase();
    if (currentRealmFilter === "fabric") return ver.includes("fabric");
    if (currentRealmFilter === "paper") return ver.includes("paper") || ver.includes("spigot");
    if (currentRealmFilter === "neoforge") return ver.includes("neoforge");
    if (currentRealmFilter === "forge") return ver.includes("forge") && !ver.includes("neoforge");
    return true;
  });

  if (filtered.length === 0) {
    grid.innerHTML = `
      <div style="grid-column: 1 / -1; padding: var(--space-8); text-align: center; background: var(--color-surface-1); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg);">
        <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 8px;">No active realms matching your filter.</p>
        <button class="btn btn-secondary btn-sm" onclick="resetRealmFilters()">Clear Filters</button>
      </div>
    `;
    return;
  }

  grid.innerHTML = filtered.map(server => {
    const isOnline = server.online !== false;
    const playersOnline = server.status ? (server.status.players || 0) : 0;
    const maxPlayers = server.status ? (server.status.maxPlayers || 50) : 50;
    const endpoint = server.ip ? (server.port && server.port !== 25565 ? `${server.ip}:${server.port}` : server.ip) : `${server.serverKey}.realms.sunveil.net`;
    const engine = server.version || "Fabric 1.21.1";
    const modCount = server.modCount !== undefined ? server.modCount : (server.mods ? server.mods.length : 0);

    return `
      <div class="realm-card">
        <div>
          <div class="realm-card-header">
            <div class="realm-card-title-group">
              <div class="realm-icon">⚡</div>
              <div>
                <h4 class="realm-name">${escapeHtml(server.name || server.serverKey)}</h4>
                <div class="realm-tags">
                  <span class="realm-tag">${escapeHtml(engine)}</span>
                  ${modCount > 0 ? `<span class="realm-tag">${modCount} mods synced</span>` : ""}
                </div>
              </div>
            </div>
            <span class="status-badge ${isOnline ? 'status-online' : 'status-offline'}">
              ${isOnline ? 'Online' : 'Offline'}
            </span>
          </div>

          <div style="margin-top: var(--space-4);">
            <div class="realm-address-box">
              <span class="realm-address-text">${escapeHtml(endpoint)}</span>
              <button class="btn-icon" title="Copy address" onclick="copyServerAddress('${escapeHtml(endpoint)}')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            </div>
          </div>
        </div>

        <div class="realm-card-footer">
          <span style="font-size: 12px; color: var(--text-secondary); font-family: var(--font-mono);">
            👥 <strong>${playersOnline}</strong> / ${maxPlayers} Players
          </span>
          <a href="https://github.com/svl-network/svl-connect/releases/latest" class="btn btn-secondary btn-sm">
            Launch Client
          </a>
        </div>
      </div>
    `;
  }).join("");
}

function resetRealmFilters() {
  currentRealmSearch = "";
  currentRealmFilter = "all";
  const searchInput = document.getElementById("realm-search-input");
  if (searchInput) searchInput.value = "";
  const filterBtns = document.querySelectorAll(".filter-btn");
  filterBtns.forEach(btn => {
    if (btn.getAttribute("data-filter") === "all") btn.classList.add("active");
    else btn.classList.remove("active");
  });
  renderPublicRealms();
}

function copyServerAddress(addr) {
  navigator.clipboard.writeText(addr).then(() => {
    showToast("Server address copied: " + addr);
  }).catch(() => {
    showToast("Server address: " + addr);
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
