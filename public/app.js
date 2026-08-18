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
const STORAGE_TOKEN_KEY = "svl_jwt_token";
let currentAuthTab = "login";
let currentUserData = null;
let currentKeyVisible = false;
let isSyncing = false;

// Helper: Retrieve JWT Token from localStorage
function getAuthToken() {
  return localStorage.getItem(STORAGE_TOKEN_KEY) || localStorage.getItem("svl_realms_session_jwt");
}

// Helper: Set JWT Token in localStorage
function setAuthToken(token) {
  localStorage.setItem(STORAGE_TOKEN_KEY, token);
  localStorage.setItem("svl_realms_session_jwt", token);
}

// Helper: Remove JWT Token
function removeAuthToken() {
  localStorage.removeItem(STORAGE_TOKEN_KEY);
  localStorage.removeItem("svl_realms_session_jwt");
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
});

// Check Session & Update Navigation
async function checkSessionState() {
  const token = getAuthToken();
  const guestNav = document.getElementById("nav-guest-actions");
  const userNav = document.getElementById("nav-user-actions");

  if (token) {
    try {
      const res = await fetch("/api/v1/user/dashboard", {
        headers: { "Authorization": `Bearer ${token}` }
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
  const token = getAuthToken();
  if (!token) {
    openAuthModal("login");
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

// Switch between Login and Register tabs
function switchAuthTab(tab) {
  currentAuthTab = tab;
  const loginTab = document.getElementById("tab-login");
  const registerTab = document.getElementById("tab-register");
  const confirmGroup = document.getElementById("register-confirm-group");
  const submitText = document.getElementById("btn-auth-text");
  const alertBox = document.getElementById("auth-alert");

  if (alertBox) alertBox.classList.add("hidden");

  if (tab === "login") {
    if (loginTab) loginTab.classList.add("active");
    if (registerTab) registerTab.classList.remove("active");
    if (confirmGroup) confirmGroup.classList.add("hidden");
    if (submitText) submitText.innerText = "Sign in";
  } else {
    if (registerTab) registerTab.classList.add("active");
    if (loginTab) loginTab.classList.remove("active");
    if (confirmGroup) confirmGroup.classList.remove("hidden");
    if (submitText) submitText.innerText = "Create account";
  }
}


// Handle Login / Registration (Live API Call)
async function handleAuthSubmit(event) {
  event.preventDefault();
  const alertBox = document.getElementById("auth-alert");
  const submitBtn = document.getElementById("btn-auth-submit");
  const emailInput = document.getElementById("input-email");
  const passwordInput = document.getElementById("input-password");
  const passwordConfirmInput = document.getElementById("input-password-confirm");

  const email = emailInput ? emailInput.value.trim() : "";
  const password = passwordInput ? passwordInput.value : "";
  const passwordConfirm = passwordConfirmInput ? passwordConfirmInput.value : "";

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
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.style.opacity = "0.7";
  }

  const endpoint = currentAuthTab === "register" ? "/api/v1/auth/register" : "/api/v1/auth/login";

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok || !data.success) {
      throw new Error(data.message || "Authentication failed.");
    }

    setAuthToken(data.token);
    closeAuthModal();
    showToast(currentAuthTab === "register" ? "Account created successfully." : "Signed in.");
    
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
  const token = getAuthToken();
  if (!token) {
    openAuthModal("login");
    return;
  }

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
    const res = await fetch("/api/v1/user/dashboard", {
      headers: { "Authorization": `Bearer ${token}` }
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
  const { user, server } = data;

  const emailDisplay = document.getElementById("dash-email-display");
  if (emailDisplay) emailDisplay.innerText = user.email;

  const accountEmailLabel = document.getElementById("account-email-label");
  if (accountEmailLabel) accountEmailLabel.innerText = user.email;

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
  }

  // Boosts (Real Database Counts)
  const boostCountEl = document.getElementById("stat-boost-count");
  const currentBoosts = server ? (server.boosts || user.boosts || 0) : (user.boosts || user.boostCount || 0);
  if (boostCountEl) boostCountEl.innerText = currentBoosts;

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

  const token = getAuthToken();
  if (!token) {
    openAuthModal("login");
    return;
  }

  try {
    const res = await fetch("/api/v1/user/license/regenerate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
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
  const token = getAuthToken();
  if (!token) {
    openAuthModal("login");
    return;
  }

  try {
    const res = await fetch("/api/v1/user/boost", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({ amount })
    });
    const data = await res.json();
    if (data.success) {
      showToast("Server boost added.");
      fetchDashboardData(false);
    } else {
      throw new Error(data.message || "Boost failed");
    }
  } catch (err) {
    showToast("Failed to apply boost.");
  }
}

// Handle Settings Form Submission via Live API
async function handleSettingsSubmit(event) {
  event.preventDefault();
  const token = getAuthToken();
  if (!token) {
    openAuthModal("login");
    return;
  }

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
    const res = await fetch("/api/v1/user/settings", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
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
function handleLogout() {
  removeAuthToken();
  currentUserData = null;
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
