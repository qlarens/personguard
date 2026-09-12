(() => {
  "use strict";

  const MAGIC = new Uint8Array([0x50, 0x47, 0x44, 0x31]);
  const HEADER_SIZE = 40;
  const PGD_VERSION = 1;
  const KDF_ID = 1;
  const CIPHER_ID = 1;
  const KDF_ITERATIONS = 600_000;
  const APP_KDF_ITERATIONS = 210_000;
  const MAX_FILE_SIZE = 25 * 1024 * 1024;
  const te = new TextEncoder();
  const td = new TextDecoder("utf-8", { fatal: true });

  const state = {
    vault: null,
    key: null,
    salt: null,
    fileName: null,
    pendingFile: null,
    dirty: false,
    selectedFilter: "all",
    selectedGroup: null,
    layout: "grid",
    graphZoom: 1,
    inactivityTimer: null,
    revealedTimers: new Map(),
  };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const screens = $$(".screen");
  const els = {
    welcome: $("#welcome-screen"),
    appLockScreen: $("#app-lock-screen"),
    app: $("#app-screen"),
    fileInput: $("#file-input"),
    createDialog: $("#create-dialog"),
    unlockDialog: $("#unlock-dialog"),
    entryDialog: $("#entry-dialog"),
    appLockDialog: $("#app-lock-dialog"),
    deleteDialog: $("#delete-dialog"),
    entriesGrid: $("#entries-grid"),
    emptyState: $("#empty-state"),
    groupList: $("#group-list"),
    search: $("#search-input"),
  };

  function showScreen(target) {
    screens.forEach((screen) => screen.classList.toggle("is-active", screen === target));
  }

  function showToast(message, type = "success") {
    const region = $("#toast-region");
    const toast = document.createElement("div");
    toast.className = `toast ${type === "error" ? "error" : ""}`;
    toast.textContent = message;
    region.append(toast);
    window.setTimeout(() => toast.remove(), 3400);
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  async function deriveVaultKey(password, salt, iterations = KDF_ITERATIONS) {
    const material = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  function buildHeader(salt, iv, iterations = KDF_ITERATIONS) {
    const header = new Uint8Array(HEADER_SIZE);
    header.set(MAGIC, 0);
    header[4] = PGD_VERSION;
    header[5] = KDF_ID;
    header[6] = CIPHER_ID;
    header[7] = 0;
    new DataView(header.buffer).setUint32(8, iterations, false);
    header.set(salt, 12);
    header.set(iv, 28);
    return header;
  }

  async function encryptVault(vault, key, salt) {
    const iv = randomBytes(12);
    const header = buildHeader(salt, iv);
    const plaintext = te.encode(JSON.stringify(vault));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: header, tagLength: 128 },
      key,
      plaintext,
    ));
    const output = new Uint8Array(header.length + ciphertext.length);
    output.set(header, 0);
    output.set(ciphertext, header.length);
    plaintext.fill(0);
    return output;
  }

  function cleanString(value, max) {
    return typeof value === "string" ? value.slice(0, max) : "";
  }

  function sanitizeVault(value) {
    if (!value || typeof value !== "object" || value.schemaVersion !== 1 || !Array.isArray(value.entries)) {
      throw new Error("Файл содержит неподдерживаемую структуру.");
    }
    if (value.entries.length > 100_000) throw new Error("В файле слишком много записей.");
    return {
      schemaVersion: 1,
      vaultId: cleanString(value.vaultId, 100) || crypto.randomUUID(),
      name: cleanString(value.name, 48) || "Мои пароли",
      createdAt: cleanString(value.createdAt, 40) || new Date().toISOString(),
      updatedAt: cleanString(value.updatedAt, 40) || new Date().toISOString(),
      entries: value.entries.map((item) => ({
        id: cleanString(item?.id, 100) || crypto.randomUUID(),
        title: cleanString(item?.title, 80),
        url: cleanString(item?.url, 400),
        username: cleanString(item?.username, 180),
        password: cleanString(item?.password, 500),
        phone: cleanString(item?.phone, 40),
        favorite: Boolean(item?.favorite),
        createdAt: cleanString(item?.createdAt, 40) || new Date().toISOString(),
        updatedAt: cleanString(item?.updatedAt, 40) || new Date().toISOString(),
      })).filter((item) => item.title && item.username && item.password),
    };
  }

  async function decryptVault(buffer, password) {
    const bytes = new Uint8Array(buffer);
    if (bytes.length < HEADER_SIZE + 16) throw new Error("Файл слишком короткий или повреждён.");
    if (!equalBytes(bytes.subarray(0, 4), MAGIC)) throw new Error("Это не файл PersonGuard .pgd.");
    if (bytes[4] !== PGD_VERSION) throw new Error("Версия этого .pgd пока не поддерживается.");
    if (bytes[5] !== KDF_ID || bytes[6] !== CIPHER_ID) throw new Error("Неизвестный алгоритм защиты.");
    const iterations = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8, false);
    if (iterations < 100_000 || iterations > 2_000_000) throw new Error("Некорректные параметры защиты файла.");
    const header = bytes.slice(0, HEADER_SIZE);
    const salt = bytes.slice(12, 28);
    const iv = bytes.slice(28, 40);
    const key = await deriveVaultKey(password, salt, iterations);
    let plaintext;
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: header, tagLength: 128 },
        key,
        bytes.subarray(HEADER_SIZE),
      ));
    } catch {
      throw new Error("Неверный мастер‑пароль или файл был изменён.");
    }
    let parsed;
    try {
      parsed = JSON.parse(td.decode(plaintext));
    } catch {
      throw new Error("Расшифрованные данные повреждены.");
    } finally {
      plaintext.fill(0);
    }
    return { vault: sanitizeVault(parsed), key, salt };
  }

  function passwordScore(password) {
    if (!password) return 0;
    let score = 0;
    if (password.length >= 10) score += 1;
    if (password.length >= 14) score += 1;
    const classes = [/[a-zа-я]/, /[A-ZА-Я]/, /\d/, /[^\p{L}\p{N}]/u].filter((rx) => rx.test(password)).length;
    if (classes >= 3) score += 1;
    if (classes === 4 && password.length >= 16) score += 1;
    if (/^(.)\1+$/.test(password) || /password|qwerty|пароль|12345/i.test(password)) score = Math.min(score, 1);
    return Math.min(score, 4);
  }

  function updateStrength(input, meter, label, isMaster = false) {
    const score = passwordScore(input.value);
    meter.dataset.score = String(score);
    const labels = isMaster
      ? ["Минимум 12 символов", "Слабый пароль", "Средний пароль", "Надёжный пароль", "Очень надёжный пароль"]
      : ["Надёжность пароля", "Слабый", "Средний", "Надёжный", "Очень надёжный"];
    label.textContent = labels[score];
  }

  function isEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(value.trim());
  }

  function emailGroup(entry) {
    return isEmail(entry.username) ? entry.username.trim().toLowerCase() : null;
  }

  function groupsForVault() {
    const groups = new Map();
    if (!state.vault) return groups;
    state.vault.entries.forEach((entry) => {
      const group = emailGroup(entry);
      if (!group) return;
      if (!groups.has(group)) groups.set(group, []);
      groups.get(group).push(entry);
    });
    return new Map([...groups].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0])));
  }

  function hashColor(value) {
    let hash = 0;
    for (let i = 0; i < value.length; i += 1) hash = value.charCodeAt(i) + ((hash << 5) - hash);
    const palette = ["#385eb7", "#255e70", "#604294", "#7a4657", "#446148", "#795632", "#3e4d86"];
    return palette[Math.abs(hash) % palette.length];
  }

  function safeHostname(value) {
    if (!value) return "Без ссылки";
    try {
      const url = new URL(value.startsWith("http://") || value.startsWith("https://") ? value : `https://${value}`);
      return url.hostname.replace(/^www\./, "");
    } catch {
      return "Без ссылки";
    }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
    })[char]);
  }

  function pluralEntries(count) {
    const mod10 = count % 10;
    const mod100 = count % 100;
    if (mod10 === 1 && mod100 !== 11) return `${count} запись`;
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${count} записи`;
    return `${count} записей`;
  }

  function setDirty(dirty = true) {
    state.dirty = dirty;
    const indicator = $("#dirty-indicator");
    indicator.classList.toggle("is-dirty", dirty);
    indicator.textContent = dirty ? "Есть несохранённые изменения" : "Все изменения сохранены в файл";
  }

  function formatRelativeTime(value) {
    const time = Date.parse(value);
    if (!Number.isFinite(time)) return "сейчас";
    const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
    if (seconds < 60) return "сейчас";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} мин. назад`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} ч. назад`;
    return new Intl.DateTimeFormat("ru", { day: "numeric", month: "short" }).format(new Date(time));
  }

  function render() {
    if (!state.vault) return;
    const entries = state.vault.entries;
    const groups = groupsForVault();
    const weakCount = entries.filter((entry) => passwordScore(entry.password) < 3).length;
    const health = entries.length ? Math.round(((entries.length - weakCount) / entries.length) * 100) : null;
    $("#sidebar-vault-name").textContent = state.vault.name;
    $("#nav-count").textContent = String(entries.length);
    $("#metric-total").textContent = String(entries.length).padStart(2, "0");
    $("#metric-groups").textContent = String(groups.size).padStart(2, "0");
    $("#metric-health").textContent = health === null ? "—" : `${health}%`;
    $("#metric-health-copy").textContent = health === null ? "добавьте записи" : health >= 80 ? "отличная защита" : "проверьте слабые";
    $("#all-tab-count").textContent = String(entries.length);
    $("#fav-tab-count").textContent = String(entries.filter((entry) => entry.favorite).length);
    $("#weak-tab-count").textContent = String(weakCount);
    $("#last-updated").textContent = `Обновлено ${formatRelativeTime(state.vault.updatedAt)}`;
    renderGroups(groups);
    renderEntries();
    if ($("#schema-view").classList.contains("is-active")) renderGraph();
  }

  function renderGroups(groups) {
    els.groupList.replaceChildren();
    if (!groups.size) {
      const empty = document.createElement("p");
      empty.className = "group-empty";
      empty.textContent = "Группы появятся, когда username будет email‑адресом.";
      els.groupList.append(empty);
      return;
    }
    groups.forEach((entries, email) => {
      const button = document.createElement("button");
      button.className = `group-item${state.selectedGroup === email ? " is-active" : ""}`;
      button.dataset.group = email;
      button.innerHTML = `<span class="group-avatar" style="--group-color:${hashColor(email)}">${escapeHtml(email[0].toUpperCase())}</span><strong>${escapeHtml(email)}</strong><em>${entries.length}</em>`;
      els.groupList.append(button);
    });
  }

  function filteredEntries() {
    const query = els.search.value.trim().toLowerCase();
    return state.vault.entries.filter((entry) => {
      if (state.selectedGroup && emailGroup(entry) !== state.selectedGroup) return false;
      if (state.selectedFilter === "favorites" && !entry.favorite) return false;
      if (state.selectedFilter === "weak" && passwordScore(entry.password) >= 3) return false;
      if (query && ![entry.title, entry.url, entry.username, entry.phone].some((value) => value.toLowerCase().includes(query))) return false;
      return true;
    });
  }

  function renderEntries() {
    const entries = filteredEntries();
    els.entriesGrid.className = `entries-grid${state.layout === "list" ? " list" : ""}`;
    els.entriesGrid.replaceChildren();
    $("#result-count").textContent = pluralEntries(entries.length);
    els.emptyState.classList.toggle("is-active", entries.length === 0);
    if (!entries.length) {
      $("#empty-state h2").textContent = state.vault.entries.length ? "Ничего не найдено" : "Сейф пока пуст";
      $("#empty-state p").textContent = state.vault.entries.length
        ? "Измените поиск, фильтр или выбранную email‑группу."
        : "Добавьте первый сайт — запись сразу попадёт в подходящую email‑группу.";
      $("#empty-add-btn").style.display = state.vault.entries.length ? "none" : "inline-flex";
      return;
    }
    entries.forEach((entry) => {
      const card = document.createElement("article");
      card.className = "entry-card";
      card.dataset.id = entry.id;
      const group = emailGroup(entry);
      const score = passwordScore(entry.password);
      const strengthClass = score >= 3 ? "strong" : "weak";
      const strengthLabel = score >= 3 ? "НАДЁЖНЫЙ" : "ПРОВЕРИТЬ";
      const host = safeHostname(entry.url);
      const initial = entry.title.trim().slice(0, 2).toUpperCase();
      card.innerHTML = `
        <div class="entry-head">
          <button class="site-icon" style="--site-color:${hashColor(entry.title)}" data-action="open-url" title="Открыть сайт">${escapeHtml(initial)}</button>
          <div class="entry-title"><strong>${escapeHtml(entry.title)}</strong><small>${escapeHtml(host)}</small></div>
          <div class="entry-actions">
            <button class="card-btn favorite${entry.favorite ? " is-active" : ""}" data-action="favorite" aria-label="Избранное">${entry.favorite ? "★" : "☆"}</button>
            <button class="card-btn" data-action="edit" aria-label="Редактировать">•••</button>
          </div>
        </div>
        <div class="credential-row"><span class="credential-value">${escapeHtml(entry.username)}</span><button class="copy-btn" data-action="copy-username" aria-label="Копировать логин">▣</button></div>
        <div class="credential-row"><span class="credential-value password-dots" data-password-display>••••••••••••</span><span><button class="copy-btn" data-action="reveal-password" aria-label="Показать пароль">◉</button><button class="copy-btn" data-action="copy-password" aria-label="Копировать пароль">▣</button></span></div>
        ${entry.phone ? `<div class="credential-row"><span class="credential-value">${escapeHtml(entry.phone)}</span><button class="copy-btn" data-action="copy-phone" aria-label="Копировать телефон">▣</button></div>` : ""}
        <div class="entry-footer"><span class="group-chip">${escapeHtml(group || "Без email‑группы")}</span><span class="strength-badge ${strengthClass}">${strengthLabel}</span></div>`;
      els.entriesGrid.append(card);
    });
  }

  async function saveVault() {
    if (!state.vault || !state.key || !state.salt) return;
    const button = $("#save-vault-btn");
    const oldHtml = button.innerHTML;
    button.disabled = true;
    button.textContent = "Шифрование…";
    try {
      state.vault.updatedAt = new Date().toISOString();
      const bytes = await encryptVault(state.vault, state.key, state.salt);
      const blob = new Blob([bytes], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = state.fileName || `${fileSafeName(state.vault.name)}.pgd`;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      state.fileName = anchor.download;
      setDirty(false);
      render();
      showToast("Зашифрованный файл .pgd сохранён");
    } catch (error) {
      console.error(error);
      showToast("Не удалось сохранить файл", "error");
    } finally {
      button.disabled = false;
      button.innerHTML = oldHtml;
    }
  }

  function fileSafeName(value) {
    return value.trim().replace(/[\\/:*?"<>|]+/g, "-").replace(/\s+/g, "-").slice(0, 60) || "person-guard";
  }

  function enterVault() {
    state.selectedFilter = "all";
    state.selectedGroup = null;
    els.search.value = "";
    showScreen(els.app);
    switchView("vault");
    setDirty(state.dirty);
    render();
    resetInactivityTimer();
  }

  function clearVaultFromMemory() {
    state.vault = null;
    state.key = null;
    if (state.salt) state.salt.fill(0);
    state.salt = null;
    state.fileName = null;
    state.pendingFile = null;
    state.dirty = false;
    state.revealedTimers.forEach((timer) => clearTimeout(timer));
    state.revealedTimers.clear();
    clearTimeout(state.inactivityTimer);
    els.entriesGrid.replaceChildren();
    $("#vault-graph").replaceChildren();
  }

  function lockVault() {
    const hadDirty = state.dirty;
    clearVaultFromMemory();
    if (getAppLock()) {
      $("#app-unlock-password").value = "";
      $("#app-unlock-error").textContent = "";
      showScreen(els.appLockScreen);
      window.setTimeout(() => $("#app-unlock-password").focus(), 30);
    } else {
      showScreen(els.welcome);
    }
    if (hadDirty) showToast("Сейф закрыт. Несохранённые изменения удалены из памяти.", "error");
  }

  function openEntryDialog(entry = null) {
    $("#entry-form").reset();
    $("#entry-error").textContent = "";
    $("#entry-id").value = entry?.id || "";
    $("#entry-title").value = entry?.title || "";
    $("#entry-url").value = entry?.url || "";
    $("#entry-username").value = entry?.username || "";
    $("#entry-password").value = entry?.password || "";
    $("#entry-phone").value = entry?.phone || "";
    $("#entry-favorite").checked = Boolean(entry?.favorite);
    $("#entry-dialog-title").textContent = entry ? "Изменить запись" : "Добавить пароль";
    $("#delete-entry-btn").style.visibility = entry ? "visible" : "hidden";
    updateStrength($("#entry-password"), $("#entry-dialog .strength"), $("#entry-strength-label"));
    els.entryDialog.showModal();
    window.setTimeout(() => $("#entry-title").focus(), 40);
  }

  function normalizeUrl(value) {
    const trimmed = value.trim();
    if (!trimmed) return "";
    const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    try {
      const url = new URL(candidate);
      if (!["http:", "https:"].includes(url.protocol)) return "";
      return url.href;
    } catch {
      return "";
    }
  }

  function switchView(view) {
    $$(".nav-item").forEach((item) => item.classList.toggle("is-active", item.dataset.view === view));
    $$(".view").forEach((item) => item.classList.toggle("is-active", item.id === `${view}-view`));
    const meta = {
      vault: [state.selectedGroup || "Все пароли", "ХРАНИЛИЩЕ"],
      schema: ["Схема связей", "КАРТА"],
      security: ["Безопасность", "НАСТРОЙКИ"],
    }[view];
    $("#page-title").textContent = meta[0];
    $("#breadcrumb").textContent = meta[1];
    $("#search-wrap").style.display = view === "vault" ? "flex" : "none";
    $("#add-entry-btn").style.display = view === "security" ? "none" : "inline-flex";
    if (view === "schema") window.setTimeout(renderGraph, 20);
    $("#sidebar").classList.remove("is-open");
  }

  function graphGroups() {
    const map = groupsForVault();
    const other = state.vault.entries.filter((entry) => !emailGroup(entry));
    const result = [...map.entries()].map(([name, entries]) => ({ name, entries, type: "email" }));
    if (other.length) result.push({ name: "Другие записи", entries: other, type: "other" });
    return result;
  }

  function addSvg(parent, tag, attributes = {}, text = "") {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, String(value)));
    if (text) node.textContent = text;
    parent.append(node);
    return node;
  }

  function truncate(value, max) {
    return value.length > max ? `${value.slice(0, max - 1)}…` : value;
  }

  function renderGraph() {
    if (!state.vault) return;
    const svg = $("#vault-graph");
    const groups = graphGroups();
    svg.replaceChildren();
    $("#graph-empty").classList.toggle("is-active", groups.length === 0);
    if (!groups.length) return;
    svg.setAttribute("viewBox", "0 0 800 520");
    const cx = 400;
    const cy = groups.length === 1 ? 380 : 270;
    const root = addSvg(svg, "g", { transform: `translate(${cx} ${cy}) scale(${state.graphZoom}) translate(${-cx} ${-cy})` });
    const orbitX = groups.length === 1 ? 0 : 220;
    const orbitY = groups.length === 1 ? 170 : 155;
    const positions = groups.map((group, index) => {
      const angle = groups.length === 1
        ? -Math.PI / 2
        : groups.length === 2
          ? index * Math.PI
          : -Math.PI / 2 + (index * Math.PI * 2) / groups.length;
      return { ...group, x: cx + Math.cos(angle) * orbitX, y: cy + Math.sin(angle) * orbitY };
    });
    positions.forEach((group) => addSvg(root, "line", { x1: cx, y1: cy, x2: group.x, y2: group.y, class: "graph-line" }));
    positions.forEach((group, groupIndex) => {
      const maxNodes = Math.min(group.entries.length, 10);
      const radius = Math.min(115, 70 + maxNodes * 4);
      group.entries.slice(0, maxNodes).forEach((entry, index) => {
        const angle = -Math.PI / 2 + (index * Math.PI * 2) / maxNodes + groupIndex * .25;
        const x = group.x + Math.cos(angle) * radius;
        const y = group.y + Math.sin(angle) * radius;
        addSvg(root, "line", { x1: group.x, y1: group.y, x2: x, y2: y, class: "graph-line" });
        addSvg(root, "circle", { cx: x, cy: y, r: 15, class: "graph-site-node" });
        addSvg(root, "text", { x, y: y + 3.5, "text-anchor": "middle", class: "graph-label" }, entry.title.slice(0, 1).toUpperCase());
        addSvg(root, "text", { x, y: y + 31, "text-anchor": "middle", class: "graph-sublabel" }, truncate(entry.title, 15));
      });
      addSvg(root, "circle", { cx: group.x, cy: group.y, r: 38, class: "graph-group-halo" });
      addSvg(root, "circle", { cx: group.x, cy: group.y, r: 23, class: "graph-group-node" });
      addSvg(root, "text", { x: group.x, y: group.y + 4, "text-anchor": "middle", class: "graph-label" }, group.type === "email" ? "@" : "◇");
      addSvg(root, "text", { x: group.x, y: group.y + 52, "text-anchor": "middle", class: "graph-label" }, truncate(group.name, 24));
      addSvg(root, "text", { x: group.x, y: group.y + 66, "text-anchor": "middle", class: "graph-sublabel" }, pluralEntries(group.entries.length));
    });
    addSvg(root, "circle", { cx, cy, r: 55, fill: "rgba(86,125,255,.07)", stroke: "rgba(86,125,255,.13)" });
    addSvg(root, "circle", { cx, cy, r: 32, fill: "#111d39", stroke: "#5f82f5", "stroke-width": 2 });
    addSvg(root, "text", { x: cx, y: cy + 5, "text-anchor": "middle", class: "graph-label", "font-size": 16 }, "PG");
    addSvg(root, "text", { x: cx, y: cy + 78, "text-anchor": "middle", class: "graph-label" }, truncate(state.vault.name, 22));
    $("#graph-zoom").textContent = `${Math.round(state.graphZoom * 100)}%`;
  }

  function secureRandomIndex(max) {
    const ceiling = Math.floor(0x100000000 / max) * max;
    const value = new Uint32Array(1);
    do crypto.getRandomValues(value); while (value[0] >= ceiling);
    return value[0] % max;
  }

  function generatePassword(length = 24) {
    const sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%&*+-_=?:"];
    const all = sets.join("");
    const chars = sets.map((set) => set[secureRandomIndex(set.length)]);
    while (chars.length < length) chars.push(all[secureRandomIndex(all.length)]);
    for (let i = chars.length - 1; i > 0; i -= 1) {
      const j = secureRandomIndex(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

  async function copySecret(value, label) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(`${label} скопирован. Буфер очистится через 30 секунд.`);
      window.setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30_000);
    } catch {
      showToast("Браузер не разрешил доступ к буферу обмена", "error");
    }
  }

  function getEntry(id) {
    return state.vault?.entries.find((entry) => entry.id === id);
  }

  async function deriveAppHash(password, salt) {
    const material = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: APP_KDF_ITERATIONS, hash: "SHA-256" },
      material,
      256,
    ));
  }

  function getAppLock() {
    try {
      const parsed = JSON.parse(localStorage.getItem("pg_app_lock_v1"));
      if (!parsed?.salt || !parsed?.hash || parsed.iterations !== APP_KDF_ITERATIONS) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  function autolockMinutes() {
    const value = Number(localStorage.getItem("pg_autolock_minutes") ?? "3");
    return [0, 1, 3, 5, 15].includes(value) ? value : 3;
  }

  function resetInactivityTimer() {
    clearTimeout(state.inactivityTimer);
    if (!state.vault) return;
    const minutes = autolockMinutes();
    if (!minutes) return;
    state.inactivityTimer = window.setTimeout(lockVault, minutes * 60_000);
  }

  async function setupAppPassword(password) {
    const salt = randomBytes(16);
    const hash = await deriveAppHash(password, salt);
    localStorage.setItem("pg_app_lock_v1", JSON.stringify({
      version: 1,
      iterations: APP_KDF_ITERATIONS,
      salt: bytesToBase64(salt),
      hash: bytesToBase64(hash),
    }));
    salt.fill(0);
    hash.fill(0);
  }

  function bindEvents() {
    $("#create-vault-btn").addEventListener("click", () => {
      $("#create-vault-form").reset();
      $("#vault-name-input").value = "Мои пароли";
      $("#create-error").textContent = "";
      $("#create-dialog .strength").dataset.score = "0";
      $("#strength-label").textContent = "Минимум 12 символов";
      els.createDialog.showModal();
    });
    $("#open-vault-btn").addEventListener("click", () => els.fileInput.click());
    els.fileInput.addEventListener("change", async () => {
      const file = els.fileInput.files?.[0];
      els.fileInput.value = "";
      if (!file) return;
      if (file.size > MAX_FILE_SIZE) return showToast("Файл превышает безопасный лимит 25 МБ", "error");
      state.pendingFile = { name: file.name, size: file.size, buffer: await file.arrayBuffer() };
      $("#pending-file-name").textContent = file.name;
      $("#pending-file-size").textContent = `${Math.max(1, Math.round(file.size / 1024))} КБ · зашифрованный контейнер`;
      $("#unlock-password-input").value = "";
      $("#unlock-error").textContent = "";
      els.unlockDialog.showModal();
      window.setTimeout(() => $("#unlock-password-input").focus(), 40);
    });

    $$(".modal-close, .modal-actions .btn[value='cancel']").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        button.closest("dialog").close();
      });
    });
    $("#master-password-input").addEventListener("input", (event) => {
      updateStrength(event.target, $("#create-dialog .strength"), $("#strength-label"), true);
    });
    $("#entry-password").addEventListener("input", (event) => {
      updateStrength(event.target, $("#entry-dialog .strength"), $("#entry-strength-label"));
    });
    $$('[data-reveal]').forEach((button) => button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.reveal);
      input.type = input.type === "password" ? "text" : "password";
      button.textContent = input.type === "password" ? "○" : "◉";
    }));

    $("#create-vault-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const passwordInput = $("#master-password-input");
      const password = passwordInput.value;
      const confirm = $("#master-confirm-input").value;
      const error = $("#create-error");
      error.textContent = "";
      if (password.length < 12) return void (error.textContent = "Мастер‑пароль должен содержать минимум 12 символов.");
      if (password !== confirm) return void (error.textContent = "Пароли не совпадают.");
      const submit = event.submitter;
      submit.disabled = true;
      submit.textContent = "Создание ключа…";
      try {
        const salt = randomBytes(16);
        const key = await deriveVaultKey(password, salt);
        const now = new Date().toISOString();
        state.vault = {
          schemaVersion: 1,
          vaultId: crypto.randomUUID(),
          name: $("#vault-name-input").value.trim() || "Мои пароли",
          createdAt: now,
          updatedAt: now,
          entries: [],
        };
        state.key = key;
        state.salt = salt;
        state.fileName = `${fileSafeName(state.vault.name)}.pgd`;
        state.dirty = true;
        passwordInput.value = "";
        $("#master-confirm-input").value = "";
        els.createDialog.close();
        enterVault();
        await saveVault();
      } catch (err) {
        console.error(err);
        error.textContent = "Не удалось создать криптографический ключ.";
      } finally {
        submit.disabled = false;
        submit.textContent = "Создать и сохранить .pgd";
      }
    });

    $("#unlock-vault-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!state.pendingFile) return;
      const passwordInput = $("#unlock-password-input");
      const error = $("#unlock-error");
      const submit = event.submitter;
      error.textContent = "";
      submit.disabled = true;
      submit.textContent = "Расшифровка…";
      try {
        const result = await decryptVault(state.pendingFile.buffer, passwordInput.value);
        state.vault = result.vault;
        state.key = result.key;
        state.salt = result.salt;
        state.fileName = state.pendingFile.name.toLowerCase().endsWith(".pgd") ? state.pendingFile.name : `${state.pendingFile.name}.pgd`;
        state.pendingFile = null;
        state.dirty = false;
        passwordInput.value = "";
        els.unlockDialog.close();
        enterVault();
        showToast("Хранилище успешно расшифровано");
      } catch (err) {
        error.textContent = err.message || "Не удалось открыть файл.";
        passwordInput.select();
      } finally {
        submit.disabled = false;
        submit.textContent = "Расшифровать";
      }
    });

    $("#add-entry-btn").addEventListener("click", () => openEntryDialog());
    $("#empty-add-btn").addEventListener("click", () => openEntryDialog());
    $("#entry-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const error = $("#entry-error");
      const title = $("#entry-title").value.trim();
      const username = $("#entry-username").value.trim();
      const password = $("#entry-password").value;
      const rawUrl = $("#entry-url").value;
      const url = normalizeUrl(rawUrl);
      if (!title || !username || !password) return void (error.textContent = "Заполните название, username и пароль.");
      if (rawUrl.trim() && !url) return void (error.textContent = "Введите корректную ссылку сайта.");
      const id = $("#entry-id").value;
      const now = new Date().toISOString();
      const existing = id ? getEntry(id) : null;
      const entry = {
        id: existing?.id || crypto.randomUUID(),
        title,
        url,
        username,
        password,
        phone: $("#entry-phone").value.trim(),
        favorite: $("#entry-favorite").checked,
        createdAt: existing?.createdAt || now,
        updatedAt: now,
      };
      if (existing) state.vault.entries.splice(state.vault.entries.indexOf(existing), 1, entry);
      else state.vault.entries.unshift(entry);
      state.vault.updatedAt = now;
      setDirty(true);
      els.entryDialog.close();
      render();
      showToast(existing ? "Запись обновлена" : "Пароль добавлен в сейф");
    });
    $("#generate-password-btn").addEventListener("click", () => {
      const input = $("#entry-password");
      input.value = generatePassword();
      input.type = "text";
      updateStrength(input, $("#entry-dialog .strength"), $("#entry-strength-label"));
      showToast("Сгенерирован пароль из 24 символов");
    });

    $("#delete-entry-btn").addEventListener("click", () => els.deleteDialog.showModal());
    $("#delete-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const entry = getEntry($("#entry-id").value);
      if (entry) state.vault.entries.splice(state.vault.entries.indexOf(entry), 1);
      state.vault.updatedAt = new Date().toISOString();
      setDirty(true);
      els.deleteDialog.close();
      els.entryDialog.close();
      render();
      showToast("Запись удалена");
    });

    els.entriesGrid.addEventListener("click", async (event) => {
      const actionButton = event.target.closest("[data-action]");
      const card = event.target.closest(".entry-card");
      if (!actionButton || !card) return;
      const entry = getEntry(card.dataset.id);
      if (!entry) return;
      const action = actionButton.dataset.action;
      if (action === "edit") openEntryDialog(entry);
      if (action === "favorite") {
        entry.favorite = !entry.favorite;
        entry.updatedAt = new Date().toISOString();
        state.vault.updatedAt = entry.updatedAt;
        setDirty(true);
        render();
      }
      if (action === "copy-username") await copySecret(entry.username, "Username");
      if (action === "copy-password") await copySecret(entry.password, "Пароль");
      if (action === "copy-phone") await copySecret(entry.phone, "Телефон");
      if (action === "reveal-password") {
        const display = card.querySelector("[data-password-display]");
        clearTimeout(state.revealedTimers.get(entry.id));
        display.textContent = entry.password;
        display.classList.remove("password-dots");
        const timer = window.setTimeout(() => {
          display.textContent = "••••••••••••";
          display.classList.add("password-dots");
          state.revealedTimers.delete(entry.id);
        }, 5000);
        state.revealedTimers.set(entry.id, timer);
      }
      if (action === "open-url" && entry.url) {
        const url = normalizeUrl(entry.url);
        if (url) window.open(url, "_blank", "noopener,noreferrer");
      }
    });

    $$(".nav-item").forEach((item) => item.addEventListener("click", () => switchView(item.dataset.view)));
    els.groupList.addEventListener("click", (event) => {
      const item = event.target.closest("[data-group]");
      if (!item) return;
      state.selectedGroup = state.selectedGroup === item.dataset.group ? null : item.dataset.group;
      state.selectedFilter = "all";
      $$(".tab").forEach((tab) => tab.classList.toggle("is-active", tab.dataset.filter === "all"));
      switchView("vault");
      $("#page-title").textContent = state.selectedGroup || "Все пароли";
      render();
    });
    $$(".tab").forEach((tab) => tab.addEventListener("click", () => {
      state.selectedFilter = tab.dataset.filter;
      state.selectedGroup = null;
      $$(".tab").forEach((button) => button.classList.toggle("is-active", button === tab));
      render();
    }));
    $$(".view-toggle").forEach((button) => button.addEventListener("click", () => {
      state.layout = button.dataset.layout;
      $$(".view-toggle").forEach((item) => item.classList.toggle("is-active", item === button));
      renderEntries();
    }));
    els.search.addEventListener("input", renderEntries);
    $("#save-vault-btn").addEventListener("click", saveVault);
    $("#lock-vault-btn").addEventListener("click", lockVault);
    $("#open-sidebar-btn").addEventListener("click", () => $("#sidebar").classList.add("is-open"));
    $("#close-sidebar-btn").addEventListener("click", () => $("#sidebar").classList.remove("is-open"));
    $("#graph-minus").addEventListener("click", () => { state.graphZoom = Math.max(.65, state.graphZoom - .1); renderGraph(); });
    $("#graph-plus").addEventListener("click", () => { state.graphZoom = Math.min(1.6, state.graphZoom + .1); renderGraph(); });
    $("#graph-reset").addEventListener("click", () => { state.graphZoom = 1; renderGraph(); });

    $("#autolock-select").value = String(autolockMinutes());
    $("#autolock-select").addEventListener("change", (event) => {
      localStorage.setItem("pg_autolock_minutes", event.target.value);
      resetInactivityTimer();
      showToast(event.target.value === "0" ? "Автоблокировка выключена" : `Автоблокировка: ${event.target.options[event.target.selectedIndex].text}`);
    });
    $("#configure-app-lock-btn").addEventListener("click", () => {
      $("#app-lock-form").reset();
      $("#app-lock-error").textContent = "";
      $("#remove-app-lock-btn").style.visibility = getAppLock() ? "visible" : "hidden";
      els.appLockDialog.showModal();
    });
    $("#app-lock-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const password = $("#new-app-password").value;
      const confirm = $("#confirm-app-password").value;
      const error = $("#app-lock-error");
      if (password.length < 8) return void (error.textContent = "Используйте минимум 8 символов.");
      if (password !== confirm) return void (error.textContent = "Пароли не совпадают.");
      event.submitter.disabled = true;
      try {
        await setupAppPassword(password);
        els.appLockDialog.close();
        showToast("Локальная защита приложения включена");
      } catch {
        error.textContent = "Не удалось настроить пароль приложения.";
      } finally {
        event.submitter.disabled = false;
      }
    });
    $("#remove-app-lock-btn").addEventListener("click", () => {
      localStorage.removeItem("pg_app_lock_v1");
      els.appLockDialog.close();
      showToast("Локальный пароль приложения удалён");
    });
    $("#app-unlock-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const config = getAppLock();
      if (!config) return showScreen(els.welcome);
      const submit = event.submitter;
      const error = $("#app-unlock-error");
      error.textContent = "";
      submit.disabled = true;
      try {
        const actual = await deriveAppHash($("#app-unlock-password").value, base64ToBytes(config.salt));
        const valid = equalBytes(actual, base64ToBytes(config.hash));
        actual.fill(0);
        if (!valid) {
          error.textContent = "Неверный пароль приложения.";
          $("#app-unlock-password").select();
          return;
        }
        $("#app-unlock-password").value = "";
        showScreen(els.welcome);
      } catch {
        error.textContent = "Не удалось проверить пароль.";
      } finally {
        submit.disabled = false;
      }
    });

    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k" && state.vault) {
        event.preventDefault();
        switchView("vault");
        els.search.focus();
      }
      resetInactivityTimer();
    });
    ["pointerdown", "mousemove", "touchstart"].forEach((name) => document.addEventListener(name, resetInactivityTimer, { passive: true }));
    window.addEventListener("beforeunload", (event) => {
      if (!state.vault || !state.dirty) return;
      event.preventDefault();
      event.returnValue = "";
    });
  }

  function registerWebMcpTools() {
    const context = document.modelContext;
    if (!context?.registerTool) return;
    const tools = [
      {
        name: "read_vault_summary",
        title: "Сводка сейфа",
        description: "Показывает только количество записей и email-групп без логинов и паролей.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
        annotations: { readOnlyHint: true, untrustedContentHint: false },
        execute() {
          return state.vault
            ? { locked: false, entries: state.vault.entries.length, emailGroups: groupsForVault().size, unsavedChanges: state.dirty }
            : { locked: true, entries: 0, emailGroups: 0, unsavedChanges: false };
        },
      },
      {
        name: "start_password_creation",
        title: "Добавить пароль",
        description: "Открывает защищённую форму добавления записи; данные вводит и подтверждает пользователь.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
        annotations: { readOnlyHint: false, untrustedContentHint: false },
        execute() {
          if (!state.vault) throw new Error("Сначала пользователь должен открыть .pgd-хранилище.");
          switchView("vault");
          openEntryDialog();
          return { status: "form_opened" };
        },
      },
    ];
    tools.forEach((tool) => {
      try { void Promise.resolve(context.registerTool(tool)).catch(() => {}); } catch { /* Browser API is optional. */ }
    });
  }

  function init() {
    if (!window.crypto?.subtle) {
      document.body.innerHTML = '<main style="max-width:560px;margin:15vh auto;padding:30px;color:white;font-family:system-ui"><h1>Нужен современный браузер</h1><p>Web Crypto недоступен. Откройте PersonGuard через localhost или HTTPS в актуальной версии браузера.</p></main>';
      return;
    }
    bindEvents();
    registerWebMcpTools();
    if (getAppLock()) showScreen(els.appLockScreen);
    else showScreen(els.welcome);
  }

  init();
})();
