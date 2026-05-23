import { analyzePassword, generateAlternatives, generatePassphrase, passwordToStorageLabel } from "./analyzer.js";

const STORAGE_KEY = "password-strength-analyzer.history.v1";

const elements = {
  input: document.querySelector("#password-input"),
  toggleVisibility: document.querySelector("#toggle-visibility"),
  remember: document.querySelector("#remember-password"),
  generate: document.querySelector("#generate-password"),
  clearHistory: document.querySelector("#clear-history"),
  scoreTitle: document.querySelector("#score-title"),
  scoreValue: document.querySelector("#score-value"),
  scoreSummary: document.querySelector("#score-summary"),
  meterFill: document.querySelector("#meter-fill"),
  checkList: document.querySelector("#check-list"),
  suggestionList: document.querySelector("#suggestion-list"),
  historyCount: document.querySelector("#history-count"),
  alternatives: document.querySelector("#alternative-list")
};

let reuseDetected = false;
let analysisRun = 0;

initialize();

function initialize() {
  elements.input.addEventListener("input", refreshAnalysis);
  elements.toggleVisibility.addEventListener("click", togglePasswordVisibility);
  elements.remember.addEventListener("click", rememberPasswordHash);
  elements.generate.addEventListener("click", generatePassword);
  elements.clearHistory.addEventListener("click", clearHistory);

  renderAlternatives(generateAlternatives());
  refreshHistoryCount();
  refreshAnalysis();
}

async function refreshAnalysis() {
  const run = (analysisRun += 1);
  const password = elements.input.value;
  reuseDetected = password ? await hasPasswordBeenStored(password) : false;
  if (run !== analysisRun) return;

  const result = analyzePassword(password, { reused: reuseDetected });

  elements.scoreTitle.textContent = result.label;
  elements.scoreValue.textContent = String(result.score);
  elements.scoreSummary.textContent = result.summary;
  elements.meterFill.style.width = `${result.score}%`;
  elements.meterFill.style.backgroundColor = scoreColor(result.score);
  elements.scoreValue.style.backgroundColor = scoreColor(result.score);
  elements.remember.disabled = !password || reuseDetected;

  renderChecks(result.checks);
  renderSuggestions(result.suggestions);
}

function renderChecks(checks) {
  elements.checkList.replaceChildren(
    ...checks.map((check) => {
      const item = document.createElement("li");
      const marker = document.createElement("span");
      const label = document.createElement("span");

      marker.className = `status-dot ${check.status}`;
      marker.textContent = check.status === "pass" ? "✓" : check.status === "warn" ? "!" : "×";
      label.textContent = check.label;

      item.append(marker, label);
      return item;
    })
  );
}

function renderSuggestions(suggestions) {
  elements.suggestionList.replaceChildren(
    ...suggestions.map((suggestion) => {
      const item = document.createElement("li");
      const marker = document.createElement("span");
      const label = document.createElement("span");

      marker.className = "suggestion-marker";
      label.textContent = suggestion;

      item.append(marker, label);
      return item;
    })
  );
}

function renderAlternatives(passwords) {
  elements.alternatives.replaceChildren(
    ...passwords.map((password) => {
      const item = document.createElement("div");
      const code = document.createElement("code");
      const copy = document.createElement("button");

      item.className = "alternative";
      code.textContent = password;
      copy.className = "copy-button";
      copy.type = "button";
      copy.textContent = "Use";
      copy.addEventListener("click", () => {
        elements.input.value = password;
        elements.input.focus();
        refreshAnalysis();
      });

      item.append(code, copy);
      return item;
    })
  );
}

function togglePasswordVisibility() {
  const showing = elements.input.type === "text";
  elements.input.type = showing ? "password" : "text";
  elements.toggleVisibility.classList.toggle("is-hidden", !showing);
  elements.toggleVisibility.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  elements.toggleVisibility.setAttribute("title", showing ? "Show password" : "Hide password");
}

function generatePassword() {
  elements.input.value = generatePassphrase();
  renderAlternatives(generateAlternatives());
  refreshAnalysis();
  elements.input.focus();
}

async function rememberPasswordHash() {
  const password = elements.input.value;
  if (!password) return;

  const history = readHistory();
  const salt = randomSalt();
  const hash = await sha256(`${salt}:${password}`);
  history.push({
    salt,
    hash,
    label: passwordToStorageLabel(password),
    createdAt: new Date().toISOString()
  });
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(-30)));
  refreshHistoryCount();
  await refreshAnalysis();
}

function clearHistory() {
  localStorage.removeItem(STORAGE_KEY);
  refreshHistoryCount();
  refreshAnalysis();
}

async function hasPasswordBeenStored(password) {
  const history = readHistory();
  for (const entry of history) {
    const hash = await sha256(`${entry.salt}:${password}`);
    if (hash === entry.hash) {
      return true;
    }
  }
  return false;
}

function readHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed.filter(isHistoryEntry) : [];
  } catch {
    return [];
  }
}

function isHistoryEntry(entry) {
  return typeof entry?.salt === "string" && typeof entry?.hash === "string";
}

function refreshHistoryCount() {
  elements.historyCount.textContent = String(readHistory().length);
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function randomSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function scoreColor(score) {
  if (score >= 80) return "#168a50";
  if (score >= 60) return "#2c6fbb";
  if (score >= 40) return "#ba7a13";
  return "#c24135";
}
