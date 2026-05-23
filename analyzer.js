const COMMON_PASSWORDS = new Set([
  "123456",
  "123456789",
  "qwerty",
  "password",
  "password1",
  "admin",
  "letmein",
  "welcome",
  "iloveyou",
  "monkey",
  "dragon",
  "football",
  "baseball",
  "abc123",
  "111111",
  "000000"
]);

const COMMON_FRAGMENTS = [
  "password",
  "qwerty",
  "admin",
  "welcome",
  "letmein",
  "login",
  "user",
  "secret",
  "company",
  "summer",
  "winter",
  "spring",
  "autumn",
  "birthday"
];

const SEQUENCES = [
  "abcdefghijklmnopqrstuvwxyz",
  "zyxwvutsrqponmlkjihgfedcba",
  "0123456789",
  "9876543210",
  "qwertyuiop",
  "poiuytrewq",
  "asdfghjkl",
  "lkjhgfdsa",
  "zxcvbnm",
  "mnbvcxz"
];

const CHECK_LABELS = {
  length: "At least 12 characters",
  longLength: "16 or more characters",
  variety: "Uses three or more character types",
  noCommon: "Not a common password",
  noSequence: "Avoids obvious sequences",
  noRepeat: "Avoids heavy repetition",
  unique: "No local reuse detected"
};

export function analyzePassword(password, options = {}) {
  const reused = Boolean(options.reused);
  const value = String(password || "");
  const lower = value.toLowerCase();
  const length = value.length;
  const categories = getCategoryList(value);
  const entropy = estimateEntropy(value);
  const common = COMMON_PASSWORDS.has(lower) || COMMON_FRAGMENTS.some((fragment) => lower.includes(fragment));
  const sequence = hasSequence(lower);
  const repeated = hasHeavyRepetition(value);
  const yearOrDate = hasDatePattern(value);

  const checks = [
    makeCheck("length", length >= 12),
    makeCheck("longLength", length >= 16, length >= 12),
    makeCheck("variety", categories.length >= 3),
    makeCheck("noCommon", !common),
    makeCheck("noSequence", !sequence && !yearOrDate, !sequence),
    makeCheck("noRepeat", !repeated),
    makeCheck("unique", !reused)
  ];

  let score = 0;
  score += Math.min(length * 3, 36);
  score += Math.min(categories.length * 11, 40);
  score += Math.min(Math.floor(entropy / 3), 24);
  if (length >= 16) score += 8;
  if (categories.length === 4) score += 6;
  if (length === 0) score = 0;
  if (length > 0 && length < 8) score -= 18;
  if (common) score -= 34;
  if (sequence) score -= 18;
  if (repeated) score -= 16;
  if (yearOrDate) score -= 8;
  if (reused) score -= 32;
  score = clamp(score, 0, 100);

  const label = getStrengthLabel(score, length);
  const suggestions = buildSuggestions({
    length,
    categories,
    common,
    sequence,
    repeated,
    yearOrDate,
    reused,
    score
  });

  return {
    score,
    label,
    entropy: Math.round(entropy),
    checks,
    suggestions,
    categories,
    summary: makeSummary(label, score, entropy, reused)
  };
}

export function generatePassphrase(wordCount = 4) {
  const words = [
    "cedar",
    "harbor",
    "mosaic",
    "orbit",
    "lantern",
    "quartz",
    "river",
    "signal",
    "velvet",
    "canyon",
    "meadow",
    "fable",
    "silver",
    "anchor",
    "ember",
    "pixel",
    "tempo",
    "summit",
    "garden",
    "ripple",
    "atlas",
    "breeze",
    "copper",
    "novel"
  ];
  const separators = ["-", ".", "_"];
  const separator = pick(separators);
  const chosen = [];

  while (chosen.length < wordCount) {
    const word = pick(words);
    if (!chosen.includes(word)) {
      chosen.push(word);
    }
  }

  const number = String(randomInt(10, 99));
  const symbol = pick(["!", "#", "%", "+", "?"]);
  return `${chosen.join(separator)}${separator}${number}${symbol}`;
}

export function generateAlternatives(count = 3) {
  return Array.from({ length: count }, () => generatePassphrase(4));
}

export function passwordToStorageLabel(password) {
  const length = String(password || "").length;
  return `${length} chars`;
}

function makeCheck(id, passed, partial = false) {
  return {
    id,
    label: CHECK_LABELS[id],
    status: passed ? "pass" : partial ? "warn" : "fail"
  };
}

function getCategoryList(value) {
  const categories = [];
  if (/[a-z]/.test(value)) categories.push("lowercase");
  if (/[A-Z]/.test(value)) categories.push("uppercase");
  if (/\d/.test(value)) categories.push("numbers");
  if (/[^A-Za-z0-9]/.test(value)) categories.push("symbols");
  return categories;
}

function estimateEntropy(value) {
  if (!value) return 0;
  let pool = 0;
  if (/[a-z]/.test(value)) pool += 26;
  if (/[A-Z]/.test(value)) pool += 26;
  if (/\d/.test(value)) pool += 10;
  if (/[^A-Za-z0-9]/.test(value)) pool += 33;

  const base = Math.log2(Math.max(pool, 1)) * value.length;
  const uniqueRatio = new Set(value).size / value.length;
  return base * Math.max(uniqueRatio, 0.35);
}

function hasSequence(lower) {
  if (lower.length < 4) return false;
  return SEQUENCES.some((sequence) => {
    for (let index = 0; index <= sequence.length - 4; index += 1) {
      if (lower.includes(sequence.slice(index, index + 4))) {
        return true;
      }
    }
    return false;
  });
}

function hasHeavyRepetition(value) {
  return /(.)\1{2,}/.test(value) || /^(.{1,3})\1{2,}$/.test(value);
}

function hasDatePattern(value) {
  return /(19|20)\d{2}/.test(value) || /\d{1,2}[/-]\d{1,2}[/-]\d{2,4}/.test(value);
}

function buildSuggestions(details) {
  const suggestions = [];

  if (details.length === 0) {
    return ["Start with a passphrase of at least four unrelated words."];
  }

  if (details.length < 12) {
    suggestions.push("Use at least 12 characters; 16 or more is better for important accounts.");
  }

  if (details.categories.length < 3) {
    suggestions.push("Mix uppercase, lowercase, numbers, and symbols without making a predictable pattern.");
  }

  if (details.common) {
    suggestions.push("Avoid common words such as password, qwerty, admin, welcome, or seasonal names.");
  }

  if (details.sequence || details.yearOrDate) {
    suggestions.push("Replace sequences, keyboard walks, years, and dates with unrelated words.");
  }

  if (details.repeated) {
    suggestions.push("Avoid repeating the same character or short pattern.");
  }

  if (details.reused) {
    suggestions.push("Create a fresh password instead of reusing one already saved in local memory.");
  }

  if (details.score >= 80) {
    suggestions.push("This is strong; keep it unique and store it in a password manager.");
  }

  return suggestions.slice(0, 5);
}

function makeSummary(label, score, entropy, reused) {
  if (score === 0) {
    return "Enter a password to analyze length, complexity, uniqueness, and reuse.";
  }
  const reuseText = reused ? " Local reuse was detected." : "";
  return `${label} password. Estimated entropy: ${Math.round(entropy)} bits.${reuseText}`;
}

function getStrengthLabel(score, length) {
  if (length === 0) return "Waiting for password";
  if (score >= 85) return "Excellent";
  if (score >= 70) return "Strong";
  if (score >= 50) return "Moderate";
  if (score >= 30) return "Weak";
  return "Very weak";
}

function clamp(value, min, max) {
  return Math.min(Math.max(Math.round(value), min), max);
}

function pick(values) {
  return values[randomInt(0, values.length - 1)];
}

function randomInt(min, max) {
  const range = max - min + 1;
  if (globalThis.crypto?.getRandomValues) {
    const buffer = new Uint32Array(1);
    globalThis.crypto.getRandomValues(buffer);
    return min + (buffer[0] % range);
  }
  return min + Math.floor(Math.random() * range);
}
