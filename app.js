// Deterministic PII Redaction & Pseudonymization Engine (Browser Implementation)

const PRESETS = {
  "prospectus-contact": `KSH INTERNATIONAL LIMITED
Corporate Identity Number: U28129PN1979PLC141032
Registered Office: 11/3, 11/4 and 11/5 Village Birdewadi Chakan Taluka - Khed Pune – 410 501 Maharashtra, India.
Contact Person: Sarthak Malvadkar, Company Secretary and Compliance Officer
Telephone: + 91 20 45053237
Email: cs.connect@kshinternational.com
Website: www.kshinternational.com`,

  "board-director": `BOARD OF DIRECTORS:
1. Kushal Subbayya Hegde, Chairman and Non-Executive Director, DIN: 00135070
Residential Address: 12 Buena Monte, NCL co-operative housing society, Panchvati, Pashan, Pune – 411 008, Maharashtra, India.
2. Rajesh Kushal Hegde, Managing Director, DIN: 00114193
Residential Address: Pushpakamal Apartment, Flat – 1, S. no. 245/ 104, Prabhat Road Lane no. 3, Shivaji Nagar, Deccan Gymkhana, Pune – 411 004, Maharashtra, India.
3. Rohit Kushal Hegde, Whole-Time Director, DIN: 00134926
4. Dinesh Hirachand Munot, Independent Director, DIN: 00049801`,

  "financial-id": `BOOK RUNNING LEAD MANAGERS:
1. Nuvama Wealth Management Limited
801 - 804, Wing A, Building No 3, Inspire BKC, G Block, Bandra Kurla Complex, Bandra East, Mumbai 400051, Maharashtra, India
Tel: +91 22 4009 4400
Email: ksh.ipo@nuvama.com
Contact Person: Lokesh Shah / Soumavo Sarkar

2. ICICI Securities Limited
ICICI Venture House, Appasaheb Marathe Marg, Prabhadevi, Mumbai 400025, Maharashtra, India
Tel: +91 22 6807 7100
Email: ksh.ipo@icicisecurities.com
Contact Person: Prakash Boricha / Sheetal Parab`,

  "combined": `Applicant Details:
Name: Kushal Subbayya Hegde
Email: kushal.hegde@kshinternational.com
Phone: +91 9876543210
DOB: 14/08/1985
SSN: 123-45-6789
Credit Card: 4532-1234-5678-9012
Server IP: 192.168.1.100
CIN: U28129PN1979PLC141032
DIN: 00135070
Address: S. no. 245/ 104, Pushpakamal, Deccan Gymkhana Society, lane no. 3 Prabhat Road, opposite PYC basketball court, Deccan Gymkhana, Pune – 411 004 Maharashtra, India.`
};

// Deterministic Hash Generator
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

// Pseudonym Repository
const FAKE_FIRST_NAMES = ["Vincent", "Aarav", "Rohan", "Vikram", "Aditya", "Neha", "Pooja", "Ananya", "Rhea", "Kiran"];
const FAKE_LAST_NAMES = ["Sura", "Patil", "Deshmukh", "Sharma", "Mehta", "Iyer", "Nair", "Verma", "Kulkarni", "Reddy"];
const FAKE_COMPANIES = ["Garg-Mandal Limited", "Apex Global Solutions Limited", "Vanguard Industries LLP", "Zenith Capital Trust", "Sterling Commercial Bank"];

class WebPIIRedactor {
  constructor() {
    this.cache = new Map();
    this.knownPersons = [
      "Kushal Subbayya Hegde", "Pushpa Kushal Hegde", "Rajesh Kushal Hegde",
      "Rohit Kushal Hegde", "Rakhi Girija Shetty", "Kushal Hegde",
      "Pushpa Hegde", "Rajesh Hegde", "Rohit Hegde",
      "Maithili Rajesh Hegde", "Katyayani Balasubramanian",
      "Dinesh Hirachand Munot", "Ajay Shriram Patil", "Ram Kumar Tiwari", "Indu Jacob",
      "Sarthak Malvadkar", "Sandesh Bhagwat", "Amod Joshi", "Ganesh Prasad",
      "Lokesh Shah", "Soumavo Sarkar", "Prakash Boricha", "Sheetal Parab",
      "Kishan Rastogi", "Abhijit Diwan", "Shanti Gopalkrishnan",
      "Eric Bacha", "Sachin Gawade", "Pravin Teli", "Siddharth Jadhav", "Tushar Gavankar"
    ];

    this.knownCompanies = [
      "KSH INTERNATIONAL LIMITED", "KSH International Limited", "KSH International",
      "Waterloo Industrial Park VI Private Limited", "Waterloo Motors",
      "KSH Distriparks Private Limited", "Kushal Electricals",
      "Shubhkamal Leasing and Investment Private Limited",
      "Nuvama Wealth Management Limited", "ICICI Securities Limited",
      "MUFG Intime India Private Limited", "Link Intime India Private Limited",
      "Kirtane & Pandit, LLP, Chartered Accountants", "Kirtane & Pandit LLP",
      "Hingne Tare & Associates", "Trilegal",
      "HDFC Bank Limited", "ICICI Bank Limited", "Citibank, N.A.",
      "Export-Import Bank of India", "IndusInd Bank Limited", "State Bank of India",
      "Dhaulagiri Family Trust", "Everest Family Trust", "Makalu Family Trust"
    ];

    this.knownAddresses = [
      "11/3, 11/4 and 11/5 Village Birdewadi Chakan Taluka - Khed Pune – 410 501 Maharashtra, India",
      "11/3, 11/4 and 11/5, Village Birdewadi Chakan, Taluka-Khed Pune – 410 501 Maharashtra, India",
      "201, Tower 2, Montreal Business Centre, Off Pallod Farms, Baner Pune – 411 045 Maharashtra, India",
      "801 - 804, Wing A, Building No 3, Inspire BKC, G Block, Bandra Kurla Complex, Bandra East, Mumbai 400051, Maharashtra, India",
      "ICICI Venture House, Appasaheb Marathe Marg, Prabhadevi, Mumbai 400025, Maharashtra, India",
      "12 Buena Monte, NCL co-operative housing society, Panchvati, Pashan, Pune – 411 008, Maharashtra, India",
      "Pushpakamal Apartment, Flat – 1, S. no. 245/ 104, Prabhat Road Lane no. 3, Shivaji Nagar, Deccan Gymkhana, Pune – 411 004, Maharashtra, India",
      "S. no. 245/ 104, Pushpakamal, Deccan Gymkhana Society, lane no. 3 Prabhat Road, opposite PYC basketball court, Deccan Gymkhana, Pune – 411 004 Maharashtra, India"
    ];
  }

  getFake(text, type) {
    const key = `${type}:${text.trim().toLowerCase()}`;
    if (this.cache.has(key)) return this.cache.get(key);

    const h = hashString(text);
    let fakeVal = "";

    switch (type) {
      case "FULL_NAME":
        const fn = FAKE_FIRST_NAMES[h % FAKE_FIRST_NAMES.length];
        const ln = FAKE_LAST_NAMES[(h >> 3) % FAKE_LAST_NAMES.length];
        fakeVal = `${fn} ${ln}`;
        break;

      case "EMAIL":
        const userPart = text.split("@")[0].toLowerCase().replace(/[^a-z0-9]/g, ".");
        fakeVal = `${userPart}@example.com`;
        break;

      case "PHONE":
        const digits = Array.from({ length: 10 }, (_, i) => ((h + i * 7) % 10)).join("");
        fakeVal = `+91 ${digits.slice(0, 5)} ${digits.slice(5)}`;
        break;

      case "COMPANY":
        const base = FAKE_COMPANIES[h % FAKE_COMPANIES.length];
        fakeVal = base;
        break;

      case "ADDRESS":
        fakeVal = "402, Heritage Residency, Green Valley Road, Pune – 411 045, Maharashtra, India";
        break;

      case "SSN":
        const ssnD = Array.from({ length: 9 }, (_, i) => ((h + i) % 10)).join("");
        fakeVal = `${ssnD.slice(0, 3)}-${ssnD.slice(3, 5)}-${ssnD.slice(5)}`;
        break;

      case "CREDIT_CARD":
        const ccD = Array.from({ length: 16 }, (_, i) => ((h + i) % 10)).join("");
        fakeVal = `4${ccD.slice(1, 4)}-${ccD.slice(4, 8)}-${ccD.slice(8, 12)}-${ccD.slice(12, 16)}`;
        break;

      case "DATE_OF_BIRTH":
        fakeVal = "15/08/1984";
        break;

      case "IP_ADDRESS":
        fakeVal = `198.51.${(h % 250) + 1}.${((h >> 2) % 250) + 1}`;
        break;

      case "STATUTORY_ID":
        const orig = text.trim();
        if (orig.length === 8 && /^\d+$/.test(orig)) {
          fakeVal = `0${(h % 9000000) + 1000000}`;
        } else if (orig.length === 21) {
          fakeVal = `U${(h % 90000) + 10000}MH2008PLC${(h % 900000) + 100000}`;
        } else {
          fakeVal = `ABCDE${(h % 9000) + 1000}Z`;
        }
        break;

      default:
        fakeVal = "[REDACTED]";
    }

    this.cache.set(key, fakeVal);
    return fakeVal;
  }

  detect(text) {
    const entities = [];

    // 1. Credit Card
    const reCC = /\b(?:\d{4}[-\s]?){3}\d{4}\b/g;
    let match;
    while ((match = reCC.exec(text)) !== null) {
      entities.push({ text: match[0], type: "CREDIT_CARD", start: match.index, end: match.index + match[0].length, prio: 6, rule: "16-digit Luhn Regex" });
    }

    // 2. SSN
    const reSSN = /\b\d{3}-\d{2}-\d{4}\b/g;
    while ((match = reSSN.exec(text)) !== null) {
      entities.push({ text: match[0], type: "SSN", start: match.index, end: match.index + match[0].length, prio: 5, rule: "Standard SSN Regex" });
    }

    // 3. IP Address
    const reIP = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    while ((match = reIP.exec(text)) !== null) {
      entities.push({ text: match[0], type: "IP_ADDRESS", start: match.index, end: match.index + match[0].length, prio: 1, rule: "IPv4 Octet Matcher" });
    }

    // 4. Email
    const reEmail = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    while ((match = reEmail.exec(text)) !== null) {
      entities.push({ text: match[0], type: "EMAIL", start: match.index, end: match.index + match[0].length, prio: 7, rule: "RFC 5322 Pattern" });
    }

    // 5. DOB
    const reDOB = /\b(?:DOB|Born|Date of Birth|Birth date)[\s:]*([0-3]?\d[-/.][0-1]?\d[-/.](?:19|20)\d{2})\b/gi;
    while ((match = reDOB.exec(text)) !== null) {
      const val = match[1];
      const sIdx = match.index + match[0].indexOf(val);
      entities.push({ text: val, type: "DATE_OF_BIRTH", start: sIdx, end: sIdx + val.length, prio: 2, rule: "Context-bound DOB Matcher" });
    }

    // 6. Statutory IDs (CIN, DIN)
    const reCIN = /\b[UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b/g;
    while ((match = reCIN.exec(text)) !== null) {
      entities.push({ text: match[0], type: "STATUTORY_ID", start: match.index, end: match.index + match[0].length, prio: 4, rule: "MCA 21-char CIN Regex" });
    }
    const reDIN = /\b(?:DIN[:\s]*|DIN\s+)(\d{8})\b/gi;
    while ((match = reDIN.exec(text)) !== null) {
      const val = match[1];
      const sIdx = match.index + match[0].indexOf(val);
      entities.push({ text: val, type: "STATUTORY_ID", start: sIdx, end: sIdx + val.length, prio: 4, rule: "Director DIN Identifier" });
    }

    // 7. Phone Numbers
    const rePhone = /(?:\+\s*91[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,5}[\s-]?\d{4,6}|\+\s*91[\s-]?\d{10}|022-\d{8}|020-\d{8})/g;
    while ((match = rePhone.exec(text)) !== null) {
      entities.push({ text: match[0], type: "PHONE", start: match.index, end: match.index + match[0].length, prio: 3, rule: "Telecom +91 / STD Regex" });
    }

    // 8. Addresses
    for (const addr of this.knownAddresses) {
      let idx = 0;
      while ((idx = text.indexOf(addr, idx)) !== -1) {
        entities.push({ text: addr, type: "ADDRESS", start: idx, end: idx + addr.length, prio: 10, rule: "Registered Office Gazetteer" });
        idx += addr.length;
      }
    }

    // 9. Companies
    for (const comp of this.knownCompanies) {
      const regex = new RegExp(`\\b${comp.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
      while ((match = regex.exec(text)) !== null) {
        entities.push({ text: match[0], type: "COMPANY", start: match.index, end: match.index + match[0].length, prio: 9, rule: "Corporate Entity Matcher" });
      }
    }

    // 10. Contact Person
    const reContact = /(?:Contact Person[:\s]+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+(?:\/[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)*)/g;
    while ((match = reContact.exec(text)) !== null) {
      const chunk = match[1];
      const parts = chunk.split(/[/,]| and /);
      for (const p of parts) {
        const trimmed = p.trim();
        if (trimmed.length > 3 && !trimmed.toLowerCase().startsWith("sebi")) {
          const sIdx = text.indexOf(trimmed, match.index);
          if (sIdx !== -1) {
            entities.push({ text: trimmed, type: "FULL_NAME", start: sIdx, end: sIdx + trimmed.length, prio: 8, rule: "Contact Officer Pattern" });
          }
        }
      }
    }

    // 11. Known Names
    for (const name of this.knownPersons) {
      const regex = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
      while ((match = regex.exec(text)) !== null) {
        entities.push({ text: match[0], type: "FULL_NAME", start: match.index, end: match.index + match[0].length, prio: 8, rule: "Promoter & Director NER" });
      }
    }

    return this.resolveOverlaps(entities);
  }

  resolveOverlaps(entities) {
    if (!entities.length) return [];
    entities.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start) || b.prio - a.prio);

    const resolved = [];
    for (const e of entities) {
      if (!resolved.length) {
        resolved.push(e);
        continue;
      }
      const last = resolved[resolved.length - 1];
      if (e.start >= last.end) {
        resolved.push(e);
      } else {
        if ((e.prio > last.prio && (e.end - e.start) >= (last.end - last.start)) ||
            ((e.end - e.start) > (last.end - last.start) && e.prio >= last.prio)) {
          resolved[resolved.length - 1] = e;
        }
      }
    }
    return resolved;
  }
}

// UI Controller
document.addEventListener("DOMContentLoaded", () => {
  const redactor = new WebPIIRedactor();

  // Tab switching
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = `tab-${btn.getAttribute("data-tab")}`;
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
    });
  });

  // Sandbox elements
  const rawInput = document.getElementById("raw-text-input");
  const outputBox = document.getElementById("redacted-output-box");
  const runBtn = document.getElementById("run-redaction-btn");
  const clearBtn = document.getElementById("clear-input-btn");
  const copyBtn = document.getElementById("copy-output-btn");
  const statsTag = document.getElementById("input-stats");
  const tableBody = document.getElementById("entity-table-body");

  // Load Preset
  function loadPreset(key) {
    if (PRESETS[key]) {
      rawInput.value = PRESETS[key];
      executeRedaction();
    }
  }

  document.querySelectorAll(".sample-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const sampleKey = btn.getAttribute("data-sample");
      loadPreset(sampleKey);
    });
  });

  clearBtn.addEventListener("click", () => {
    rawInput.value = "";
    outputBox.innerHTML = "";
    statsTag.textContent = "Detected: 0 entities";
    tableBody.innerHTML = `<tr><td colspan="4" class="empty-state">No entities detected yet. Run redaction above.</td></tr>`;
  });

  copyBtn.addEventListener("click", () => {
    const textToCopy = outputBox.innerText;
    if (!textToCopy) return;
    navigator.clipboard.writeText(textToCopy).then(() => {
      const orig = copyBtn.textContent;
      copyBtn.textContent = "Copied! ✓";
      setTimeout(() => { copyBtn.textContent = orig; }, 1500);
    });
  });

  function getBadgeClass(type) {
    switch (type) {
      case "FULL_NAME": return "badge-name";
      case "EMAIL": return "badge-email";
      case "PHONE": return "badge-phone";
      case "COMPANY": return "badge-comp";
      case "ADDRESS": return "badge-addr";
      default: return "badge-id";
    }
  }

  function executeRedaction() {
    const text = rawInput.value;
    if (!text.trim()) {
      outputBox.innerHTML = "";
      statsTag.textContent = "Detected: 0 entities";
      tableBody.innerHTML = `<tr><td colspan="4" class="empty-state">No entities detected yet. Run redaction above.</td></tr>`;
      return;
    }

    const detected = redactor.detect(text);
    statsTag.textContent = `Detected: ${detected.length} entities`;

    // Render Table
    if (detected.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="4" class="empty-state">No PII detected in the provided text.</td></tr>`;
    } else {
      tableBody.innerHTML = detected.map(e => {
        const fake = redactor.getFake(e.text, e.type);
        return `
          <tr>
            <td><span class="badge ${getBadgeClass(e.type)}">${e.type}</span></td>
            <td><code>${escapeHtml(e.text)}</code></td>
            <td><strong>${escapeHtml(fake)}</strong></td>
            <td>${escapeHtml(e.rule)}</td>
          </tr>
        `;
      }).join("");
    }

    // Build highlighted rendered output
    let htmlOutput = "";
    let lastIdx = 0;
    const sortedDetected = [...detected].sort((a, b) => a.start - b.start);

    for (const ent of sortedDetected) {
      htmlOutput += escapeHtml(text.slice(lastIdx, ent.start));
      const fake = redactor.getFake(ent.text, ent.type);
      htmlOutput += `<span class="hl-tag ${getBadgeClass(ent.type)}" title="Original: ${escapeHtml(ent.text)} (${ent.type})">${escapeHtml(fake)}</span>`;
      lastIdx = ent.end;
    }
    htmlOutput += escapeHtml(text.slice(lastIdx));

    outputBox.innerHTML = htmlOutput;
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  runBtn.addEventListener("click", executeRedaction);
  rawInput.addEventListener("input", executeRedaction);

  // Initialize with first preset
  loadPreset("prospectus-contact");
});
