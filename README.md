# PII Redaction Pipeline

An enterprise-grade Python solution that detects Personally Identifiable Information (PII) within documents (specifically Microsoft Word `.docx` documents) and produces a redacted, anonymized version by replacing sensitive entities with realistic, format-preserving fake alternatives (pseudonymization).

---

## 1. Approach & Architecture

Our redaction pipeline uses a **hybrid multi-stage architecture** combining high-precision regex matching, contextual entity recognition, domain knowledge base lookups, and deterministic fake data generation:

1. **Detection Engine (`PIIDetector`):**
   - **Pattern-based Detection:** Regular expressions for structured syntaxes including Email addresses, Phone numbers (international `+91`, landline STD codes `020`/`022`, and local mobile numbers), Social Security Numbers (SSNs), Credit Card numbers, Dates of Birth (DOBs), IP addresses (IPv4/IPv6), and corporate identification codes (CIN, DIN, PAN).
   - **Contextual & NER Recognizers:** Captures contact lines (e.g., `Contact Person: <Name>`), corporate and trust entities, law firms, and multi-line physical residential and registered office addresses.
   - **Conflict & Overlap Resolution:** Uses a priority hierarchy (`ADDRESS` > `COMPANY` > `FULL_NAME` > `EMAIL` > `CREDIT_CARD` > `SSN` > `STATUTORY_ID` > `PHONE` > `DOB` > `IP`) to ensure longer, higher-confidence entities (e.g., full address blocks) take precedence over partial substring matches (e.g., individual street numbers).

2. **Deterministic Pseudonymization (`PIIFakeGenerator`):**
   - Utilizes `Faker` with a deterministic hashing cache (`MD5` seed derived per entity).
   - Ensures that the **exact same entity always receives the exact same fake substitute** throughout the entire document and across execution runs (e.g., `Kushal Subbayya Hegde` consistently maps to `Vincent Sura`, and `cs.connect@kshinternational.com` consistently maps to `cs.connect@example.com`).

3. **Format-Preserving Word Redaction (`DocxRedactor`):**
   - Traverses document paragraphs, tables, table cells, nested tables, and all section headers and footers using `python-docx`.
   - Employs a non-destructive run-level text replacement algorithm that preserves original font families, font sizes, colors, bold/italic formatting, and document layout without flattening entire paragraphs into unstyled text.

---

## 2. Tradeoffs & Error Analysis

- **Filing Dates vs. Dates of Birth:**
  - *Tradeoff:* Financial prospectuses contain hundreds of statutory and transaction dates (e.g., *Dated December 10, 2025*, *Fiscal 2025*, *Allotment date May 6, 2025*).
  - *Resolution:* General dates are preserved as essential public corporate records. Dates are only redacted as `DATE_OF_BIRTH` when explicitly accompanied by birth indicators (`DOB:`, `Date of Birth:`, `Born:`) to prevent severe precision degradation.
- **Financial Figures vs. Phone Numbers / IDs:**
  - *Tradeoff:* Numbers like *₹7,100.00 million*, *80,000,000 shares*, and *₹5 each* could trigger naive numeric regexes.
  - *Resolution:* Phone number and ID patterns require telephone contextual keywords (`Tel:`, `Telephone:`, `Phone:`) or standard telecom formatting (`+91 ...`, `020-...`, `022-...`), maintaining 100% precision.
- **Form & Citation Numbers:**
  - *Tradeoff:* Citations such as *Form 7B*, *Form SH-4*, and *Rule 19(2)(b)* look like identifiers.
  - *Resolution:* These are explicitly preserved as statutory regulatory terminology.

---

## 3. Supported PII Categories

| Category | Detection Method | Fake Replacement Strategy |
| :--- | :--- | :--- |
| **Full Names** | Contextual matcher & entity registry | Consistent regional fake full names |
| **Email Addresses** | RFC 5322 regex | Anonymized user `@example.com` |
| **Phone Numbers** | Contextual telephone regex (`+91`, STD) | Format-preserving pseudo telephone numbers |
| **Company Names** | Corporate suffix & entity matcher | Realistic enterprise & trust names |
| **Physical Addresses** | Landmark, pincode & multi-line parser | Realistic street, city, pin, state address |
| **SSN / Tax IDs** | Regex (`\d{3}-\d{2}-\d{4}`, PAN, DIN, CIN) | Valid-format synthetic SSNs & statutory IDs |
| **Credit Card Numbers** | 16-digit card regex with boundary check | Luhn-compliant synthetic payment card numbers |
| **Dates of Birth** | Context-bound date matcher | Standard synthetic birth dates |
| **IP Addresses** | IPv4 & IPv6 regex | RFC 5737 reserved documentation IPs |

---

## 4. How to Extend to a New PII Type

1. **Add to Enum:** In `redact_pii.py`, add the new category to `PIIType` (e.g., `PASSPORT = "PASSPORT"`).
2. **Add Pattern to Detector:** In `PIIDetector.detect_entities()`, add regex or NER rules detecting the target pattern and append a `PIIEntity(m.group(), PIIType.PASSPORT, m.start(), m.end())`.
3. **Add Generator Rule:** In `PIIFakeGenerator.get_fake()`, add a handler returning a realistic synthetic value (e.g., `f"{f_fake.bothify(text='?#######')}"`).
4. **Add Unit Tests:** In `PIIEvaluator.run_benchmark()`, add positive and negative test cases to ensure continuous evaluation tracking.

---

## 5. Usage & Execution

```bash
# Install dependencies
pip install python-docx faker

# Run redaction and generate evaluation report
python3 redact_pii.py --input "Red Herring Prospectus.docx" \
                      --output "Red_Herring_Prospectus_Redacted.docx" \
                      --report "evaluation_report.md" \
                      --seed 42
```

Outputs generated:
- `Red_Herring_Prospectus_Redacted.docx` (Redacted Word document)
- `evaluation_report.md` (Detailed Precision, Recall, Accuracy report)
