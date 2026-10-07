# Phishing Email Investigation Methodology

A structured methodology for analyzing suspicious and potentially malicious
emails from a **SOC Analyst perspective**.

The workflow provides a consistent investigation process while allowing
analysts to select different tools depending on the artifacts and evidence
identified in each case.

---

## Investigation Workflow

```text
┌──────────────────────┐
│ 1. Initial Triage    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 2. Safe Handling &   │
│    Evidence          │
│    Preservation      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 3. EML Analysis      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 4. IOC Extraction    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 5. Header &          │
│    Authentication    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 6. IOC Enrichment    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 7. URL / Attachment  │
│    Analysis          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 8. Evidence          │
│    Correlation       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 9. Final Assessment  │
└──────────────────────┘
```

---

# 1. Initial Triage

The initial triage provides a quick assessment of the email's visible
characteristics and identifies the first suspicious indicators.

This step establishes the investigation scope before deeper analysis begins.

### Technologies

- [Sublime Text](https://www.sublimetext.com/)
- Or any text editor capable of safely viewing raw email content

### Typical observations

- Sender identity
- Sender domain
- Subject
- Social engineering techniques
- Urgency or impersonation
- Suspicious links
- Attachments
- Visible branding or unusual formatting

---

# 2. Safe Handling & Evidence Preservation

The email should be treated as potentially malicious evidence and handled
without interacting with links, attachments, or active content.

Preserving the original `.eml` ensures that subsequent analysis is performed
against an unchanged source.

### Technologies

- Original `.eml` file
- Linux CLI
- `sha256sum`

### Example

```bash
sha256sum suspicious-email.eml
```

The resulting hash can be used to verify the integrity of the evidence
throughout the investigation.

---

# 3. EML Analysis

The raw EML structure is analyzed to identify message headers, MIME parts,
URLs, and attachments that may not be visible from the rendered email.

This provides a structured view of the email and its underlying artifacts.

### Technologies

- [emlAnalyzer](https://github.com/armbues/emlAnalyzer)
- Sublime Text
- Linux CLI

### Example

```bash
emlAnalyzer -i suspicious-email.eml --header -a -u
```

### Focus areas

- Email headers
- MIME structure
- HTML content
- Plain-text content
- URLs
- Attachments
- Embedded objects

---

# 4. IOC Extraction

Indicators of Compromise (IOCs) are extracted from the email to identify
artifacts that can be investigated and correlated with external intelligence.

This step converts raw email content into actionable investigation data.

### Technologies

- [ioc-finder](https://github.com/fhightower/ioc-finder)
- `grep`
- Regular expressions

### Example

```bash
cat suspicious-email.eml | ioc-finder
```

### Common IOCs

| Type | Examples |
|---|---|
| IP Address | `192.0.2.10` |
| Domain | `example.com` |
| URL | `https://example.com/login` |
| Email | `sender@example.com` |
| Hash | `SHA256 / MD5` |

---

# 5. Header & Authentication Analysis

Email headers are analyzed to reconstruct message delivery and determine
whether the sender's claimed identity is supported by authentication
mechanisms.

This step can reveal spoofing, unauthorized sending infrastructure, and
inconsistencies between the visible sender and the actual origin.

### Technologies

- [Google Admin Toolbox — Message Header Analyzer](https://toolbox.googleapps.com/apps/main/)
- [MXToolbox](https://mxtoolbox.com/)
- [PhishTool](https://www.phishtool.com/)

### Authentication checks

- SPF
- DKIM
- DMARC
- `Received` headers
- `Return-Path`
- `Message-ID`
- Reverse DNS
- Sending IP


---

# 6. IOC Enrichment

Extracted indicators are investigated using external intelligence sources
to determine their reputation, ownership, infrastructure, and historical
context.

Enrichment helps distinguish isolated suspicious artifacts from known or
related malicious infrastructure.

### Technologies

- [VirusTotal](https://www.virustotal.com/)
- [Cisco Talos Intelligence](https://talosintelligence.com/)
- [IPinfo](https://ipinfo.io/)
- [PhishTool](https://www.phishtool.com/)


### Depending on the IOC

**IP addresses**

- ASN
- Hosting provider
- Geolocation
- Reputation
- Reverse DNS

**Domains**

- Reputation
- Registration information
- DNS records
- Historical context

**Hashes**

- Malware reputation
- Detection results
- Related samples

---

# 7. URL / Attachment Analysis

URLs and attachments require deeper analysis when they are present in the
message.

The analysis method depends on the artifact: URLs may require reputation
and behavioral analysis, while attachments may require static or dynamic
malware analysis.

### URL Analysis

**Technologies**

- [VirusTotal](https://www.virustotal.com/)
- [URLScan.io](https://urlscan.io/)

Useful for:

- URL reputation
- Redirect chains
- Final destinations
- Page behavior
- Domain and infrastructure analysis

### Attachment Analysis

**Technologies**

- [VirusTotal](https://www.virustotal.com/)
- [ANY.RUN](https://any.run/)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [ReversingLabs](https://www.reversinglabs.com/)

Useful for:

- File reputation
- Static analysis
- Malware detection
- Process execution
- Network activity
- Behavioral indicators

> Dynamic analysis should only be performed in an isolated analysis
> environment.

---

# 8. Evidence Correlation

Findings from the different investigation stages are correlated to
determine whether individual indicators form a consistent malicious
pattern.

This is where isolated observations become an evidence-based assessment.

### Technologies

Depending on the investigation:

- [VirusTotal](https://www.virustotal.com/)
- [URLScan.io](https://urlscan.io/)
- [Cisco Talos Intelligence](https://talosintelligence.com/)
- [IPinfo](https://ipinfo.io/)
- SIEM platforms such as [Splunk](https://www.splunk.com/)

### Correlation examples

```text
Sender domain
      │
      ├── SPF / DKIM / DMARC results
      │
      ├── Sending IP
      │       └── ASN / Hosting provider
      │
      ├── Embedded URL
      │       └── Reputation / Redirects
      │
      └── Social engineering indicators
              │
              ▼
       Overall assessment
```

The goal is not to rely on a single detection source, but to evaluate the
evidence as a whole.

---

# 9. Final Assessment

The final assessment should clearly distinguish observed facts from analyst
interpretation and document the actions that should be taken.


The email was assessed as a phishing attempt based on the combination of
sender impersonation, authentication failures, suspicious infrastructure,
social engineering indicators, and malicious URL reputation.

### Recommended Actions

- Block or monitor identified IOCs where appropriate.
- Search for related messages across the environment.
- Identify potentially affected recipients.
- Investigate account activity if a recipient interacted with the email.
```

---

# Methodology Principles

This methodology is designed to provide **consistency without enforcing a
fixed toolset**.

Not every investigation requires every technology. Tools should be selected
according to the artifacts discovered during the investigation.

### Core principles

- **Preserve evidence before analysis**
- **Do not interact with suspicious content directly**
- **Separate observation from interpretation**
- **Correlate multiple sources of evidence**
- **Use dynamic analysis only when justified**
- **Document the reasoning behind the final verdict**
- **Select tools according to the case**

The methodology remains consistent across investigations, while the specific
analysis path may change depending on whether the email contains URLs,
attachments, suspicious infrastructure, authentication anomalies, or other
artifacts.
