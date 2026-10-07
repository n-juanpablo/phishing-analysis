## Overview

| Field | Details |
|---|---|
| Date & Time | 06-02-2026 |
| Sample | `sample01.eml` |
| Brand Impersonated | Microsoft |
| Target Audience | Microsoft users |

<br>

## First Contact - What the Victim Sees

Before performing deeper technical analysis, the email is examined from the recipient's perspective to understand how the message attempts to appear legitimate and influence the recipient's behavior.

- Microsoft "Unusual sign-in Activity"
- Information regarding an alleged sign-in to the user's Microsoft account.
- An urgency-based call to action urging the recipient to secure the account immediately.
- A fake blue "Review recent activity" button.
- A second call-to-action message stating that the account requires immediate attention.

S C R E E N S H O T

<br><br>



## Step 1: Initial Triage

The email is first examined to establish an initial understanding of the sender identity, subject, social engineering techniques, and potentially suspicious artifacts. The analysis is performed without interacting with potentially malicious links, attachments, or active content.

```bash
subl sample01.eml
```

Safely open the email and read it while avoiding any accidental interaction with potentially malicious hyperlinks or active content. This is where we train our eye to manually spot red flags.

**Sender identity:**
The displayed sender is `Microsoft Account Team <noreply@microsoftonline-verify.com>`.

**Subject and Social Engineering:**
The message uses several social engineering techniques to create a sense of urgency and increase the perceived legitimacy of the request.

**Urgency:** The phrase "[Action Required] Unusual sign-in activity on your account" creates a sense that immediate action is required to investigate a potentially unauthorized sign-in.

**Security-related pretext:** The email presents itself as a Microsoft security notification concerning unusual account activity, creating a plausible reason for the recipient to interact with the message.

**Call to action:** The recipient is encouraged to review the alleged account activity through a link presented as a security-related action.

**Authority / Brand impersonation:** The message presents itself as the Microsoft Account Team, leveraging the trust associated with Microsoft and its account security notifications.

**Suspicious sender domain:** The sender uses `microsoftonline-verify.com`, which attempts to resemble Microsoft's infrastructure but is not an official `microsoft.com` domain.

**Suspicious URL:** The HTML body contains a shortened Bitly URL: `https://bit.ly/3vFn9xKz`.<br>
The URL was identified without directly accessing it.


### Tool

- [Sublime Text](https://www.sublimetext.com/)
<br><br>

---

## Step 2: Safe Handling & Evidence Preservation

The original `.eml` sample is preserved as evidence and subsequent analysis is performed against the preserved sample or a working copy where appropriate.

Potentially malicious links and active content are not opened or interacted with directly on the host system.

### Evidence Integrity

The SHA-256 hash of the original `.eml` is calculated using `sha256sum`.

S C R E E N S H O T

---

## Step 3: EML Analysis

The EML structure is analyzed to identify message headers, MIME parts, URLs, and other embedded content that may not be visible from the rendered email.

`emlAnalyzer` provides a structured extraction of the available message headers, URLs, and attachments.

### Tool

- [emlAnalyzer](https://github.com/armbues/emlAnalyzer)

### Command

```bash
emlAnalyzer -i sample01.eml --header -a -u
```

S C R E E N S H O T

---

## Step 4: IOC Extraction

Relevant artifacts are extracted from the message and classified as Indicators of Compromise (IOCs) for further investigation.

### Tool

- [ioc-finder](https://github.com/fhightower/ioc-finder)

### Command

```bash
cat sample01.eml | ioc-finder
```

S C R E E N S H O T

The extracted indicators are retained for subsequent header, infrastructure, and URL enrichment.

---

## Step 5: Authentication

Email headers are analyzed to reconstruct the message delivery path and determine whether the sender's claimed identity is supported by email authentication mechanisms.

### Authentication Results

The `Authentication-Results` header shows failures for SPF, DKIM, and DMARC:


The SPF result specifically indicates that the sending IP `178.238.225.91` is not authorized to send mail for `microsoftonline-verify.com`.


### Infrastructure Findings

**Originating IP:** `178.238.225.91`

**Reverse DNS:** `vmi3247644.contaboserver.net`

**Hosting Provider:** Contabo infrastructure

**Return-Path:** `noreply@microsoftonline-verify.com`



S C R E E N S H O T

### Tools

- MXToolbox

---

## Step 6: IOC Enrichment

Extracted indicators are investigated using external intelligence sources to determine their reputation, ownership, infrastructure, and historical context.
Only relevant indicators are enriched; not every extracted IOC requires the same level of investigation.

### Domain Analysis

**Indicator:** `microsoftonline-verify.com`

The sender domain was identified as a relevant IOC during the investigation.

The domain is used by the sender address `noreply@microsoftonline-verify.com`.

### IP / Infrastructure Analysis

**IP:** `178.238.225.91`

**Reverse DNS:** `vmi3247644.contaboserver.net`

**Hosting Provider:** Contabo infrastructure

The reverse DNS record provides additional context about the hosting infrastructure associated with the originating IP.

The hostname `vmi3247644.contaboserver.net` indicates that the IP `178.238.225.91` is associated with Contabo-hosted infrastructure.

However, the use of a legitimate hosting provider does not by itself indicate malicious activity. This finding should be considered together with the other indicators identified during the investigation.

### URL Reputation

**Indicator:** `https://bit.ly/3vFn9xKz`

The shortened URL was checked against VirusTotal to obtain additional reputation and threat intelligence context.

VirusTotal reported:

`1/92` detections.

- Gridinsoft classified the URL as **Phishing**.
- The URL may no longer be active or its associated infrastructure may have been taken down.
- The current lack of widespread detections does not establish that the URL was safe when the email was delivered.

This result provides additional threat intelligence context for the URL, but does not confirm its original destination.




---

## Step 7: URL Analysis

### URL Analysis

The shortened URL was further analyzed to determine its current behavior, final destination, and associated infrastructure.

**Indicator:** `https://bit.ly/3vFn9xKz`

#### URL Expander

The shortened URL was submitted to URL Expander to determine its original destination. <br>
The service returned an HTTP `404 Not Found` response and was unable to resolve the shortened URL.
The original destination therefore could not be confirmed through the current state of the shortened URL.
This does not indicate that the URL was benign. The link may have been removed, expired, or disabled after the phishing campaign.

S C R E E N S H O T



S C R E E N S H O T





---

## Step 8: Evidence Correlation

The findings from the different investigation stages are correlated to determine whether the individual indicators form a consistent phishing pattern.



```

### Correlated Findings

- The sender impersonates Microsoft using the domain `microsoftonline-verify.com`.
- SPF, DKIM, and DMARC authentication checks failed.
- The originating IP `178.238.225.91` is associated with `vmi3247644.contaboserver.net` and Contabo-hosted infrastructure.
- The email uses social engineering techniques, including an urgent "Unusual sign-in activity" notification and a request to review recent account activity.
- The message contains a shortened Bitly URL: `https://bit.ly/3vFn9xKz`.
- VirusTotal reported `1/92` detections, with Gridinsoft classifying the URL as **Phishing**.
- The URL currently returns `404 Not Found`, so its current state does not establish whether it was active or malicious at the time the email was delivered.

---

## Step 9: Final Assessment

The email is assessed as a **phishing attempt impersonating Microsoft**.

The attack uses Microsoft impersonation, a misleading sender domain, failed email authentication, suspicious sending infrastructure, social engineering techniques, and a shortened URL to persuade the recipient to review alleged account activity.

The current `404 Not Found` response indicates that the requested URL is no longer available at the analyzed location, but does not invalidate the other evidence collected during the investigation.

### IOCs Summary

| Field | Finding |
|---|---|
| **Sender (claimed)** | Microsoft Account Team |
| **Sender (actual)** | `noreply@microsoftonline-verify.com` |
| **Sender IP** | `178.238.225.91` (`vmi3247644.contaboserver.net`) |
| **Subject** | `[Action Required] Unusual sign-in activity on your account` |
| **SPF/DKIM/DMARC** | Fail / Fail / Fail |
| **Phishing URL** | `hxxps://bit[.]ly/3vF9xKz` |
| **Brand Impersonated** | Microsoft |
| **Technique** | Credential phishing via Microsoft impersonation, fabricated account-security alert, urgency tactics, and a shortened URL |
| **Additional Indicators** | `microsoftonline-verify[.]com` sender domain; originating infrastructure hosted on Contabo |
| **Verdict** | **Phishing** |

### Analysis Tools Used

| Tool | Command / Action |
|---|---|
| Sublime Text | `subl microsoft-credentialharvester.eml` |
| `emlAnalyzer` | `emlAnalyzer -i microsoft-credentialharvester.eml --header -a -u` |
| `ioc-finder` | `cat microsoft-credentialharvester.eml \| ioc-finder` |
| MXToolbox | Pasted email headers → Header Analyzer |
| PhishTool | Uploaded `.eml` → Header and email analysis |
| VirusTotal | Submitted `https://bit.ly/3vF9xKz` → URL reputation analysis |
| URLScan.io | Submitted URL → Current destination and infrastructure analysis |
