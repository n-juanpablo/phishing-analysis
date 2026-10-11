## Overview

| Field | Details |
|---|---|
| Date & Time | 05-07-2026 |
| Sample | `sample01.eml` |
| Brand Impersonated | Brazilian Detran / gov.br  |
| Target Audience | Brazilian drivers and CNH holders  |

<br>

## First Contact - What the Victim Sees 

Before performing deeper technical analysis, the email is examined from the recipient's perspective to understand Social Engineering techniques and how the message attempts to appear legitimate and influence the recipient's behavior.<br><br>


![First Contact](../screenshots/sample01/First%20contact.png)<br><br>


- **Official-looking formatting:** The email uses Brazilian government branding, including the gov.br logo and references to the Department of Transit, to present itself as an official administrative notification.
- **Government impersonation:** 
- Una notificación que dice ser "oficial" del Departamento de Tránsito del Gobierno de Brasil (gov.br)
- **Personalization:** The recipient's email address is displayed in the greeting, making the message appear individually addressed rather than broadly distributed. This increases the perceived legitimacy.

- **Pretexting:** The message establishes a scenario in which the victim allegedly has an unresolved traffic violation that has triggered the suspension of the license.

- **Sense of urgency:** The stated regularization deadline combined with the claim that suspension is already active, creates time pressure and encourages the victim to act quickly.

- **Fear:** The email lists potentially consequences on vehicle licensing. These threats are intended to make inaction appear risky.

- **Call to action:** A prominent green button labeled "“REGULARIZAR SITUAÇÃO DA CNH" directs the victim toward the next step.

- **Reassurance:** A regularization process that promises subsequent confirmation by email reducing the hesitation by presenting the requested action as a routine procedure.
 

<br><br>

---
## Step 1: Initial Triage

The email is first examined to establish an initial understanding of the sender identity, subject, social engineering techniques, and potentially suspicious artifacts. The analysis is performed without interacting with potentially malicious links, attachments, or active content.

```bash
subl sample01.eml
```
![Step 1](../screenshots/sample01/Step%201.png)


Safely open the email and read it while avoiding any accidental interaction with potentially malicious hyperlinks or active content. This is where we train our eye to manually spot red flags.

**Display Name:** Detran - Alerta de Penalidade<br>
**Sending Address:** detran@sistemadeinfracaro054752<br>
**Sender IP:** 45.77.197.210<br>
**Claimed Sender Identity:** Brazilian transit authority (DETRAN)<br>
**Recipient Address:** phishing@pot<br>
**Date + Time:** 2026-07-05 19:12:56 UTC<br>
**Return-Path:** detran@sistemadeinfracao054752<br>
**Content-Type:** multipart/alternative

Look for `Content-Transfer-Encoding:` "base64" means the body needs decoding.<br><br>
![Step 1a](../screenshots/sample01/Step%201a.png)
<br><br>


### Tool

- [Sublime Text](https://www.sublimetext.com/)
<br><br><br>

---
## Step 2: Safe Handling & Evidence Preservation

Potentially malicious links and active content are not opened or interacted with directly on the host system.<br><br>
![Step 2](../screenshots/sample01/Step%202.png)


### Evidence Integrity

The SHA-256 hash of the original `.eml` is calculated using `sha256sum`.
<br><br><br>

---
## Step 3: EML Analysis

The EML structure is analyzed to identify message headers, MIME parts, URLs, and other embedded content that may not be visible from the rendered email.
#### Command

```bash
emlAnalyzer -i sample01.eml --header -a -u
```

![Step 3](../screenshots/sample01/Step%203.png)
![Step 3a](../screenshots/sample01/Step%203a.png)

`emlAnalyzer` provides a structured extraction of the available message headers, URLs, and attachments. <br><br>


### Tool

- [emlAnalyzer](https://github.com/armbues/emlAnalyzer)

<br><br><br>

---

## Step 4: IOC Extraction

Relevant artifacts are extracted from the message and classified as Indicators of Compromise (IOCs) for further investigation.

#### Command

```bash
cat sample01.eml | ioc-finder
```
![Step 4](../screenshots/sample01/Step%204.png)


The extracted indicators are retained for subsequent header, infrastructure, and URL analysis.

### Tool

- [ioc-finder](https://github.com/fhightower/ioc-finder)

<br><br>
---


## Step 5: Header Analysis and Authentication

Email headers are analyzed to reconstruct the message delivery path and determine whether the sender's claimed identity is supported by email authentication mechanisms.

### Authentication Results

![Step 5](../screenshots/sample01/Step%205.png)



#### Email Authentication Analysis

❌ **DMARC — No Applicable Result (`dmarc=none`)**
    └── The message's claimed sender identity could not be validated through DMARC based on the available results.

❌ **SPF Alignment — Not Established**
    └── Further investigation is required to determine whether an applicable SPF record exists for the evaluated sender.

❌ **SPF Authentication — No Result (`spf=none`)**
  └── Microsoft reported `spf=none` for the sending IP `45.77.197.210`.
  └── This result does not establish that the IP was explicitly unauthorized; the SPF configuration and evaluation context require further verification.

❌ **DKIM Alignment — Not Established**
    └── Without a DKIM signature, successful DKIM authentication and alignment could not be established.

❌ **DKIM Authentication — No Signature (`dkim=none`)**
  └── The authentication results indicate that the message was not signed with DKIM.
  └── The message's integrity and signing-domain identity could not be verified through DKIM.

#### The Relay Chart

The bar chart at the bottom visualizes the email's relay path through Microsoft Exchange infrastructure and the approximate time associated with each stage:

- **Total Relay Time:** Approximately 4 seconds, as reported by MXToolbox.
- **Observation:** The message passed through Microsoft email protection and Exchange infrastructure within a few seconds.
- **Assessment:** No suspicious delay is established by the relay chart alone. The observed timing is not by itself evidence of malicious activity.


### Infrastructure Findings

**Originating IP:** 45.77.197.210

**Reverse DNS:** 45.77.197.210.vultrusercontent.com

**Hosting Provider:** Vultrus

**Return-Path:** detran@sistemadeinfracao054752<br><br>
![Step 5a](../screenshots/sample01/Step%205a.png)



### Tool

- [MXToolbox](https://mxtoolbox.com/)
<br><br>

---

## Step 6: Decode the Body

1. Copy the Base64-encoded block located in Sublime Text.
2. Access CyberChef
3. Use CyberChef's **From Base64** operation to decode the contentand obtain the HTML source.
4. Examine the decoded HTML to identify the email's visible message, embeded links and other elements that could provide evidence of phishing activity.
<br><br>

![Step 6](../screenshots/sample01/Step%206.png)

**Extracted URL:**
- `https://www.windows.com-pt-brprincipal380294208@dt3-161255673571.southamerica-east1.run.app`


**Defang the URL for safe sharing:**
- `hxxps://www[.]windows[.]com-pt-brprincipal380294208@dt3-161255673571[.]southamerica-east1[.]run[.]app`


### Tool
- [CyberChef](https://gchq.github.io/CyberChef/)
<br><br><br>

## Step 7: URL Analysis
For the URL extracted in Step 6, analyze it using **VirusTotal**. Use the original, non-defanged URL for analysis.<br><br>
![Step 7](../screenshots/sample01/Step%207.png)

**VirusTotal** identified the submitted URL as suspicious, with 12 out of 93 security vendors flagging it, primarily as phishing. Several vendors classified the URL as malicious or associated it with phishing activity, while others reported no detection.
The detection ratio provides additional evidence supporting the phishing assessment.
<br>

### Tool
- [VirusTotal](https://www.virustotal.com/) 

<br><br>

---


## Step 8: Findings and Evidence Correlation

### Findings

#### Social Engineering Techniques

The email impersonates Brazil's Detran traffic authority and claims that the recipient's driver's license (CNH) is at risk of suspension. It establishes a deadline of July 8, 2026, and uses threatening language to pressure the recipient into clicking the **"REGULARIZAR SITUAÇÃO DA CNH"** (Regularize Your Driver's License Status) button.

```text
Government impersonation  ← Exploits trust in a public authority
Threat of license suspension ← Creates fear of consequences
Deadline: 08/07/2026       ← Creates time pressure
Call-to-action button     ← Encourages interaction with the suspicious URL
```

The originating IP address was identified in the email headers. Its reverse DNS hostname, `45.77.197.210.vultrusercontent.com`, is associated with Vultr hosting infrastructure. This provides context about the sending infrastructure but does not independently establish malicious activity.


### Authentication Results

```text
SPF:    none (sender domain does not designate permitted hosts)
DKIM:   none (message not signed)
DMARC:  none (no authentication result established)
```

The message did not provide successful SPF or DKIM authentication, and DMARC returned `none`. These results do not independently prove spoofing but provide no positive authentication evidence supporting the claimed sender identity.

### Body Analysis

The email body was Base64-encoded and decoded using CyberChef's **From Base64** operation to recover the HTML content for inspection.

**What the Victim Sees**

- A message impersonating Brazil's Detran traffic authority.
- A warning about the pending suspension of the recipient's driver's license (CNH).
- A deadline of **July 8, 2026**, to resolve the alleged penalty.
- A personalized-looking reference to `rodrigo-f-p@hotmail.com`.
- A prominent **"REGULARIZAR SITUAÇÃO DA CNH"** call-to-action button.

The combination of government impersonation, a threatened penalty, and a deadline is consistent with social engineering intended to encourage the recipient to act without carefully verifying the message.

### Malicious URL

The URL was extracted from the decoded HTML body.

```text
Observed URL:
https://www.windows.com-pt-brprincipal380294208@dt3-161255673571.southamerica-east1.run.app
```

**URL Structure**
```text
Misleading user information:
www.windows.com-pt-brprincipal380294208

Actual hostname:
dt3-161255673571.southamerica-east1.run.app
```

The Windows-like string appears before the `@` character and is not the destination hostname. The actual hostname is `dt3-161255673571.southamerica-east1.run.app`.

URLScan.io resolved the hostname to `34.143.76.2`, associated with Google Cloud Platform, and returned an HTTP `404 Not Found` response during the scan. The scan showed an HTTP-to-HTTPS redirect on the same hostname and identified no HTML forms in the captured DOM.

These results do not demonstrate a functioning credential-harvesting page at the time of scanning. However, the misleading URL structure, combined with the email's impersonation and threatening content, supports treating the URL as suspicious.
<br>
## IOCs Summary

| **Field** | **Finding** |
|---|---|
| **Sender (claimed)** | `Detran - Alerta de Penalidade` |
| **Sender (actual)** | `detran@sistemadeinfracao054752` |
| **Sender IP** | `45.77.197.210` (Vultr-hosted infrastructure) |
| **Subject** | Departamento de Trânsito: Notificação de suspensão pendente da CNH. Registro: 727660475 |
| **SPF/DKIM/DMARC** | `none / none / none` |
| **Suspicious URL** | `hxxps://www[.]windows[.]com-pt-brprincipal380294208@dt3-161255673571[.]southamerica-east1[.]run[.]app` |
| **Destination IP** | `34.143.76.2` (Google Cloud Platform; observed by URLScan.io) |
| **Brand Impersonated** | Brazilian Detran traffic authority |
| **Technique** | Government impersonation + urgency + threat of driver's license suspension |
| **VirusTotal** | 12 detections reported; queried artifact requires confirmation |
| **URLScan.io** | HTTP 404; no forms detected during the scan |
| **Verdict** | Phishing attempt |
<br>

### Evidence Correlation
Detran / gov.br impersonation (detran@sistemadeinfracao054752)<br>
        ↓<br>
Unofficial sender address, unofficial government or Detran domain<br>
        ↓<br>
CNH suspension threat + deadline + urgency (social engineering)<br>
        ↓<br>
SPF: none + DKIM: none + DMARC: none<br>
        ↓<br>
Sender IP: 45.77.197.210 (Vultr-hosted infrastructure)<br>
        ↓<br>
Deceptive URL structure + Google Cloud-hosted destination<br>
        ↓<br>
12/93 VirusTotal detections<br>
        ↓<br>
HTTP 404 response + no HTML forms detected during the scan<br>
        ↓<br>
Overall Assessment: Phishing attempt; credential theft not confirmed<br>

---

## Step 9: Final Assessment
## Final Assessment

The analyzed email is assessed as a **phishing attempt impersonating Brazil's Detran traffic authority**. The message uses the threat of driver's license (CNH) suspension, a specific deadline, and official-looking government branding to pressure the recipient into clicking a suspicious URL.<br>
Email header analysis identified the originating IP address `45.77.197.210`, associated with Vultr hosting infrastructure. SPF and DKIM returned `none`, while DMARC also returned `none`, providing no positive authentication evidence supporting the claimed sender identity.<br>
The decoded HTML revealed a call-to-action URL containing a misleading Windows-like string before the `@` character. The actual destination hostname is `dt3-161255673571.southamerica-east1.run.app`. VirusTotal reported 16 detections during the investigation, although the specific queried artifact should be confirmed. URLScan.io associated the hostname with IP address `34.143.76.2` and returned an HTTP `404 Not Found` response, with no HTML forms detected during the scan.

Taken together, the email content, suspicious URL structure, authentication results, and reported reputation detections support classifying the message as a phishing attempt.


<br>

## Tools Used

| Tool | Command / Action |
|---|---|
| [Mozilla Thunderbird](https://www.thunderbird.net/) | Opened the `.eml` sample to inspect the email message and its contents. |
| [Sublime Text](https://www.sublimetext.com/) | Opened `sample-10102.eml` to inspect the raw email headers and body. |
| [emlAnalyzer](https://github.com/wahlflo/eml_analyzer) | `emlAnalyzer -i sample-10102.eml --header -a -u` |
| [IOC-Finder](https://github.com/fhightower/ioc-finder) | `cat sample-10102.eml \| ioc-finder` |
| [MXToolbox](https://mxtoolbox.com/) | Pasted email headers into Header Analyzer to examine header information. |
| [PhishTool](https://www.phishtool.com/) | Analyzed the email to support phishing investigation and assessment. |
| [CyberChef](https://gchq.github.io/CyberChef/) | Used `From Base64` to decode the email body and inspect the HTML content. |
| [VirusTotal](https://www.virustotal.com/) | Submitted the suspicious URL or hostname for reputation analysis. |
| [urlscan.io](https://urlscan.io/) | Submitted the destination URL to examine its observed behavior, HTTP response, redirects, and hosting infrastructure. |