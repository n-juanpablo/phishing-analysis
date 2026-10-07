# Overview<br>

| Field | Details |
|---|---|
| Date & Time | 25-02-2026 |
| Sample | `sample02.eml` |
| Brand Impersonated | DHL |
| Target Audience | DHL customer |
| Primary Attack Vector | Malicious Attachment |
<br><br>
---

## First Contact - What the Victim Sees

Before performing deeper technical analysis, the email is examined from the recipient's perspective to understand how the message attempts to appear legitimate and influence the recipient's behavior.<br><br>

![First Contact](../screenshots/sample02/First%20contact.png)

- The official DHL logo is used to make the email appear legitimate.
- A message stating "Your shipment is on hold: Action required for package", accompanied by a tracking ID.
- An urgent call to action asking the recipient to make a payment to release the package and enable another delivery attempt.
- An `.exe` attachment disguised as a `.pdf` file.

Together, these elements make the email appear trustworthy and convincing to the victim, increasing the likelihood that they will fall for the phishing attempt.

### Tool
- [Thunderbird](https://www.thunderbird.net/)
<br><br>



## Step 1: Initial Triage

Safely open the email and read it while avoiding any accidental interaction with potentially malicious hyperlinks, attachments, or active content. This is where we train our eye to manually spot red flags.

```bash
subl phishing-DHL.eml
```
![Step 1 - Initial Triage](../screenshots/sample02/Step%201.png)


**Sender identity:**
The displayed sender is `DHL Express <track@dhl-global-logistics.net>`.

**Subject and Social Engineering:**
The message uses several social engineering techniques to create a sense of urgency and increase the perceived legitimacy of the request.

**Pretexting:** The attacker establishes a plausible scenario involving an existing shipment, an incomplete shipping invoice, and a failed delivery attempt to justify the requested action.

**Urgency:** The phrase "Your shipment is on hold" creates a sense that immediate action is required to resolve an ongoing problem.

**Call to action with financial pressure:** The recipient is presented with a specific action: reviewing the invoice and paying a shipping fee to release the package.

Using a small amount ($2.95) may appear insignificant and reduce the recipient's reluctance to comply.

**Specificity / Personalization:** The package number `#4920112` makes the message appear more specific and legitimate than a generic delivery notification.

**Fear / Loss avoidance:** The possibility of a delayed or unsuccessful delivery creates concern about losing access to the expected package.

**Authority / Brand impersonation:** The message presents itself as DHL Express, leveraging the trust associated with a recognizable logistics company. This offers visual legitimacy.

**Attachment (filename):** `Shipping_Invoice_DHL_4920112.pdf.exe`

The filename uses a **double extension** (`.pdf.exe`), which may be intended to make the file appear to be a PDF while its final extension identifies it as an executable file.

### Tool
- [Sublime Text](https://www.sublimetext.com/)

<br><br>

## Step 2: Safe Handling & Evidence Preservation

The original `.eml` and the `.eml` file attached are preserved as evidence, and subsequent analysis is performed against a working copy where appropriate.

Potentially malicious links and attachments are not opened directly on the host system.

**Evidence Integrity**

The SHA-256 hash is calculated using the `sha256sum` utility.

![Step 2 - Safe Handling & Evidence Preservation](../screenshots/sample02/Step%202.jpeg)
<br><br>

## Step 3: Extract URLs and list attachments

`emlAnalyzer` simplifies EML analysis by providing structured output and automatically identifying URLs and attachments.


### Command

```bash
emlAnalyzer -i sample02.eml --header -a -u
```

### Findings

The EML analysis confirmed that the message contains a multipart structure with an HTML body and one file attachment. No URLs were identified in the HTML or text parts.

![Step 3 - Extract URLs and list attachments](../screenshots/sample02/Step%203.jpeg)

### Tool

- [emlAnalyzer](https://github.com/armbues/emlAnalyzer)
<br><br><br>

## Step 4: Extract IoCs automatically (ioc-finder)

`ioc-finder` is used to automatically extract potentially relevant Indicators of Compromise from the email for further investigation.


**Command**

```bash
cat phishing-DHL.eml | ioc-finder
```
<br>

**Extracted IOCs**

![Step 4 - IOC Extraction](../screenshots/sample02/Step%204.jpeg)
| Type | Indicator | Context |
|---|---|---|
| Domain | `dhl-global-logistics.net` | Sender domain |
| Email | `track@dhl-global-logistics.net` | Sender address |
| SHA-256 | `aebf5a5b2fbafb5ed6d4c8105e84a18b61c6b47f2160c092687e551a2d9c54dd` | Extracted attachment |

The `ioc-finder` output included `example.com` and `recipient@example.com`. These were excluded from the IOC set as placeholder values present in the sample.
<br>

**Tool**

- [ioc-finder](https://github.com/fhightower/ioc-finder)

<br><br>

## Step 5: Header & Authentication

`MXToolbox` analyzes email headers and domain configuration to inspect authentication-related information and available delivery data.

**Email Authentication**

No SPF, DKIM, or DMARC authentication results are available in the EML headers.

![Step 5 - Header & Authentication](../screenshots/sample02/Step%205.png)

| Mechanism | Result | Observation |
|---|---|---|
| SPF | None | No SPF authentication result is available in the EML headers. |
| DKIM | None | No DKIM authentication result is available in the EML headers. |
| DMARC | None | No DMARC authentication result is available in the EML headers. |

**DMARC Compliance**

No DMARC record was found for `dhl-global-logistics.net`.

**Header Findings**

- **Originating IP:** `Not available`
- **Reverse DNS:** `Not available`
- **Return-Path:** `Not present`
- **From:** `track@dhl-global-logistics.net`
- **Reply-To:** `Not present`
- **Message-ID:** `Not present`

The available EML does not contain sufficient header information to determine the originating IP, reverse DNS, or message delivery path.

**Tool:**
- [MXToolbox](https://mxtoolbox.com/)

<br><br>

## Step 6: IOC Enrichment

The email did not provide sufficient delivery-path information to enrich an originating IP or related infrastructure. No actionable URL was identified in the message.<br>
The absence of reputation data does not indicate that the indicators are benign. It only means that no additional intelligence could be established from the available sources.<br><br>

## Step 7: URL / Attachment Analysis

### VirusTotal

**SHA-256:**

`aebf5a5b2fbafb5ed6d4c8105e84a18b61c6b47f2160c092687e551a2d9c54dd`

![Step 6 - IOC Enrichment](../screenshots/sample02/Step%206.png)

VirusTotal returned no existing analysis or reputation data for this hash.

The absence of VirusTotal data does not establish that the attachment is benign or malicious.
<br>

### Attachment Analysis

The attachment presents characteristics consistent with a potential executable delivery mechanism, particularly the `.pdf.exe` double extension and its use within a shipment-related phishing narrative.

**Filename:** `Shipping_Invoice_DHL_4920112.pdf.exe`

**Type:** `application/octet-stream` / `.exe`

**SHA-256:**

`aebf5a5b2fbafb5ed6d4c8105e84a18b61c6b47f2160c092687e551a2d9c54dd`

**Static Analysis**

The filename uses a double extension (`.pdf.exe`), which may be intended to make the file appear to be a PDF while its final extension identifies it as an executable.
The file was Base64-encoded within the EML.

### Tool:
- [VirusTotal](https://www.virustotal.com/)



<br><br>

## Step 8: Evidence Correlation
### Key Correlations

Microsoft impersonation (microsoftonline-verify.com)<br>
↓<br>
Unusual sign-in activity pretext + Urgency + Account-security pressure<br>
↓<br>
SPF / DKIM / DMARC failures<br>
↓<br>
178.238.225.91<br>
↓<br>
Contabo-hosted infrastructure<br>
↓<br>
Shortened URL destination could not be determined (currently inactive/404)<br>
↓<br>
1/92 VirusTotal detection (classified as Phishing)<br>
↓<br>
Suspicious phishing activity<br>

<br>

## Step 9: Final Assessment

After correlating the findings collected throughout the investigation, the email is assessed as **suspicious phishing activity**.

- The sender impersonates DHL Express using the domain `dhl-global-logistics.net`.
- The message uses a shipment-related pretext, urgency, financial pressure, and brand impersonation to influence the recipient.
- The available EML does not contain SPF, DKIM, or DMARC authentication results.
- No DMARC record was identified for `dhl-global-logistics.net`.
- The message contains an executable attachment named `Shipping_Invoice_DHL_4920112.pdf.exe`, using a double extension that may be intended to disguise its executable nature.
- The attachment's SHA-256 hash is `aebf5a5b2fbafb5ed6d4c8105e84a18b61c6b47f2160c092687e551a2d9c54dd`.
- VirusTotal returned no existing reputation data for the attachment hash.
- No originating IP or sufficient delivery headers were available to reconstruct the message's delivery path.
- The available evidence does not establish that the attachment itself is malicious.

<br><br><br>

### IOCs Summary

| Field | Finding |
|---|---|
| **Sender** | DHL Express |
| **Sender Address** | `track@dhl-global-logistics.net` |
| **Sender Domain** | `dhl-global-logistics.net` |
| **Attachment** | `Shipping_Invoice_DHL_4920112.pdf.exe` |
| **Attachment SHA-256** | `aebf5a5b2fbafb5ed6d4c8105e84a18b61c6b47f2160c092687e551a2d9c54dd` |
| **SPF/DKIM/DMARC** | No authentication results available |
| **DMARC Record** | Not found |
| **Brand Impersonated** | DHL |
| **Technique** | Phishing via DHL impersonation, shipment pretext, urgency, financial pressure, and executable attachment disguised with a double extension |
| **Additional Indicators** | No originating IP available; no Return-Path, Reply-To, or Message-ID present |
| **Verdict** | **Phishing** |

<br><br>

### Tools Used

| Tool | Command / Action |
| ---- | --------------------------------------------- |
| [Thunderbird](https://www.thunderbird.net/) | Render and visually inspect the email from the recipient's perspective |
| [Sublime Text](https://www.sublimetext.com/) | `subl phishing-DHL.eml` |
| `sha256sum` | Calculate SHA-256 hash of the original EML and extracted attachment |
| [emlAnalyzer](https://github.com/armbues/emlAnalyzer) | `emlAnalyzer -i phishing-DHL.eml --header -a -u` |
| [ioc-finder](https://github.com/fhightower/ioc-finder) | `cat phishing-DHL.eml \| ioc-finder` |
| [MXToolbox](https://mxtoolbox.com/) | Analyze email authentication and domain configuration |
| [VirusTotal](https://www.virustotal.com/) | Submitted attachment SHA-256 → File reputation analysis |
