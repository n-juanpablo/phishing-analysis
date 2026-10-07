# Overview<br>

| Field | Details |
|---|---|
| Date & Time | 22-03-2026 |
| Sample | `sample03.eml` |
| Classification | Phishing |
| Brand Impersonated | Netflix |
| Target Audience | Netflix users |
<br><br>


## First Contact - What the Victim Sees

Before performing deeper technical analysis, the email is examined from the recipient's perspective to understand how the message attempts to appear legitimate and influence the recipient's behavior.<br>


- Netflix branding is used to make the email appear legitimate.
- A message stating "Your Netflix Membership is on hold", suggesting that there is an issue with the recipient's account.
- An urgent call to action asking the recipient to verify their billing and payment information to prevent their Netflix membership from being suspended.
- A hyperlink presented as "Click here to verify your account", directing the recipient to an external domain.

Together, these elements make the email appear trustworthy and convincing to the victim, increasing the likelihood that they will interact with the phishing message.<br><br>

**Tool:** [Thunderbird](https://www.thunderbird.net/)

<br><br>



## Step 1: Initial Triage

```bash
subl sample03.eml
```

Safely open the email and read it while avoiding any accidental interaction with potentially malicious hyperlinks or active content. This is where we train our eye to manually spot red flags.

**Sender identity:**
The displayed sender is `Netflix <email@netflix.intl.com>`.

**Subject and Social Engineering:**
The message uses several social engineering techniques to create a sense of urgency and increase the perceived legitimacy of the request.

**Urgency:** The phrase "Your Netflix Membership is on hold" creates a sense that immediate action is required to resolve an issue with the recipient's account.

**Fear / Loss avoidance:** The message states that failure to complete the verification process will result in the suspension of the recipient's Netflix membership, creating concern about losing access to the service.

**Call to action:** The recipient is instructed to verify their billing and payment information through a link presented as "Click here to verify your account".

**Authority / Brand impersonation:** The message presents itself as Netflix, leveraging the trust associated with a recognizable streaming service. Netflix branding is used to increase the perceived legitimacy of the email.

**Suspicious sender domain:** The sender uses `netflix.intl.com`, which differs from the official `netflix.com` domain and is inconsistent with the claimed sender identity.

**Suspicious URL:** The hyperlink points to `membership-webid934.com`, an external domain unrelated to the claimed Netflix identity.

**Remote content:** The email contains an externally hosted Netflix-branded image. Thunderbird blocked the remote content during the analysis.


**Tool:** [SublimeText](https://www.sublimetext.com/)

<br><br>



## Step 2: Safe Handling & Evidence Preservation

The original `.eml` is preserved as evidence, and subsequent analysis is performed against a working copy where appropriate.

Potentially malicious links and active content are not opened directly on the host system.

**Evidence Integrity**

The SHA-256 hash is calculated using the `sha256sum` utility.

S C R E E N S H O T
<br><br>


## Step 3: EML Analysis

The message is analyzed with `emlAnalyzer` to extract and structure the message headers, URLs, and attachments.

**Command:**

```bash
emlAnalyzer -i sample03.eml --header -a -u
```

The analysis confirms the HTML message structure and identifies the embedded remote image and phishing URL.

**No attachments were identified in the message.**

**Tool:** [emlAnalyzer](https://github.com/armbues/emlAnalyzer)
<br><br>

## Step 4: IOC Extraction

Relevant artifacts are extracted from the message using `ioc-finder` and classified as Indicators of Compromise (IoCs) for further investigation.

**Command:**

```bash
cat sample03.eml | ioc-finder
```

### Extracted IoCs

| Type | Indicator | Context |
|---|---|---|
| Domain | `netflix.intl.com` | Sender domain |
| Email | `email@netflix.intl.com` | Sender address |
| Domain | `web.com` | Mail relay / delivery infrastructure |
| IPv4 | `104.207.131.25` | Source IP in Received header |
| IPv4 | `140.82.32.95` | Mail relay IP in Received header |
| Domain | `makeit.netflix.com` | Remote image host |
| URL | `http://makeit.netflix.com/assets/netflix-logo-small-37aa32cd2cbd63dde01c529820f8b640b7a2f6ed35df981193d518adf1d39103.png` | Remote image |
| Domain | `membership-webid934.com` | Hyperlink destination |
| URL | `http://membership-webid934.com/membershipkey=9324832648389430184837738178348732/` | Account verification link |

`web.com` is a legitimate email and hosting service. Its presence in the `Received` headers indicates that the message passed through infrastructure associated with the service, but does not by itself indicate that `web.com` sent the phishing email.

**Tool:** [ioc-finder](https://github.com/fhightower/ioc-finder)
<br><br>


## Step 5: Header & Authentication

MXToolbox identified a DNS record for `netflix.intl.com`, but no DMARC record was found for the domain.

| Test | Result |
|---|---|
| DNS Record | Found |
| DMARC Record | Not found |
| DMARC Policy | Not enabled |
| BIMI Record | Not published |

The absence of a DMARC record indicates that `netflix.intl.com` does not publish a DMARC policy.
<br>

**Reverse DNS**<br>
Reverse DNS lookups were performed for the IP addresses identified in the `Received` headers.

| IP Address | PTR Record | Observation |
|---|---|---|
| `104.207.131.25` | `104.207.131.25.vultrusercontent.com` | Vultr-hosted infrastructure |
| `140.82.32.95` | `140.82.32.95.vultrusercontent.com` | Vultr-hosted infrastructure |

Both IP addresses resolve to PTR records under `vultrusercontent.com`, indicating that the message traversed infrastructure hosted on Vultr.

**Tools:**<br>
[MXToolbox](https://mxtoolbox.com/) <br>
[MXToolbox Reverse Lookup](https://mxtoolbox.com/ReverseLookup.aspx)
<br><br>


## Step 6: IOC Enrichment

The extracted indicators are enriched using external intelligence sources to determine their reputation and available contextual information.

#### VirusTotal

VirusTotal reported detections from **5/67 security vendors** for the analyzed URL.

**URL:**
`http://membership-webid934.com/membershipkey=9324832648389430184837738178348732/`

**Observed IP:** `91.209.70.101`

The URL received 5/67 detections at the time of analysis.

**Tool:** [VirusTotal](https://www.virustotal.com/)
<br><br>

## Step 7: URL / Attachment Analysis

#### URLScan.io

The analyzed URL currently returns:

```text
404 Not Found
```

| Indicator | Result |
|---|---|
| Initial Protocol | HTTP |
| Current Response | `404 Not Found` |
| URLScan Classification | No phishing classification |
| Google Safe Browsing | No classification |
| Observed IP | `91.209.70.101` |

The current `404 Not Found` response does not invalidate the other evidence collected during the investigation. It may be consistent with the phishing page having been removed or the campaign infrastructure being taken down.

**Tool:** [URLScan](https://urlscan.io/)
<br><br>

## Step 8: Evidence Correlation

The combination of brand impersonation, sender-domain impersonation, suspicious email infrastructure, and the phishing URL provides consistent evidence that the message was designed to deceive the recipient into disclosing billing and payment information.

**Key Correlations**

```text
Netflix impersonation
        ↓
email@netflix.intl.com
        ↓
Sender domain differs from official netflix.com domain
        ↓
No DMARC record identified for netflix.intl.com
        ↓
Vultr-hosted infrastructure identified in Received headers
        ↓
membership-webid934.com phishing URL
        ↓
5/67 VirusTotal detections
        ↓
Current 404 response
        ↓
Urgency + account suspension threat + billing information request
        ↓
Overall Assessment
```
<br>

**Correlated Findings**

- The message uses urgency and the threat of account suspension to persuade the recipient to provide billing and payment information.
- The sender impersonates Netflix using the domain `netflix.intl.com`, rather than the official `netflix.com` domain.
- The available EML does not contain SPF, DKIM, or DMARC authentication results.
- The domain `netflix.intl.com` has no DMARC record identified by MXToolbox.
- The `Received` headers identify infrastructure hosted on Vultr, with `104.207.131.25` appearing as the closest available source IP in the observed delivery path.
- The message contains a link to `membership-webid934.com`, which received `5/67` detections in VirusTotal.
- The phishing URL currently returns `404 Not Found`, indicating that the requested resource is no longer available at the analyzed location.

<br>

## Step 9: Final Assessment

The attacker uses brand impersonation, a misleading sender domain, social engineering techniques, and a link to an unrelated external domain to persuade the recipient to verify billing and payment information.

The identified infrastructure, URL reputation, and email characteristics provide additional evidence supporting this assessment.

The phishing URL currently returns `404 Not Found`, indicating that the requested resource is no longer available at the analyzed location.<br><br>

### Recommended Actions

- Do not interact with the phishing URL.
- Quarantine the email and remove similar messages from recipient mailboxes.
- Block or monitor the identified sender domain and phishing URL.
<br><br>
### IOCs Summary

| Field | Finding |
|---|---|
| **Sender (claimed)** | Netflix |
| **Sender (actual)** | `email@netflix.intl.com` |
| **Sender IP** | `104.207.131.25` (`104.207.131.25.vultrusercontent.com`) |
| **Additional IP** | `140.82.32.95` (`140.82.32.95.vultrusercontent.com`) |
| **Subject** | `Your Netflix Membership is on hold` |
| **SPF/DKIM/DMARC** | No authentication results available in EML / No DMARC record identified |
| **Phishing URL** | `http://membership-webid934[.]com/membershipkey=9324832648389430184837738178348732/` |
| **Observed URL IP** | `91.209.70.101` |
| **Brand Impersonated** | Netflix |
| **Technique** | Phishing via Netflix impersonation, account-suspension threat, billing verification request, and external phishing URL |
| **Additional Indicators** | `netflix.intl.com` sender domain; Vultr-hosted infrastructure; URL detected by 5/67 VirusTotal vendors |
<br><br>

### Analysis Tools Used

| Tool | Command / Action |
| ---- | --------------------------------------------- |
| [Thunderbird](https://www.thunderbird.net/) | Render and visually inspect the email from the recipient's perspective |
| [Sublime Text](https://www.sublimetext.com/) | Review the raw EML content and message structure |
| `sha256sum` | Calculate the SHA-256 hash of the original EML |
| [emlAnalyzer](https://github.com/armbues/emlAnalyzer) | `emlAnalyzer -i sample03.eml --header -a -u` |
| [ioc-finder](https://github.com/fhightower/ioc-finder) | `cat sample03.eml \| ioc-finder` |
| [MXToolbox](https://mxtoolbox.com/) | Analyze domain configuration and perform Reverse DNS / PTR lookups |
| [VirusTotal](https://www.virustotal.com/) | Enrich the phishing URL and review reputation results |
| [URLScan](https://urlscan.io/) | Analyze URL response behavior, redirects, and associated infrastructure |
