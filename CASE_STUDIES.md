# ShadowTrace Case Studies & Hackathon Pitch Dossier

**Target Audience:** NFSU Jury, MHA I4C Representatives, MLH Evaluators  
**Classification:** Law Enforcement Operational Intelligence  

---

## 1. Case Study Breakdown

### Case #409: "Operation DhanChor"
- **Modus Operandi:** Fake Telegram Part-Time Job Scam ("Review products & earn ₹5,000/day")
- **Suspect Anchor:** `@earnmoneyfast_bot`
- **Victim Impact:** 850+ Indian Citizens | ₹6.2 Crore Cumulative Fraud Loss
- **Laundering Kill-Chain:**
  1. **Lure:** Telegram bot `@earnmoneyfast_bot` + Landing Domain `earn-daily-income.in`
  2. **Layer 1 (Collection):** Micro-deposits to UPI mules `rajeshk.mule03@ybl`, `priya.sharma88@paytm`
  3. **Layer 2 (Consolidation):** Primary operator VPA `vikram.ops@axl` (Phone: `+918234567890`)
  4. **Layer 3 (Crypto On-ramp):** High-volume INR deposits into WazirX P2P escrow desk
  5. **Layer 4 (Blockchain Wash):** Converted to TRC-20 USDT -> Collection Wallet `TN7FfhXJakLRxCgfK4EJYbWnKXHGEREFhr` -> Layered to Wash Wallet `TJFoS6JEwpUDxMMAMjY7JG7hRgn1ekNbU1`
  6. **Layer 5 (Offshore Exit):** 89 transactions mixed via Tornado Cash router -> cashed out on Huobi CEX

#### Forensic Evidence & Graph Entities
- **Primary Anchor:** Telegram handle `@earnmoneyfast_bot`
- **Correlated Identifiers:**
  - Phone: `+918234567890` (Reliance Jio, Lucknow circle, tagged "Vikram Job Support")
  - Host IP: `45.154.98.221` (DigitalOcean Singapore)
  - Bank Accounts: Yes Bank (YESB), Paytm Payments Bank (PYTM), Axis Bank (UTIB)
  - Crypto Wallets: TRON TRC-20 (`TN7Ffh...`, `TJFoS6...`)

---

### Case #102: "Operation Vidyut"
- **Modus Operandi:** Fake Electricity Disconnection SMS -> Malware APK -> Banking Credential / OTP Theft
- **Suspect Anchor:** `bijli-pay-india.com`
- **Victim Impact:** 1,200+ Victims | ₹8.7 Crore Unauthorized Debits
- **Laundering Kill-Chain:**
  1. **Smishing Transmission:** Bulk SMS blasts from `+917891234560` (87 spam alerts)
  2. **Phishing Payload:** `bijli-pay-india.com` serving malicious `bijli_pay_v2.3.apk`
  3. **Command & Control (C2):** Hostinger Mumbai VPS `103.74.19.104:8443` exfiltrating inbound SMS & OTPs
  4. **Financial Exfiltration:** Unauthorized net-banking transfers routed into SBI Merchant UPI `quickpay.merchant@oksbi`
  5. **Crypto Layering:** Converted to ETH (`0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68`), sent through Sinbad.io mixer
  6. **Offshore Exit:** Post-mixer output converted to Bitcoin (`bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh`), liquidated on Binance (23.4 BTC)

---

## 2. Regulatory & Compliance Framework

ShadowTrace report generation conforms with Indian evidentiary & cyber legal standards:

1. **Section 94 BNSS 2023 (formerly Section 91 CrPC):**
   - Autonomous compilation of structured summons/production schedules for digital records (telecom CDRs, PSP logs, crypto exchange KYC).
2. **IT Act 2000 / 2008 Amendments:**
   - Section 43 (Unauthorized access/extraction of computer data)
   - Section 66C (Identity theft via VPA/mule impersonation)
   - Section 66D (Cheating by personation using computer resource)
3. **PMLA 2002 (Prevention of Money Laundering Act):**
   - Section 3 & 4 prosecution-ready money trail structuring for Enforcement Directorate (ED) & FIU-IND submission.
4. **MHA I4C CFCFRMS Standards:**
   - Pre-formatted FIR / Police Briefing dossier directly ingestible into the National Cybercrime Reporting Portal.

---

## 3. Official 3-Minute Hackathon Pitch Script (NFSU / MHA Jury)

### Timing & UI Action Plan

| Time | Presenter Dialogue | Live Screen Action |
|---|---|---|
| **0:00 - 0:35**<br>*(The Crisis)* | "Respected Jury and Officers. India battles over 30,000 cyber fraud complaints every day. When an Indian citizen loses their life savings to an online scam, our cyber cells face a wall: money enters a Telegram bot, hops through 5 UPI mule accounts in 10 minutes, and disappears into cross-chain crypto mixers. Manual triage takes 4 days. ShadowTrace reduces that investigation time to under 30 seconds." | Display ShadowTrace Cyberpunk UI. Show empty search bar and live status indicator. |
| **0:35 - 1:20**<br>*(Autonomous Execution)* | "Watch Operation DhanChor. We have just one suspect Telegram handle: `@earnmoneyfast_bot`. We hit 'Initiate Autonomous Trace'. ShadowTrace activates its autonomous investigation loop: it identifies the handle, discovers linked phishing domains, extracts 3 Indian UPI mule accounts across PhonePe, Paytm, and Axis Bank, correlates the operator phone in Lucknow, and follows the fiat-to-crypto bridge into WazirX and TRON wash wallets." | Select **Operation DhanChor** from dropdown, click **Initiate Autonomous Trace**. Watch live terminal thought trace update in real time. |
| **1:20 - 2:05**<br>*(Interactive Vis.js Graph)* | "Here is the result: an interactive, forensically clustered multi-hop graph. The red nodes represent critical threat vectors: our mule accounts and Tornado Cash mixer routers. Purple nodes map the blockchain laundering hops. Investigators can drag, isolate clusters, and inspect transaction velocities, revealing ₹6.2 Crores routed across 850 victims." | Interact with Vis.js Graph: zoom, drag nodes, hover over `TJFoS6...` TRON wallet and `rajeshk.mule03@ybl`. |
| **2:05 - 2:40**<br>*(Police Briefing & Export)* | "Down here, ShadowTrace generates an FIR-ready Police Briefing structured for I4C compliance and Section 94 BNSS production orders. An investigator can export the complete evidence dossier as an executive HTML dashboard, print-ready PDF, or raw Markdown in one click." | Click **Export Dossier** options (HTML / PDF / Markdown). Expand the Police Briefing accordions. |
| **2:40 - 3:00**<br>*(Impact & Conclusion)* | "ShadowTrace runs resiliently offline and live, protects operational integrity without exposing investigative heuristics, and gives Indian Law Enforcement an unfair advantage against transnational syndicates. Thank you." | Switch to Case #102 or show final Risk Score Badge (96% CRITICAL). Q&A Ready. |
