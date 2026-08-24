<div align="right">
  <sub>Language: <b>English</b> · <a href="./README.zh-CN.md">简体中文</a></sub>
</div>

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/hero-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="./assets/hero-light.svg" />
    <img src="./assets/hero-dark.svg" width="100%" alt="Swing / Winmin — Know it. Hack it." />
  </picture>

  <p>
    <a href="https://bestwing.me"><b>Blog ↗</b></a>
    ·
    <a href="https://twitter.com/bestswngs"><b>X ↗</b></a>
    ·
    <a href="#disclosure-archive"><b>CVEs ↓</b></a>
  </p>
</div>

## About

I research vulnerabilities in the **Linux kernel**, **embedded systems**, and **network appliances**. My work spans source auditing, fuzzing, exploit development, and responsible disclosure.

CTF player with [FlappyPig](https://github.com/FlappyPig) and [r3kapig](http://r3kapig.com/).

<!-- IMPACT_START -->
> **117 public CVEs** across **12 ecosystems**, including **78 Linux kernel findings**.
<!-- IMPACT_END -->

## Selected research

- [**When ASUS IoT Devices Play Hide-and-Seek with Security**](https://bestwing.me/offbyone-conference-when-asus-iot-devices-play-hide-and-seek-with-security.html)<br>
  <sub>Off-By-One Conference · ASUS routers · IoT security</sub>

- [**Enterprise Security Appliance Vulnerability Analysis and Exploitation**](https://bestwing.me/Security-Equipment-Vulnerability-Research.html)<br>
  <sub>Secure Optical Network Cybersecurity Forum · Xianzhi Security Salon · Gateway / Firewall / VPN</sub>

- [**Vigor2960 Memoirs: Pursuit of the Elusive 0day & 1day**](https://bestwing.me/Vigor2960-Memoirs-Pursuit-of-the-Elusive.html)<br>
  <sub>Changsha CPS Security Salon · DrayTek · Vigor2960</sub>

## Focus

- **Surfaces** — Linux kernel, embedded devices, IoT, and network appliances
- **Methods** — source auditing, fuzzing, reverse engineering, and exploit development
- **Practice** — PWN, CTF, root-cause analysis, and responsible disclosure

## Recognition

- **2025 · 1st place** — 0x300 · Tianwang Cup ITAI Critical Product Vulnerability Discovery Challenge
- **2024 · Two 1st-place finishes** — 0x300 · Tianwang Cup ITAI Critical Product Vulnerability Discovery Challenge · Matrix Cup Hardware & Software Security Testing Competition
- **2023 · Champion** — 跃哥我真不会啊 · Datacon Vulnerability Analysis Track<br>
  **2nd place** — 0x300 · CSST Tianwang Cup

<details>
<summary><b>Earlier recognition</b> · 2018–2021</summary>

- **2021 · 2nd place** — 0x300 · Inaugural ITAI Critical Product Security Challenge<br>
  **Best Vulnerability Reproduction** — Tianfu Cup · Docker Escape & Ubuntu LPE
- **2019** — Chaitin · GeekPwn & HUAWEI Smart Device Security Challenge · MAXHUB Exploit
- **2018 · Best Demo Award** — Piggy mine · GeekPwn

</details>

## Publications

- **CTF Training Camp: Technical Deep Dives, Problem-Solving Methods, and Competition Skills** — *Author*
- **Fuzzing Against the Machine**<br>
  <sub>Automate vulnerability research with emulated IoT devices on QEMU</sub> — *Translator*

## Disclosure archive

The archive below is synchronized from [bestwing.me](https://bestwing.me/about/) every week.

<details>
<summary><b>Browse the complete CVE index</b> · grouped by vendor</summary>

<br />

<!-- CVE_START -->
**HUAWEI**: [CVE-2019-5268](https://www.huawei.com/cn/psirt/security-advisories/huawei-sa-20191113-01-homerouter-cn) | [CVE-2019-5269](https://www.huawei.com/cn/psirt/security-advisories/huawei-sa-20191113-01-homerouter-cn)

**DrayTek**: [CVE-2020-14472](https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-remote-code-injection/execution-vulnerability-(cve-2020-14472)/) | [CVE-2020-14473](https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-stack-based-buffer-overflow-vulnerability-(cve-2020-14473)/)

**QNAP**: [CVE-2020-2490](https://www.qnap.com/en/security-advisory/qsa-20-09) | [CVE-2020-2492](https://www.qnap.com/en/security-advisory/qsa-20-09)

**CISCO**: [CVE-2021-1207](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-overflow-WUnUgv4U) | [CVE-2021-1209](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-overflow-WUnUgv4U) | [CVE-2021-1164](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-overflow-WUnUgv4U) | [CVE-2021-1307](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-overflow-WUnUgv4U) | [CVE-2021-1293](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv160-260-rce-XZeFkNHf) | [CVE-2021-1295](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv160-260-rce-XZeFkNHf) | [CVE-2021-1609](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv340-cmdinj-rcedos-pY8J3qfy) | [CVE-2021-1610](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv340-cmdinj-rcedos-pY8J3qfy)

**D-Link**: [CVE-2020-25506](https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10183)

**ZYXEL**: [CVE-2020-29299](https://www.zyxel.com/support/Zyxel-security-advisory-for-command-injection-vulnerability-of-firewalls.shtml)

**XIAOMI**: [CVE-2020-14102](https://privacy.mi.com/trust#/security/vulnerability-management/vulnerability-announcement/detail?id=23&locale=zh)

**Linux Kernel**: [CVE-2021-4001](https://access.redhat.com/security/cve/CVE-2021-4001) | [CVE-2025-38477](https://git.kernel.org/stable/c/5e28d5a3f774f118896aec17a3a20a9c5c9dfc64) | [CVE-2025-40083](https://git.kernel.org/stable/c/dd831ac8221e691e9e918585b1003c7071df0379) | [CVE-2025-68325](https://git.kernel.org/stable/c/9fefc78f7f02d71810776fdeb119a05a946a27cc) | [CVE-2026-22977](https://vulert.com/vuln-db/net--sock--fix-hardened-usercopy-panic-in-sock-recv-errqueue) | [CVE-2026-23276](https://git.kernel.org/stable/c/6f1a9140ecda3baba3d945b9a6155af4268aafc4) | [CVE-2026-23277](https://git.kernel.org/stable/c/0cc0c2e661af418bbf7074179ea5cfffc0a5c466) | [CVE-2026-23396](https://git.kernel.org/stable/c/c73bb9a2d33bf81f6eecaa0f474b6c6dbe9855bd) | [CVE-2026-23397](https://git.kernel.org/stable/c/dbdfaae9609629a9569362e3b8f33d0a20fd783c) | [CVE-2026-23398](https://git.kernel.org/stable/c/614aefe56af8e13331e50220c936fc0689cf5675) | [CVE-2026-31419](https://git.kernel.org/stable/c/2884bf72fb8f03409e423397319205de48adca16) | [CVE-2026-31420](https://git.kernel.org/stable/c/fa6e24963342de4370e3a3c9af41e38277b74cf3) | [CVE-2026-31421](https://git.kernel.org/stable/c/faeea8bbf6e958bf3c00cb08263109661975987c) | [CVE-2026-31422](https://git.kernel.org/stable/c/1a280dd4bd1d616a01d6ffe0de284c907b555504) | [CVE-2026-31423](https://git.kernel.org/stable/c/4576100b8cd03118267513cafacde164b498b322) | [CVE-2026-31424](https://git.kernel.org/stable/c/3d5d488f11776738deab9da336038add95d342d1) | [CVE-2026-31425](https://git.kernel.org/stable/c/a54ecccfae62c5c85259ae5ea5d9c20009519049) | [CVE-2026-31426](https://git.kernel.org/stable/c/f6484cadbcaf26b5844b51bd7307a663dda48ef6) | [CVE-2026-31427](https://git.kernel.org/stable/c/6a2b724460cb67caed500c508c2ae5cf012e4db4) | [CVE-2026-31428](https://git.kernel.org/stable/c/52025ebaa29f4eb4ed8bf92ce83a68f24ab7fdf7) | [CVE-2026-43085](https://git.kernel.org/stable/c/1f3083aec8836213da441270cdb1ab612dd82cf4) | [CVE-2026-43086](https://git.kernel.org/stable/c/9a91797e61d286805ae10a92cc48959c30800556) | [CVE-2026-45837](https://git.kernel.org/stable/c/4fddde2a732de60bb97e3307d4eb69ac5f1d2b74) | [CVE-2026-45838](https://git.kernel.org/stable/c/5828b9e5b272ecff7cf5d345128d3de7324117f7) | [CVE-2026-45839](https://git.kernel.org/stable/c/1c22483a2c4bbf747787f328392ca3e68619c4dc) | [CVE-2026-45840](https://git.kernel.org/stable/c/2091c6aa0df6aba47deb5c8ab232b1cb60af3519) | [CVE-2026-45841](https://git.kernel.org/stable/c/2195574dc6d9017d32ac346987e12659f931d932) | [CVE-2026-45842](https://git.kernel.org/stable/c/e76607442d5b73e1ba6768f501ef815bb58c2c0e) | [CVE-2026-45843](https://git.kernel.org/stable/c/4c1367a2d7aad643a6f87c6931b13cc1a25e8ca7) | [CVE-2026-45844](https://git.kernel.org/stable/c/1e8e3f449b1e73b73a843257635b9c50f0cc0f0a) | [CVE-2026-45845](https://git.kernel.org/stable/c/3d07ca5c0fae311226f737963984bd94bb159a87) | [CVE-2026-45846](https://git.kernel.org/stable/c/aa6c6d9ee064aabfede4402fd1283424e649ca19) | [CVE-2026-46320](https://git.kernel.org/stable/c/3bcf7aec6a9d16438f2cec29f5d7c8d5b8edf9b2) | [CVE-2026-46321](https://git.kernel.org/stable/c/f4feb1e20058e407cb00f45aff47f5b7e19a6bbf) | [CVE-2026-46322](https://git.kernel.org/stable/c/aa8963fdce667a42fb7f0bdd2909fadcab02f9a8) | [CVE-2026-53349](https://git.kernel.org/stable/c/c3009418f9fa1dcb3eb86f4d8c92583537b5faa3) | [CVE-2026-52937](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=bddc09212c24) | [CVE-2026-52938](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=375e4e33c18d) | [CVE-2026-52939](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=34080db3e70d) | [CVE-2026-52940](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=7f2fcff15e99) | [CVE-2026-52941](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=7bf563badd37) | [CVE-2026-52942](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=a84b6fedbc97) | [CVE-2026-64187](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=2094dab19d45c487285617b7b68913d0cc0c1211) | [CVE-2026-64188](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=d00c953a8f69) | [CVE-2026-64189](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=7cd9103283b26b917360ec99d7d2f2d761bcf1ab) | [CVE-2026-64190](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=25fe708bbc59289d3d1ea4b126fbc1b460a072a5) | [CVE-2026-64191](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=6036b5067a8199ba7a2dc7b377d4b9dd276d5f9e) | [CVE-2026-64411](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=a622d2e9608c9dff47fc2e5759ac7aa3a836b45d) | [CVE-2026-64537](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=f3e02edd8322) | [CVE-2026-64538](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=46c3b8191aad) | [CVE-2026-64539](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=6f5fb689fdf8) | [CVE-2026-64540](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=8ff7f2a6da4f) | [CVE-2026-64541](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=9d160b35cc34) | [CVE-2026-64542](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=d186e942365a) | [CVE-2026-64543](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1579342d7113) | [CVE-2026-64544](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=f7dd32c5179d) | [CVE-2026-64545](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=e82d8cc4321c) | [CVE-2026-64546](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=faaa1e115583) | [CVE-2026-64547](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=03f384bc0cb8) | [CVE-2026-64548](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=0c0a8ed85349) | [CVE-2026-64549](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=dd068ef04412) | [CVE-2026-64550](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=f0f1887a9e30) | [CVE-2026-64551](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1cd23ca80784) | [CVE-2026-64552](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=9e5ad06ea826) | [CVE-2026-64553](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=aedd02af1f8b) | [CVE-2026-64554](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=86f3ce81dd2b) | [CVE-2026-64555](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=ff1022c3de46) | [CVE-2026-64567](https://git.kernel.org/stable/c/a2d8d5647ed854e38f941741aea45b9eb15a6350) | [CVE-2026-64568](https://git.kernel.org/stable/c/1d067abcd37062426c59ec73dbc4e87a63f33fea) | [CVE-2026-64569](https://git.kernel.org/stable/c/56d96fededd61192cd7cc8d2b0f36adfd59036c3) | [CVE-2026-64570](https://git.kernel.org/stable/c/286e52a799fa158bdbd77da1426c4d93f9a6e7ad) | [CVE-2026-64571](https://git.kernel.org/stable/c/ebd6d37fa94bee929e0b4c9ca19fdf9b1dcf6cea) | [CVE-2026-64572](https://git.kernel.org/stable/c/f2f152e94a67bc746afaf05a1b2702c195553112) | [CVE-2026-64573](https://git.kernel.org/stable/c/c90164ca0f7036942ba088eb7ea8d3f6c2352020) | [CVE-2026-64574](https://git.kernel.org/stable/c/952c02b33f56207a160421bcd61e7ac53c9c59ae) | [CVE-2026-74517](https://git.kernel.org/stable/c/9910e835580fef3bef53b70241dd00c4bffad693) | [CVE-2026-74563](https://git.kernel.org/stable/c/78f75d632f74b8de0f081a128588f7c37d0d1164) | [CVE-2026-74569](https://git.kernel.org/stable/c/db3d0e0e5d4bc5ab4fe445b9f413d1b486508ca5)

**Netgear**: [CVE-2021-45527](https://kb.netgear.com/000064493/Security-Advisory-for-Post-Authentication-Buffer-Overflow-on-Some-Routers-Extenders-and-WiFi-Systems-PSV-2020-0437) | [CVE-2023-36187](https://kb.netgear.com/000065571/Security-Advisory-for-Pre-Authentication-Buffer-Overflow-on-Some-Routers-PSV-2020-0578)

**ASUS**: CVE-2023-35086 | CVE-2023-35087 | CVE-2023-39238 | CVE-2023-39239 | CVE-2023-39240 | CVE-2024-3079 | CVE-2024-3080

**QEMU**: [CVE-2026-66900](https://gitlab.com/qemu-project/qemu/-/issues/3879)

**Other**: CVE-2021-33630 | CVE-2021-33631 | [CVE-2021-29629](https://www.freebsd.org/security/advisories/FreeBSD-SA-21:12.libradius.asc) | [CVE-2020-15137](https://github.com/jwise/HoRNDIS/security/advisories/GHSA-8q4r-m3rh-57jx) | CVE-2020-24074 | CVE-2020-15173 | CVE-2020-28194 | CVE-2020-36109 | [CVE-2023-24805](https://github.com/OpenPrinting/cups-filters/security/advisories/GHSA-gpxc-v2m8-fr3x) | CVE-2022-43294 | [CVE-2026-9539](https://gitlab.freedesktop.org/slirp/libslirp/-/work_items/93) | [CVE-2026-22777](https://github.com/Comfy-Org/ComfyUI-Manager/security/advisories/GHSA-562r-8445-54r2)

<!-- CVE_END -->

### Acknowledgements

- **Synology** — [2021 Security Bounty Acknowledgement](https://www.synology.com/zh-tw/security/bounty_program#acknowledgement)
- **OPPO** — 2021 IoT Bug Bounty [Top 18](https://security.oppo.com/cn/charts)

</details>

---

<div align="center">
  <sub><b>KNOW IT. HACK IT.</b> · Research responsibly. Disclose clearly. · <a href="https://bestwing.me">bestwing.me</a></sub>
</div>
