# ROOT_COMPATIBILITY.md — совместимость публичных методов с iPhone13,1 / iOS 26.2b1 (23C5027f)

> Обновлено 24.11.2026. Каждая строка проверена по первоисточникам (Apple Security Releases, GitHub, NVD, CISA KEV). Статус устройства: **root НЕ получен** (ROOTSTATE NO), публичного пути к root для этой конфигурации **не существует**.

## 1. Публичные джейлбрейки (инструменты)

| инструмент | поддерживаемое железо | поддерживаемые iOS | наш случай (iPhone 12 mini / A14 / 26.2b1) |
|---|---|---|---|
| **Dopamine 3.0.13** (opa334, stable 03.11.2026) | A8–A17, M1–M2 | arm64e: 15.0–17.3.1; A12/A13: 15.0–18.7.1 **и 26.0–26.0.1**; arm64: 15.0–18.7.1; **A14: 16.6–17.3.1 + 17.4 beta 1–3** | **НЕ ПОДДЕРЖИВАЕТСЯ** — A14 на iOS 26.x вне диапазона (iOS 26 = только A12/A13) |
| **palera1n 3.0.0 beta 3** (checkm8) | **только A8–A11** (+T2) | любой iOS на этом железе | **Неприменим** — A12+ не поддержан |
| **Прочее** (Misaka, Serotonin и т.п.) | — | — | публичного root для A14/iOS 26 не найдено |

**Вывод (VERIFIED):** для iPhone 12 mini на iOS 26.2 beta 1 публичного джейлбрейка/root **нет**. Единственный публичный iOS 26-джейлбрейк (Dopamine) работает на A12/A13 (iPhone 11/SE2), не на A14. Понижение прошивки невозможно (Apple не подписывает 17.x для этого устройства).

Источники: github.com/opa334/Dopamine (README + releases 3.0.13 от 03.11.2026), iclarified.com/jailbreak (обновление 07.08.2026), docs.palera.in/installing-dopamine, onejailbreak.com (Dopamine 3.0, 07.08.2026).

## 2. Уязвимости (CVE) — применимость к 23C5027f

| CVE | класс | Apple (описание/фикс) | публичный PoC | затрагивает 23C5027f? | тестирован на A14? | что даёт |
|---|---|---|---|---|---|---|
| **CVE-2025-46285** | integer overflow (32-бит timestamp → 64-бит) | Kernel, «**An app may be able to gain root privileges**», исправлено в **iOS 26.2 / 18.7.3** (12.12.2025) | не найден | **ДА** (ядро 23C5027f собрано 28.10.2025 — раньше фикса 12.12.2025) | н/д | **root-LPE** (единственный CVE с описанием root) |
| **CVE-2026-112477** | race insert/remove → stale entry (IOSurfaceRootUserClient, sel 17/18) | «unexpected system termination or corrupt kernel memory», исправлено в 26.7.2 / 27.2 | **ДА** — github.com/Rust505/CVE-2026-112477 (MIT, mode 407, kalloc.24 groom) + sparticle62ops/israce-probe | **ДА** (26.2b1 < 26.7.2) | PoC заявлен под iOS 26.4 arm64e; **наша сборка воспроизводит панику по команде** | panic/kernel corruption (не root) |
| **CVE-2026-64788** | UAF `IOGPUDevice::create_resource_iosurface` | IOGPUFamily, memory corruption, исправлено в 26.6.1 (17.08.2026) | **ДА** — ByteV0rtex/CVE-2026-64788, AmorCool/iOS26.6-CVE-2026-64788 | **ДА** (26.2b1 < 26.6.1) | **ДА — «tested on A14 Bionic, iPhone 12»** (заявлено автором PoC) | UAF-deref подтверждён; **kernel r/w заблокирован zone sequestration** (по собственному README PoC) |
| **CVE-2026-65330** | tmpfs setxattr — фиксированный PAC-диversifier `#0x307a` | исправлено в 26.6.1 | **ДА** — ByteV0rtex/CVE-2026-65330 (reachability-PoC) | **ДА** версионно (26.2b1 < 26.6.1); **применимость диversifier'а к 23C5027f НЕ подтверждена** (единственный `0x307a` в нашем ядре — номер строки в `handle_share_range`, APFS; см. RESEARCH_REPORT §5) | н/д | PC control → root **только при наличии kernel write** (вторая стадия цепочки) |
| **CVE-2026-112611** | CoreGraphics Type-5 (lattice Gouraud) shading OOB write | CoreGraphics, «maliciously crafted PDF → memory corruption», исправлено в 27.2 | публичные crash-oracle генераторы (CraftedSignal) | **ДА** (26.2b1 < 27.2) | н/д | OOB write (userland heap); **у нас AIMED WRITE CONFIRMED ×3** в своей странице |
| **CVE-2026-86950** | CoreGraphics OOB write (PDF thumbnail) | CoreGraphics, «may lead to arbitrary code execution», **эксплуатировалась в целевых атаках** (CISA KEV, добавлена 29.09.2026), исправлено в 26.7.1 | н/д (детали не публичны) | **ДА** (26.2b1 < 26.7.1) | н/д | OOB write / потенциально ACE |

## 3. Публичная цепочка эскалации iOS 26 (из документации PoC 65330)

```
CVE-2026-64788 (IOGPUFamily UAF)  ->  kernel r/w primitive
CVE-2026-65330 (PAC bypass #0x307a) ->  PC control -> root (uid=0)
```

* Обе части имеют публичные PoC; первая тестирована на A14.
* **Блокер:** README PoC 64788 прямо states, что на iOS 26 zone sequestration держит освобождённый `IOGPUSysMemory` в type-stable зоне с живыми внешними ссылками — поэтому r/w этим путём alone не получается; нужен вторичный примитив.
* Вывод: публичная цепочка **не завершается** на iOS 26 без дополнительного примитива — это согласуется с отсутствием публичного джейлбрейка для A14 на 26.x.

## 4. Наш собственный verified-слой (сверх публичных PoC)

| факт | статус |
|---|---|
| 112477-паника локализована до инструкции: `casa x8,x9,[x0+8]` (kernelcache файл 0x1026418) в пути `lock_mtx.c:319`, вызывающий kext IOSurface 393.2.9, поле `[obj+0x148]`, `far = x0+8` | VERIFIED (дизасм + 2 независимые паники) |
| Паника воспроизводима по команде (unit3 direct) | VERIFIED (device) |
| 7 паник: 6× NULL, 1× APP-MAPPING (21.11) | VERIFIED (.ips) |
| Контролируемого разыменования нашей памятью — нет (канареек в паниках нет) | VERIFIED |
| Root (uid 0) — не достигнут | VERIFIED (ROOTSTATE NO во всех прогонах) |

**Итог:** инструмент и доказательная база по 112477 превосходят публичный PoC (который только «triggers the UAF and probes groom-reachability»), но root на этой конфигурации не достигнут ни публичным, ни нашим путём.

## 5. NEW (25.11): CVE-2026-20687 - a second kernel hole in OUR build, with a PUBLIC PoC

* Apple (iOS 26.4 security content): Kernel, "An app may be able to cause
  unexpected system termination or WRITE KERNEL MEMORY", use-after-free,
  CVE-2026-20687 (Johnny Franks @0xjohnny). Fixed in 26.4 -> our 26.2b1 IS
  VULNERABLE.
* Public PoCs (validated by Mallory):
  * github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF - AppleJPEGDriver
    startDecoder() timeout UAF (ported into RootSuite as module "20687 JPEG UAF");
  * github.com/zeroxjf/CVE-2026-20687-AppleSEPKeyStore-UAF - a second PoC for
    the same CVE (AppleSEPKeyStore).
* Mechanics (from the PoC): async decodes (selector 1, struct 0x58,
  asyncToken != 0) + closing the client with requests in flight -> the freed
  JpegRequest (0x440 bytes) stays in the codec queue; a later queue walk
  (finish_io_gated -> fullSpeedRequestExist) reads the stale node -> UAF
  read/write. In the object +0x00 is a task_t (vtable-style deref = PC
  control), +0x80 is the self-pointer (first UAF read).
* Same recon (all affect our build, fixed after 26.2b1): CVE-2026-20626
  ("a malicious app may be able to gain root privileges", CWE-862, fixed 26.3,
  no public PoC); CVE-2026-39877 (IOSkywalkFamily memory corruption, fixed
  26.5 - family B's neighbourhood); CVE-2026-43655 (IOSurfaceAccelerator OOB
  read, fixed 26.5).
* Status: the trigger is in RootSuite (8 threads x 40 x 10 async decodes +
  close) and measures the JpegRequest wired-memory leak; the deferred panic
  needs one sync decode afterwards (Camera).

## 6. CVE-2026-20637 - AppleSEPKeyStore UAF, PoC TESTED ON OUR EXACT BUILD (26.1-26.2)

* Public PoC: github.com/zeroxjf/CVE-2026-20687-AppleSEPKeyStore-UAF -
  "Target Versions: iOS 26.1 - 26.2 (tested)" - exactly our 23C5027f, fixed
  in 26.3.
* Apple: AppleKeyStore, use after free, "unexpected system termination".
* Mechanics: 8 caller threads hammer IOConnectCallMethod on selectors 0-15,
  4 closer threads race IOServiceClose, the main thread opens 100k
  connections with rotating types (0x2022/0xbeef/0x1337/0x4141) and NO
  delay. The PoC's panic: "[iokit.IOCommandGate]: element modified after
  free" (a freed 80-byte gate element at offset 72).
* "This PoC immediately kernel-panics affected devices" - on our build this
  is the most direct trigger.
* Ported into RootSuite as module "20637 KeyStore UAF"; build e6bb72e
  (run 45688051653, IPA on the desktop, sha256 A52237A0...83A8C) awaits the
  device run.

## 7. hidgate-poc: the public CONTROL LADDER for CVE-2026-20687 (ported 26.11)

Two repos by hidra0x turn the panic PoC into a measured ladder:

* `hidra0x/hidgate-poc` - the open entry PoC (MOON Probe) plus
  `experiments/applejpeg/jpegclose*.m`, `jpegreclaim.m`, `jpegspray.m` and
  `docs/kernel-control.md`.
* `hidra0x/hidra` - the jailbreak project built on it. Explicitly: "There is
  no public jailbreak build yet... does not provide kernel read/write today,
  does not bypass PAC/PPL/SPTM yet".

Their measured ladder (A12 / iOS 18.7.2):

| Level | State | Evidence |
|---|---|---|
| L0 crash | PASS | AppleJPEG far=0x308 |
| L1 deferred JpegRequest UAF | PASS | finish_io_gated reads a freed request |
| L2 CONTROLLED 10s free | PASS | sync decode (asyncToken=0, flags=0) returns kIOReturnTimeout 0xe00002d6 after 10.001s |
| L3 same-type reclaim | PASS | 10 async on the same connection right after the timeout reuse the just-freed slot |
| L4 persistent stale node | PASS | far=0x308 reproduced WITHOUT Camera: close the userclient while a sync decode is in flight |
| L5 write/read primitive | NOT YET | paired reclaim still misses the slot (x12=0) |
| L6 PAC/PPL bypass | NOT YET | autda + blraa enforced |
| L7 kernel r/w + jailbreak | NOT YET | needs L5-L6 |

Why direct PC control is blocked (their analysis): the public PoC's
`*(*(request+0)+0x28)()` call sits behind `autda x16, x17` + `blraa x8, x17`
in finish_io_gated - `request->task` cannot be changed by a same-type
JpegRequest reclaim, so a fake vtable needs a PAC oracle or a kernel read
first. Their post-write strategy is data-only (process/credential/AMFI/MACF
data, no kernel text patching).

RootSuite now carries the exact ladder as module "20687 jpegclose" (build
9529ed1, run 45700127882, RootSuite_jpegclose.ipa on the desktop,
sha256 457075BE...5B5B): prime -> mass spray 8x100x10 -> early reclaim storm
(8 connections kept open, codecID = t&3) -> victim sync decode + close
DURING the sync -> second reclaim storm -> probe cycles -> free one
reclaimer at a time and probe after each.

Pass criterion on OUR device: a log line `victim sync kr=0xe00002d6
dt=10.001s` (L2 reached on A14 / 26.2b1) and/or a panic with far=0x308
without Camera (L4). Neither is root - L5 is the next gate.
