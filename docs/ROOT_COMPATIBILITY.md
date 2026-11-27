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

## 8. CVE-2026-20626 investigated and CLOSED for our app (27.11)

The only CVE Apple itself describes as **"a malicious app may be able to gain root
privileges"**, in the Kernel component, fixed in iOS 26.3 - our build
xnu-12377.60.50.502.2 is vulnerable.

### The fix (XNU 12377.41.6 -> 12377.61.12 diff, 112 content-changed files)

`bsd/kern/kern_prot.c`:
```c
+/* mutex for synchronizing set{,re}uid */
+LCK_MTX_DECLARE_ATTR(setuid_lock, &proc_mlock_grp, &proc_lck_attr);
+	lck_mtx_lock(&setuid_lock);       /* in setuid()   */
+	lck_mtx_unlock(&setuid_lock);     /* and setreuid() */
```
`tests/setreuid.c` and `tests/task_security_config.h` were added in the same
release.  The regression test races two threads of setreuid and asserts that
`debug.test.proccnt_uid` still reports exactly one process - i.e. the race
corrupts the per-uid process count, because `chgproccnt()` runs OUTSIDE the
`kauth_cred_proc_update()` block and both threads compute it from a stale parent.
`setreuid()`'s own comment says *"We are protected from escalation by the
prechecking"* - the race breaks exactly that protection.

### The device result (`20626 setreuid`)

```
[setreuid20626] start: ruid=501 euid=501
[setreuid20626] probe setreuid(0,0)     [root (0,0)] -> -1  (EPERM)
[setreuid20626] probe setreuid(0,-1)    [root ruid]  -> -1  (EPERM)
[setreuid20626] probe setreuid(-1,0)    [root euid]  -> -1  (EPERM)
[setreuid20626] race done: calls=7008986 errors=0 unexpected-id-changes=0
[setreuid20626] final: ruid=501 euid=501
```

7,008,986 concurrent setreuid calls, zero errors, zero unexpected id changes,
euid still 501.  The `debug.test.proccnt_uid` sysctl does not exist on a release
build (r=-1), so the count corruption is not even observable.

### Why it does not escalate from our app

The race needs a process that already holds part of the privilege it is juggling
(ruid/euid/svuid 0 mixed with unprivileged ids).  A sandboxed iOS app runs as
uid 501 with svuid 501, and every setreuid that touches uid 0 is refused with
EPERM, so there is no privileged state to race and lose.  Apple's "malicious
app" scenario is a setuid helper / daemon, not a sandboxed app.

### Net: every public lead on this device is now closed

| CVE / surface | Outcome |
|---|---|
| CVE-2026-20637 (AppleSEPKeyStore UAF) | device-confirmed; freed element is poisoned (0xffffffffffffff00), reclaim impossible |
| CVE-2026-20687 (AppleJPEGDriver) | controlled 10s free CONFIRMED; PC control blocked by PAC (autda/blraa); no reclaim |
| CVE-2026-20626 (setreuid race) | fix identified exactly; NOT reachable from an unprivileged sandbox (7M calls, 0 effect) |
| CVE-2025-46285 (vm_map.timestamp) | counter wrapped to 2^32 on device, no observable effect |
| AppleJPEGDriver sel31 | deterministic assertion panic, but a FAIL-SAFE (DoS) |
| AppleJPEGDriver +0x178 index | settable, provably inert |
| selectors 26-31 | all 0xe00002c2 (bad argument) |
| hidra0x/hidra (public 20687 research) | "no public jailbreak build yet... does not provide kernel read/write today" |

**ROOTSTATE NO.** Root is not achieved, and there is no remaining public,
sandbox-reachable path to it on iPhone13,1 / 23C5027f with the information
available.

## 9. THE LEAD: AIO kevent UAF - device-proven on iOS 26.2 / 23C55 (our kernel family)

Found by a full GitHub sweep: `AIOsource/lightsword-iphone-16`.

> "All testing was done on the author's own device: **iPhone 13 (A15, arm64e),
> T8110), iOS 26.2 / 23C55 (xnu-12377.62.10)**"

xnu-12377.**62**.10 vs our xnu-12377.**60**.50.502.2 - the same XNU branch and the
same OS release (26.2), i.e. the same kernel surface.

Their `VULNS.txt` status line:

> **AIO KEVENT UAF (track B / "B12") - xnu bsd/kern/vfs/aio.c**
> Status: **[R] read confirmed on device / [R/W] write requires a zone spray**
> Access: yes, from an ordinary sandbox app (aio_read + kqueue + kevent64).

### Mechanism (their on-device log Documents/aio_uaf.log)

```
main:  lio_listio -> enqueue aio_workq_entry E1
main:  SIGEV_KEVENT in the aiocb -> knote, kn_hook = raw dangling ptr
racer: aio_return(E1)                        [FREE]
racer: aio_read(rcb[i]) on the same thread   [RECLAIM the same slot, LIFO]
kernel: do_aio_completion_and_unlock -> KNOTE(hint=1)
        -> filt_aioevent: E1->flags & AIO_COMPLETED
main:  kevent64 -> filt_aioprocess on the DANGLING entry:
          ext[0] = entry+0x28, ext[1] = entry+0x20, data = 0,
          TAILQ_REMOVE(+0x10/+0x18), aio_entry_unref(+0x2C),
          aio_proc_lock(*(+0x40))
HIT: the kevent is delivered on the reclaimed entry (ext[1] == marker)
```

So the kernel copies the FREED entry's fields into the kevent and hands them to
userland: **a kernel read from the app**, and then performs three operations
THROUGH the entry's own data (`TAILQ_REMOVE`, `aio_entry_unref`,
`aio_proc_lock`) which become write-what-where / double-free once the slot holds
a controlled object.

`aio_workq_entry` map (zone `aio_workq_zonep`, ~224 B, zeroed on free):
`+0x10` aio_proc_link (WRITE: *prev = next), `+0x20` returnval (READ ext[1]),
`+0x28` errorval (READ ext[0]), `+0x2C` refcount (unref -> double free),
`+0x40` procp (aio_proc_lock; 0 -> PANIC FAR=0x58), `+0x48` uaiocbp (-> ident),
`+0x50` aiocb (-> udata).

Two rules they derived the hard way: the reclaim request MUST be SIGEV_NONE (a
second SIGEV_KEVENT knote makes filt_aioprocess walk the entry twice ->
procp == 0 -> FAR=0x58), and reap with aio_return, never aio_cancel.

### Why this is our zone

This is the same `aio_workq_entry` teardown that produced our 48 panics
("aio_workq_entry being freed while still enqueued", pc+0x4cff40) and the same
family-B reproducer we already had. We simply never read the kevent.

### Ported into RootSuite

Module `aio kevent UAF` (build 73aabd3, run 46064944727, success,
`RootSuite_aio.ipa` on the Desktop, sha256 582B6BC5...414E1): the B1 trigger
(free + LIFO reclaim in one thread) and the B2 kevent read over 40 rounds,
logging every ext[0]/ext[1]/ident/udata and any kernel-looking VA as a KASLR
anchor.

Pass criterion: `ext[1] == 0x4141` (the spray marker) or `ext[1] == 0x200`
means the kevent was delivered on the RECLAIMED entry - a confirmed UAF read on
our build. Next gate after that: a controlled object in `aio_workq_zonep`
(224 B) to turn TAILQ_REMOVE into write-what-where, aimed at ucred+0x18 (uid).

ROOTSTATE NO. Root is not achieved; this is the first lead with a primitive
already proven on our kernel family.
