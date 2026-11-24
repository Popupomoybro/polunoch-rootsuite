# Lock analysis of `kc_matched.decompressed` (XNU xnu-12377.60.50.502.2~1, RELEASE_ARM64_T8101)

Method: capstone 5.0.7 linear disassembly of the raw Mach-O. Mapping used throughout (verified against the
given anchors: file 0x1026318 = VA 0xfffffff00802a318, file 0x1804e30 = VA 0xfffffff008808e30):
`__TEXT_EXEC`: file = 0xfb4000 + (VA - 0xfffffff007fb8000) -- code of the kernel **and all kexts**;
`__PRELINK_TEXT`: file = 0x8000 + (VA - 0xfffffff00700c000) -- kext headers/cstrings + kernel rodata.
Public cross-reference: `apple-oss-distributions/xnu` tag **xnu-12377.61.12** (closest public tag to
12377.60.50). Note: in this XNU the mutex implementation is **`osfmk/kern/lock_mtx.c`** (not `locks.c`).
Scripts written for this task (this directory): `la_r1_func.py`, `la_r2_callees.py`, `la_r3_panics.py`,
`la_r4_bl.py`, `la_r5_kextmap.py`, `la_r6_strref.py`, `la_r7_census.py`, `la_r8_census2.py`, `la_r9_final.py`.

## 1. The faulting function at file 0x1026318

### 1.1 It is **three** functions, not one (correction to the "function starts at 0x1026318" premise)

| file range | identity | evidence |
|---|---|---|
| 0x1026318 - 0x1026404 | `lck_mtx_destroy(lck, grp)` | 0x1026314 is a tail branch (`59 99 01 14`), so 0x1026318 is a start; ends with `bl panic` (noreturn, no epilogue) |
| 0x1026408 - 0x102642c | `lck_mtx_lock` fast path | **contains the faulting `casa`**; entered by direct `bl` from IOSurface (0x32e5870); 3259 `bl` sites target it image-wide |
| 0x1026430 - 0x1026b90 | `lck_mtx_lock_slow` (`lck_mtx_lock_contended` inlined) | 0x102642c `b 0x1026430`; 0x1026430 = `pacibsp; sub sp,sp,#0xc0` |

=> the faulting instruction at **0x1026418 is in `lck_mtx_lock`, not `lck_mtx_destroy`**; the
panic-formatting code is a *separate* function placed immediately before it.

### 1.2 `lck_mtx_destroy` (file 0x1026318) -- matches `lock_mtx.c:311-331`

```
01026334  ldr w9,[x0] ; and w8,w9,#0xffffff      ; tsid
0102633c  and w9,w9,#0xff000000                 ; type<<24
01026340  cmp w8,#0 ; mov w10,#0x22000000        ; LCK_TYPE_MUTEX<<24 (locks_internal.h:153 = 0x22)
01026348  ccmp w9,w10,#0,ne ; b.eq 0x10263b8     ; (tsid!=0 && type==MUTEX) -> "waiters" panic
01026350  cmp w9,w10 ; b.ne 0x10263b4            ; type != MUTEX  -> __lck_mtx_invalid_panic
01026358  ldr w9,[x0,#8]  ; cbnz 0x10263b4       ; data  != 0    -> invalid panic
01026360  ldrh w9,[x0,#0xe]; cbnz 0x10263b4      ; as_tail != 0  -> invalid panic
01026368  ldrh w9,[x0,#0xc]; cbnz 0x10263b4      ; ilk_tail != 0 -> invalid panic
01026370  str w8,[x0]                            ; type = LCK_TYPE_NONE(0), tsid preserved
01026374  adrp x8,0xfffffff00700d000 ; ldr d0,[x8,#0xb48]   ; const at file 0x9b48 = 0xf0fe2007_00000000
0102637c  stur d0,[x0,#4]                        ; grp = 0 ; data = LCK_MTX_TAG_DESTROYED
01026380  add x8,x1,#0x10 ; mov x0,x1 ; mov x1,x8           ; lck_grp_deallocate(grp,&grp->lck_grp_mtxcnt)
010263b0  b 0xfffffff008029e38                  ; tail call (file 0x1025e38: ldadd -1, refcount drop)
```

### 1.3 The "waiters" panic path (0xfffffff00802a3b8 - 0xfffffff00802a404)

```
010263b8  ldp w8,w19,[x0] ; and w20,w8,#0xffffff ; lsr w21,w8,#0x18 ; ldr w22,[x0,#8] ; mov x23,x0
010263cc  and w0,w22,#0xfffffff ; bl 0xfffffff00806fa0c   ; ctid_get_thread_unsafe(owner) (file 0x106ba0c)
010263d4  ldrh w8,[x23,#0xe] ; ldrh w9,[x23,#0xc]         ; as_tail, ilk_tail
010263dc  mov w10,#0x13f                                  ; 319 = __LINE__
010263e0  adrp x11,0xfffffff007048000 ; add x11,x11,#0xbfa ; "lock_mtx.c"  (file 0x44bfa)
010263f8  adrp x0, 0xfffffff007048000 ; add x0, x0,#0xb9c  ; format string  (file 0x44b9c)
01026404  bl 0xfffffff008808e30                           ; panic()
```
Format (file 0x44b9c): `Mutex to destroy still has waiters: %p: <0x%06x 0x%02x 0x%08x 0x%08x/%p
0x%04x 0x%04x> @%s:%d`. The trailing ` @%s:%d` and the two extra stack args are **not** in the source
call -- they are added by the `panic()` macro (`osfmk/kern/panic_call.h`:
`(panic)(ex " @%s:%d", ..., __FILE_NAME__, __LINE__)`), which is why the binary carries `lock_mtx.c:319`
(the line of the `panic(` call, `lock_mtx.c:315-319`). All 10 varargs are placed on the **stack**
(`stp x23,x20,[sp]`, `stp w21,w19,[sp+0x10]`, `stp w22,w0,[sp+0x20]`, `stp w8,w9,[sp+0x30]`,
`stp x11,w10,[sp+0x40]`); x1-x7 are unused (see sec. 1.6).

### 1.4 `lck_mtx_lock` fast path (file 0x1026408) -- where the fault happens

```
01026408  mov x8,#0 ; mrs x1,tpidr_el1 ; ldr w9,[x1,#0x440]   ; current_thread()->ctid (thread.h:890)
01026414  add x10,x0,#8                                       ; &lock->lck_mtx.val
01026418  casa x8,x9,[x10]    ; *** FAULT ***  CAS [x0+8] == 0 ? store ctid
0102641c  cmp x8,#0 ; b.ne 0x1026428 ; ret
01026428  mov w2,#0 ; b 0x1026430        ; mode = LCK_MTX_MODE_SLEEPABLE -> lck_mtx_lock_slow
```
Exactly `lck_mtx_lock_fastpath()` (`lock_mtx.c:1028-1060`): `lock_cmpxchgv(&lock->lck_mtx.val, 0,
state.val /*thread->ctid*/, &state.val, acquire)`, slow path when non-zero. `TPIDR_EL1` = thread is proven
twice: the value at +0x440 is what is CAS-ed into the owner field (the source fills it with
`thread->ctid`), and the value at +0x158 is +/-1 exactly like `lock_disable_preemption_for_thread()`
(`osfmk/arm/locks.h`, `machine.preemption_count`).
Unlock counterpart (called by the IOSurface caller): `lck_mtx_unlock` fast path at file 0x1027198 --
`mrs x1,tpidr_el1; ldr w9,[x1,#0x440]; add x8,x0,#8; casl w2,wzr,[x8]; cmp w2,w9; b.ne slow; ret`.

### 1.5 `lck_mtx_lock_slow` (file 0x1026430) -- block roles
`mov x26,x2` keeps `mode`; `cmp w26,#2` = `LCK_MTX_MODE_SPIN_ALWAYS` (0x10264e0). It does
`lock_disable_preemption_for_thread` (+1 at `[thread+0x158]`, 0x1026470), the ilk/MCS handshake
(`ldrh w9,[thread+0x148]`, `swplh`, `caslh` on `lock->ilk_tail`, 0x1026ac54-0x1026ac78), adaptive spin,
and turnstile/waitq calls (`bl 0x80806f1d0`, `bl 0x80807efb8`, `bl 0x808084bdc`, `bl 0x808081038`).
Panic tails (all verified by their format strings + `__LINE__`):
* `bl 0xfffffff00880bf54` (file 0x1807f54) = `__lck_mtx_invalid_panic` -- file 0x44c2f
  `Invalid/destroyed mutex %p: <...>`, `lock_mtx.c:165` (source 159-166)
* `bl 0xfffffff00880bfc0` (file 0x1807fc0) = `__lck_mtx_owned_panic` -- file 0x44dad
  `Mutex %p is unexpectedly owned by thread %p`, `lock_mtx.c:189` (source 185-190)
* `bl 0xfffffff00880bff0` (file 0x1807ff0) = `__lck_mtx_lock_is_sleepable_panic` -- file 0x44d31
  `Mutex %p is held as a full-mutex (spin-always lock attempted)`, `lock_mtx.c:199` (source 192-200)
* `0xfffffff00880c020` (file 0x1808020) = `__lck_mtx_not_owned_panic`, file 0x44d76, `lock_mtx.c:172`

### 1.6 What is call target `0xfffffff008808e30`? -> **`panic()`**, a noreturn function

```
01804e30  pacibsp ; sub sp,sp,#0x20 ; stp x29,x30,[sp,#0x10] ; add x29,sp,#0x10
01804e40  add x9,x29,#0x10 ; str x9,[sp,#8]      ; va_list.__stack = &caller's stack varargs
01804e48  mov x6,x30 ; xpaci x6                  ; __builtin_return_address(0)
01804e50  add x1,sp,#8 ; mov w2,#0;x3=0;x4=0;x5=0;x7=0
01804e68  bl 0xfffffff0080124c0                  ; panic_trap_to_debugger(str,&ap,0,NULL,0,NULL,ra,NULL)
01804e6c  pacibsp ...                            ; next function starts here => no `ret` => noreturn
```
Evidence: (a) the 8-argument pattern is byte-for-byte `panic()` in `osfmk/kern/debug.c:1072-1079`, whose
callee `panic_trap_to_debugger(const char *fmt, va_list *args, unsigned reason, void *ctx, uint64_t mask,
void *data, unsigned long caller, const char *initiator)` is `debug.c:1216-1218`; (b) 12 472 `bl` sites
target it across the image (vs 3259 for `lck_mtx_lock`, 3249 for `lck_mtx_unlock`); (c) the callee
consumes the va_list as a bare stack pointer (`ldr x3,[x20]` at 0x100e51c, then
`vsnprintf(buf,0x100,fmt,x3)` at 0x100e530) -- which is why every caller of `panic()` in this build stores
its varargs on the stack (also seen in `__lck_mtx_invalid_panic` and the zero-arg caller at 0xfb7fc0:
`adr x0,<str>; bl panic`). `panic` is `__abortlike __printflike(1,2)` in `osfmk/kern/panic_call.h` --
hence no epilogue after the call.

### 1.7 Lock field layout (verified against the binary) -- `lck_mtx_t` = 16 bytes, `lock_mtx.h:45-77`

| off | field | value / evidence |
|---|---|---|
| +0x00 | `lck_mtx_tsid : 24` | turnstile id; non-zero => "still has waiters" panic (0x10263b8) |
| +0x03 | `lck_mtx_type : 8` | `LCK_TYPE_MUTEX = 0x22` (`locks_internal.h:153`); cleared at 0x1026370 |
| +0x04 | `lck_mtx_grp` | zeroed by the 8-byte store at 0x102637c |
| +0x08 | `lck_mtx` (`owner:28`,`ilocked`,`spin_mode`,`needs_wakeup`,`profile`) | the word CAS-ed at 0x1026418 / 0x10271a8 |
| +0x0c | `ilk_tail : 16` | `ldrh` at 0x1026368 |
| +0x0e | `as_tail : 16` | `ldrh` at 0x1026360 |
| -- | `LCK_MTX_TAG_DESTROYED = 0xf0fe2007` | `lock_mtx.h:77`; bytes `07 20 fe f0 00 00 00 00` at file 0x9b48 |

Thread fields (names from XNU, offsets inferred from codegen): `+0x38` = `turnstile`, `+0x148` = 16-bit
MCS/ilk tail & per-CPU index, `+0x158` = `machine.preemption_count`, `+0x440` = `ctid` (0x1026410).

## 2. The IOSurface caller (file 0x32e5838)

Owner verified: `__PRELINK_INFO` (file 0x3890000) lists `com.apple.iokit.IOSurface`,
`CFBundleShortVersionString 393.2.9`, `_PrelinkExecutableLoadAddr = 0xfffffff00777ae40`, size 0x6526;
its Mach-O is at file 0x776e40 and its `__TEXT_EXEC` (code) is file 0x32c6ac0-0x32f82ec
(VA 0xfffffff00a2caac0-0xfffffff00a2fc2ec), which contains file 0x32e5838.

Four adjacent functions, all guarding the list at `this+0x198`/`this+0x1a0` with the mutex at
`this+0x148` (lock/unlock at 0x32e586c/0x32e5910, 0x32e5968/0x32e5a04, 0x32e5a54, 0x32e5ac4):

**A. 0x32e5838-0x32e5938 -- "allocate + link a shared-list entry"**
```
01025864  mov w20,#0x2bd ; movk w20,#0xe000,lsl#16     ; kIOReturnNoMemory
0102586c  ldr x0,[x0,#0x148] ; bl lck_mtx_lock          ; the faulting path's caller
01025874  ldr x8,[x19,#0x198] ; walk list: [ent+0x20]==[arg2+8] && [ent+0x58]==arg3
010258a0  adrp x0,0xfffffff007f28000 ; add x0,x0,#0xa88 ; bl 0x86aef04 ; zone alloc (kalloc_type view)
010258ac  cbz x0,0xa2e9910                              ; NULL -> return kIOReturnNoMemory
010258b8  add x0,x0,#0x10 ; ldr x1,[x25] ; ldp x2,x3,[x22] ; bl 0x8764bb0 ; init entry+0x10
010258c8  ldr x8,[x22,#0x10] ; stp x8,x21,[x23,#0x50]    ; entry->field50 = {[arg2+0x10], arg3}
010258d0..0x102590c  insert at head of list @+0x198 (tail @+0x1a0); w20 = 0
010258f0  add w20,w20,#0xc                              ; kIOReturnInternalError (entry already present)
01025910  ldr x0,[x19,#0x148] ; bl lck_mtx_unlock ; mov x0,x20 ; retab
```
Return codes: 0xe00002bd = `kIOReturnNoMemory`, 0xe00002c9 = `kIOReturnInternalError`, 0 = success
(`iokit/IOKit/IOReturn.h:142,156`). Allocation is zone-backed: 0x86aef04 is the per-view alloc thunk
(`ldr w8,[x0,#0x28]; tst w8,#0x10; csel w1,w9/w8,eq; b 0x8024f2c`); 0x8024f2c is the shared allocator
tail with a per-CPU cache (`ldrh w11,[tpidr_el1,#0x148]; add x11,x1,x11,lsl#14; ldr w11,[x11,#0x1c]`,
else `ldr x0,[x0,#0x30]; bl 0x808bb14`). The view 0xfffffff007f28a88 is inside IOSurface's `__kalloc_type`
section (0xfffffff007f28588-0xfffffff007f29148, file 0xf24588-0xf25148). The matching free is in B:
`adrp x0,0xfffffff007f28000; add x0,x0,#0xac8; bl 0x86af0f8` (0x32e59f0).

**B. 0x32e593c-0x32e5a20 -- "find, unlink and free a shared-list entry"** (default
`kIOReturnBadArgument` 0xe00002c2, IOReturn.h:147): locks the same mutex, walks the list for an entry
matching `[arg1+8]`/`arg2`, unlinks it (head/tail fixups 0x32e59c4-0x32e59e4), zone-free (0x32e59f0) and
`OSObject`-style release (0x87667e8: `ldr x8,[x0]; ands x0,x8,#-4; ...bl`).
**C. 0x32e5a34** -- iterator: lock, then per entry `ldr x0,[x22,#0x58]; ldr w3,[x19,#0x10]; bl 0xa2f2d10`,
unlock. **D. 0x32e5aa4** -- second iterator over the same list.

**Strings referenced by these functions / immediate neighbours** (all in IOSurface's `__cstring`,
file 0x777558-0x77a37b; the caller functions themselves contain no string refs):
`IONewZero failed to alloc IOSurfaceSharedListEntry` (0x7796d3), `IOSurfaceSharedRW alloc failed`
(0x779530), `IOSurfaceSharedRO alloc failed` (0x779511), `IOBufferMemoryDescriptor::inTaskWithOptions
failed to allocate a surface shared block.` (0x779706), `Unable to prepare shared entry: %08x`
(0x77979b), `Unable to set shared memory region ownership to kernel: %08x\n` (0x77975d), `IOFence:
blocking wait timed out for surface: %d\n` (0x779573), `Entry for surface handle %d %p is not equal to
%p` / `trying to free apparently bogus surface handle %d` (0x7793fb / 0x7793c9), `IOMalloc failed to
alloc handles` (0x779304), the four shared-event-handle variants (0x779478, 0x779449, 0x7794da,
0x7794aa), and `Kernel Surfaces` / `Memory Regions` / `Memory Pools` / `User Clients` (0x779291/2a1/2b0/2bd).
=> the neighbourhood is IOSurface's **shared-memory / shared-list bookkeeping** (`IOSurfaceSharedRW`,
`IOSurfaceSharedRO`, `IOSurfaceSharedListEntry`). IOSurface keeps more than one lock -- the function at
0x32e68cc uses a different one at `this+0x138`.

## 3. Census: `ldr xN, [xM, #0x148]` in `__TEXT_EXEC` (file 0xfb4000-0x3890000)

Raw pattern scan (encoding `0xF940A400|(Rn<<5)|Rt`), then capstone decode + 8-instruction look-ahead:

* **1710** `ldr xN,[xM,#0x148]` sites; destination register: `x8` 576, `x0` 398, `x9` 351, `x1` 54, ...
* **517** have a `bl` within the next 8 instructions; **246** distinct `bl` targets
* **59** are the canonical `ldr x0,[xM,#0x148]; bl`: **17 -> `lck_mtx_lock`**, **18 -> `lck_mtx_unlock`**, 24 -> other
* Top `bl` targets overall: `lck_mtx_lock` x30, a zone-backed alloc+init wrapper (0xfffffff00863a824,
  same allocator tail `bl 0x8024f2c` at file 0x1636888) x21, `lck_mtx_unlock` x21, the arm
  "spinlock acquired check" assert (0xfffffff0081668c8 -> panic `spinlock acquired check done outside of
  kernel debugger`, file string `locks_arm.c` at file 0x58739, format at file 0x587ea, line 517) x17,
  0xfffffff0083b2794 x16, 0xfffffff0080a41dc x13, ...
* ~**946** distinct containing functions (nearest-preceding-`pacibsp` heuristic; 528/1710 sites sit >0x400
  bytes from their anchor -- mostly FairPlayIOKit tables -- so this is an upper bound)
* Hits per owner (kext from `__PRELINK_INFO` + each kext's own `__TEXT_EXEC` range; "kernel" = not in any
  kext range): **kernel 621**, IOgPTPPlugin 93, IOHIDFamily 60, IOUSBHostFamily 49, AppleH11ANEInterface 45,
  hfs 45, apfs 43, AppleFirmwareKit 33, AppleJPEGDriver 32, AppleBasebandPCIMAVPDP 31, IOSkywalkFamily 31,
  AppleBasebandPCI 28, AppleH13CameraInterface 26, ... **IOSurface 393.2.9: 14 sites (9 lock/unlock)**
* 26 distinct functions both load `+0x148` *and* call `lck_mtx_lock`/`lck_mtx_unlock`

Caveat: "bl within 8 instructions" does not prove the loaded value is the callee's argument, and many
`+0x148` slots hold non-lock data -- the 59 canonical `ldr x0,[xM,#0x148]; bl` sites (35 of them
lock/unlock) are the reliable subset.

## 4. UNKNOWN (nothing fabricated)

1. **Symbol names** of everything except the functions identified above: every kext `LC_SYMTAB` is stripped
   (`nsyms=0`, `strsize=1`, e.g. IOSurface at file 0x776e40) and the container has no symtab; the kext
   `LC_FUNCTION_STARTS` `dataoff` (0x80900000) does not map into this file. Therefore the exact C
   class/method name of the IOSurface caller is **not** recoverable -- only "IOSurface shared-list entry
   insert / remove".
2. The precise `struct thread` field at **+0x148** (16-bit MCS/ilk tail *and* per-CPU index). Thread
   offsets 0x38/0x158/0x440 are inferred from codegen, not from a compiled header.
3. The name of the kalloc_type view at 0xfffffff007f28a88 (its `+0x10/+0x20` words look like PAC-signed
   pointers into IOSurface rodata but do not resolve to clean C strings).
4. Whether the panic-time "Mutex to destroy still has waiters" call really came from `lck_mtx_destroy` on
   this boot, or whether the string is merely the nearest identifiable anchor of the faulting code region --
   the faulting instruction itself is inside `lck_mtx_lock`.
5. The identity of most census `bl` targets (0xfffffff0083b2794, 0xfffffff0080a41dc, 0xfffffff00937f040, ...).
6. Runtime slide: 0xc764000 is boot-specific; all VAs here are the file's static VAs.

## 5. Source URLs

* `osfmk/kern/lock_mtx.c` -- lck_mtx_destroy 311-331, `__lck_mtx_*_panic` 157-200, lck_mtx_lock_slow 989,
  lck_mtx_lock_fastpath 1028-1060, lck_mtx_lock 1063
* `osfmk/kern/lock_mtx.h` -- lck_mtx_t / lck_mtx_state_t 45-77, LCK_MTX_TAG_DESTROYED 77
* `osfmk/kern/locks_internal.h` -- LCK_TYPE_MUTEX = 0x22 (line 153)
* `osfmk/kern/panic_call.h` -- the `panic()` macro appending ` @%s:%d`
* `osfmk/kern/debug.c` -- panic() 1072-1079, panic_trap_to_debugger 1216-1218
* `osfmk/kern/thread.h` -- `uint32_t ctid` line 890, `struct turnstile *turnstile` line 416
* `osfmk/arm/locks.h` -- `lock_disable_preemption_for_thread` -> `machine.preemption_count`
* `iokit/IOKit/IOReturn.h` -- NoMemory 0x2bd (line 142), BadArgument 0x2c2 (line 147), InternalError 0x2c9 (line 156)
(all under `https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.61.12/`)