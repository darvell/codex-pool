// ChatGPT desktop 26.928.20755 integrity protocol, evaluated in a real browser.
(() => {
  const encode = value => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(value))));
  const pick = values => values[Math.floor(Math.random() * values.length)];
  const sample = () => {
    const proto = Object.getPrototypeOf(navigator);
    const property = pick(Object.keys(proto));
    let navigatorValue = property;
    try { navigatorValue = `${property}−${String(navigator[property])}`; } catch {}
    return [screen.width + screen.height, String(new Date()), performance.memory?.jsHeapSizeLimit ?? null,
      Math.random(), navigator.userAgent, pick(Array.from(document.scripts).map(s => s.src).filter(Boolean)),
      document.documentElement.getAttribute('data-build'), navigator.language, navigator.languages.join(','),
      Math.random(), navigatorValue, pick(Object.keys(document)), pick(Object.keys(window)), performance.now(),
      crypto.randomUUID(), [...new URLSearchParams(location.search).keys()].join(','), navigator.hardwareConcurrency,
      performance.timeOrigin, Number('ai' in window), Number('createPRNG' in window), Number('cache' in window),
      Number('data' in window), Number('solana' in window), Number('dump' in window), Number('InstallTrigger' in window)];
  };
  const hash = input => {
    let value = 2166136261;
    for (let i = 0; i < input.length; i++) { value ^= input.charCodeAt(i); value = Math.imul(value, 16777619) >>> 0; }
    value ^= value >>> 16; value = Math.imul(value, 2246822507) >>> 0;
    value ^= value >>> 13; value = Math.imul(value, 3266489909) >>> 0;
    value ^= value >>> 16;
    return (value >>> 0).toString(16).padStart(8, '0');
  };
  const xor = (value, key) => [...value].map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length))).join('');
  const runChallenge = (payload, key) => new Promise((resolve, reject) => {
    const values = new Map();
    let finished = false;
    const finish = (value, error) => {
      if (finished) { return; }
      finished = true; clearTimeout(timer);
      if (error) { reject(new Error(String(value))); } else { resolve(value); }
    };
    const timer = setTimeout(() => finish(String(steps)), 500);
    let steps = 0;
    const run = async () => {
      while (values.get(9).length > 0) {
        const [opcode, ...args] = values.get(9).shift();
        const result = values.get(opcode)?.(...args);
        if (result && typeof result.then === 'function') { await result; }
        steps++;
      }
    };
    values.set(0, (p) => runChallenge(p, String(values.get(16))));
    values.set(1, (a, b) => values.set(a, xor(String(values.get(a)), String(values.get(b)))));
    values.set(2, (a, b) => values.set(a, b));
    values.set(3, value => finish(btoa(String(value))));
    values.set(4, value => finish(btoa(String(value)), true));
    values.set(5, (a, b) => { const v = values.get(a); if (Array.isArray(v)) { v.push(values.get(b)); } else { values.set(a, v + values.get(b)); } });
    values.set(6, (a, b, c) => values.set(a, values.get(b)[String(values.get(c))]));
    values.set(7, (a, ...args) => values.get(a)(...args.map(k => values.get(k))));
    values.set(8, (a, b) => values.set(a, values.get(b)));
    values.set(10, window);
    values.set(11, (a, b) => values.set(a, Array.from(document.scripts).map(s => s.src.match(String(values.get(b)))).filter(Boolean)[0]?.[0] ?? null));
    values.set(12, a => values.set(a, values));
    values.set(13, (a, b, ...args) => { try { values.get(b)(...args); } catch (error) { values.set(a, String(error)); } });
    values.set(14, (a, b) => values.set(a, JSON.parse(String(values.get(b)))));
    values.set(15, (a, b) => values.set(a, JSON.stringify(values.get(b))));
    values.set(16, key);
    values.set(17, async (a, b, ...args) => { try { values.set(a, await values.get(b)(...args.map(k => values.get(k)))); } catch (error) { values.set(a, String(error)); } });
    values.set(18, a => values.set(a, atob(String(values.get(a)))));
    values.set(19, a => values.set(a, btoa(String(values.get(a)))));
    values.set(20, (a, b, c, ...args) => values.get(a) === values.get(b) ? values.get(c)(...args) : null);
    values.set(21, (a, b, c, d, ...args) => Math.abs(Number(values.get(a)) - Number(values.get(b))) > Number(values.get(c)) ? values.get(d)(...args) : null);
    values.set(22, async (a, operations) => { const prior = [...values.get(9)]; values.set(9, [...operations]); try { await run(); } catch (error) { values.set(a, String(error)); } finally { values.set(9, prior); } });
    values.set(23, (a, b, ...args) => values.get(a) === undefined ? null : values.get(b)(...args));
    values.set(24, (a, b, c) => values.set(a, values.get(b)[String(values.get(c))].bind(values.get(b))));
    for (const opcode of [25, 26, 28]) { values.set(opcode, () => undefined); }
    values.set(27, (a, b) => { const v = values.get(a); if (Array.isArray(v)) { v.splice(v.indexOf(values.get(b)), 1); } else { values.set(a, v - values.get(b)); } });
    values.set(29, (a, b, c) => values.set(a, Number(values.get(b)) < Number(values.get(c))));
    values.set(30, (a, b, c, d) => {
      const parameters = Array.isArray(d) ? c : [];
      const operations = (Array.isArray(d) ? d : c) ?? [];
      values.set(a, async (...args) => {
        if (finished) { return; }
        const prior = [...values.get(9)];
        parameters.forEach((p, i) => values.set(p, args[i]));
        values.set(9, [...operations]);
        try { await run(); return values.get(b); } catch (error) { return String(error); } finally { values.set(9, prior); }
      });
    });
    values.set(33, (a, b, c) => values.set(a, Number(values.get(b)) * Number(values.get(c))));
    values.set(34, async (a, b) => values.set(a, await values.get(b)));
    values.set(35, (a, b, c) => values.set(a, Number(values.get(c)) === 0 ? 0 : Number(values.get(b)) / Number(values.get(c))));
    try { values.set(9, JSON.parse(xor(atob(payload), key))); run().catch(error => finish(btoa(`${steps}: ${String(error)}`))); }
    catch (error) { finish(btoa(`${steps}: ${String(error)}`)); }
  });
  globalThis.poolIntegrity = {
    prepare() {
      const start = performance.now(); const values = sample(); values[3] = 1; values[9] = performance.now() - start;
      return `gAAAAAC${encode(values)}`;
    },
    async complete(requirements, key) {
      if (requirements.force_login) { throw new Error('Upstream requires renewed account authentication'); }
      let proof = null;
      if (requirements.proofofwork?.required) {
        const {seed, difficulty} = requirements.proofofwork;
        if (!seed || !difficulty) { throw new Error('Invalid upstream proof requirement'); }
        const values = sample(); const start = performance.now();
        for (let i = 0; i < 500000; i++) {
          values[3] = i; values[9] = Math.round(performance.now() - start); const candidate = encode(values);
          if (hash(seed + candidate).substring(0, difficulty.length) <= difficulty) { proof = `gAAAAAB${candidate}~S`; break; }
        }
        if (!proof) { throw new Error('Upstream integrity proof exceeded its limit'); }
      }
      const turnstile = requirements.turnstile?.required ? await runChallenge(requirements.turnstile.dx, key) : null;
      return {proof, turnstile};
    }
  };
})();
