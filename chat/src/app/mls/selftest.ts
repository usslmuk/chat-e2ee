import { suiteOf } from "./suite.ts";
import { makeHpke } from "./hpke.ts";

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

const fails: string[] = [];

export function suiteSelfTest(id: number): { ok: boolean; label: string; fails: string[] } {
  const s = suiteOf(id);
  const hpke = makeHpke(id);
  const fails: string[] = [];

  const alice = hpke.keygen();
  const bob = hpke.keygen();
  if (alice.pub.length !== s.kem.dhLen) fails.push("kem public key is " + alice.pub.length + ", expected " + s.kem.dhLen);

  const e = hpke.encap(bob.pub);
  const d = hpke.decap(bob.priv, e.kemOutput);
  if (!eq(e.shared, d)) fails.push("KEM shared secrets disagree");

  const aad = new TextEncoder().encode("aad");
  const pt = new TextEncoder().encode("message body that is long enough to cross a block boundary " + "x".repeat(40));
  const ca = hpke.keySchedule(e.shared, new TextEncoder().encode("info"));
  const cb = hpke.keySchedule(d, new TextEncoder().encode("info"));
  const ct = s.aead.seal(ca.key, ca.baseNonce, aad, pt);
  const back = s.aead.open(cb.key, cb.baseNonce, aad, ct);
  if (!eq(back, pt)) fails.push("AEAD round trip failed");

  const sigKey = s.sig.keygen();
  const msg = new TextEncoder().encode("sign me");
  const sig = s.sig.sign(msg, sigKey.priv);
  if (sig.length !== s.sig.sigLen) fails.push("signature is " + sig.length + ", expected " + s.sig.sigLen);
  if (!s.sig.verify(sig, msg, sigKey.pub)) fails.push("signature does not verify");
  if (s.sig.verify(sig, new TextEncoder().encode("sign you"), sigKey.pub)) fails.push("signature verified over the wrong message");

  const other = s.sig.keygen();
  if (s.sig.verify(sig, msg, other.pub)) fails.push("signature verified under the wrong key");

  const pair = hpke.derivePair(s.hash(new TextEncoder().encode("ikm")));
  if (!eq(hpke.pubOf(pair.priv), pair.pub)) fails.push("derivePair public key does not match its private key");

  const wantNk = s.id === 2 ? 32 : 16;
  if (s.nk !== wantNk) fails.push("AEAD key length is " + s.nk + ", expected " + wantNk);
  const wantNh = s.id === 2 ? 64 : 32;
  if (s.nh !== wantNh) fails.push("hash length is " + s.nh + ", expected " + wantNh);

  void fails;
  return { ok: fails.length === 0, label: s.label, fails };
}