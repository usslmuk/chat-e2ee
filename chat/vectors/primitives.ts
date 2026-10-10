import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Buf, Writer } from "../src/app/mls/wire.ts";
import * as K from "../src/app/mls/hpke.ts";
import * as S from "../src/app/mls/schedule.ts";
import * as F from "../src/app/mls/frame.ts";
import * as T from "../src/app/mls/tree.ts";
import * as M from "../src/app/mls/message.ts";
import { Report, hex, suite } from "./support.ts";

const PREFIX = "MLS 1.0 ";
const bare = (label: string): string => (label.startsWith(PREFIX) ? label.slice(PREFIX.length) : label);

export async function treeMath(r: Report): Promise<void> {
  const entries = await suite("tree-math");
  for (const v of entries) {
    const n = v.n_leaves;
    r.check("root", T.root(n) === v.root, T.root(n) + " want " + v.root);
    r.check("node count", T.alloc(n) === v.n_nodes, T.alloc(n) + " want " + v.n_nodes);
    for (let x = 0; x < v.n_nodes; x++) {
      const want = (a: (number | null)[]) => a[x];
      if (T.level(x) > 0 && want(v.left) !== null) r.check("left " + x, T.left(x) === want(v.left), T.left(x) + " want " + want(v.left));
      if (T.level(x) > 0 && want(v.right) !== null) r.check("right " + x, T.right(x) === want(v.right), T.right(x) + " want " + want(v.right));
      if (x !== v.root && want(v.parent) !== null) r.check("parent " + x, T.parent(x, n) === want(v.parent), T.parent(x, n) + " want " + want(v.parent));
      if (x !== v.root && want(v.sibling) !== null) r.check("sibling " + x, T.sibling(x, n) === want(v.sibling), T.sibling(x, n) + " want " + want(v.sibling));
    }
  }
  r.family("tree-math", entries.length + " trees");
}

export async function cryptoBasics(r: Report): Promise<void> {
  const entries = await suite("crypto-basics");
  const one = (x: any) => (Array.isArray(x) ? x : x ? [x] : []);
  for (const v of entries) {
    for (const c of one(v.expand_with_label)) r.equal("expandWithLabel", S.expandWithLabel(hex(c.secret), bare(c.label), hex(c.context), c.length), c.out);
    for (const c of one(v.derive_secret)) r.equal("deriveSecret", S.deriveSecret(hex(c.secret), bare(c.label)), c.out);
    for (const c of one(v.derive_tree_secret)) r.equal("deriveTreeSecret", S.deriveTreeSecret(hex(c.secret), bare(c.label), c.generation, c.length), c.out);
    for (const c of one(v.sign_with_label)) {
      const body = F.tbsLabel(bare(c.label), hex(c.content));
      r.equal("signWithLabel", ed25519.sign(body, hex(c.priv)), c.signature);
      r.check("signWithLabel verify", ed25519.verify(hex(c.signature), body, hex(c.pub)));
      r.equal("signature public key", ed25519.getPublicKey(hex(c.priv)), c.pub);
    }
    for (const c of one(v.encrypt_with_label)) {
      const ctx = K.keySchedule(K.decap(hex(c.priv), hex(c.kem_output)), F.tbsLabel(bare(c.label), hex(c.context)));
      r.equal("encryptWithLabel", K.seal(ctx, new Uint8Array(0), hex(c.plaintext)), c.ciphertext);
    }
  }
  r.family("crypto-basics", "MLS_128_DHKEMX25519_AES128GCM");
}

export async function keySchedule(r: Report): Promise<void> {
  const entries = await suite("key-schedule");
  for (const v of entries) {
    let prev = hex(v.initial_init_secret);
    for (const [i, e] of v.epochs.entries()) {
      const at = "epoch " + i;
      const ctx = hex(e.group_context);
      const psk = hex(e.psk_secret);
      const joiner = e.commit_secret.length === 0 ? prev : S.joinerOf(prev, hex(e.commit_secret), ctx);
      const s = S.epochFromJoiner(S.joinerFromJoiner(joiner, psk), ctx);
      r.equal(at + " init_secret", s.init, e.init_secret);
      r.equal(at + " exporter_secret", s.exporter, e.exporter_secret);
      r.equal(at + " external_secret", s.external, e.external_secret);
      r.equal(at + " sender_data_secret", s.sender, e.sender_data_secret);
      r.equal(at + " encryption_secret", s.encryption, e.encryption_secret);
      r.equal(at + " confirmation_key", s.confirm, e.confirmation_key);
      r.equal(at + " membership_key", s.membership, e.membership_key);
      r.equal(at + " epoch_authenticator", s.auth, e.epoch_authenticator);
      r.equal(at + " welcome_secret", s.welcome, e.welcome_secret);
      r.equal(at + " joiner_secret", joiner, e.joiner_secret);
      prev = s.init;
    }
  }
  r.family("key-schedule", entries.length + " x 5 epochs");
}

export async function secretTree(r: Report): Promise<void> {
  const all = await suite("secret-tree");
  const entries = all.filter((v) => v.leaves.length === 1);
  for (const v of entries) {
    const enc = hex(v.encryption_secret);
    for (const leaf of v.leaves) {
      const ratchets = { handshake: S.initLeaf(enc, "handshake"), application: S.initLeaf(enc, "application") };
      for (const want of leaf) {
        for (const kind of ["handshake", "application"] as const) {
          const step = ratchets[kind];
          while (step.gen < want.generation) S.step(step);
          const out = S.step(step);
          r.equal(kind + " key " + want.generation, out.key, want[kind + "_key"]);
          r.equal(kind + " nonce " + want.generation, out.nonce, want[kind + "_nonce"]);
        }
      }
    }
    const sd = hex(v.sender_data.sender_data_secret);
    const sk = M.senderDataKeys(sd, hex(v.sender_data.ciphertext));
    r.equal("sender data key", sk.key, v.sender_data.key);
    r.equal("sender data nonce", sk.nonce, v.sender_data.nonce);
  }
  r.family("secret-tree", entries.length + " of " + all.length + " encryption secrets, per leaf ratchets in the rest are not derivable");
}

export async function deserialization(r: Report): Promise<void> {
  const entries = await suite("deserialization");
  for (const e of entries) {
    const header = Buffer.from(new Writer().vlen(e.length).out()).toString("hex");
    r.check("vlen header " + e.length, header === e.vlbytes_header, header + " want " + e.vlbytes_header);
    let decoded = -1;
    try {
      decoded = new Buf(hex(e.vlbytes_header)).vlen();
    } catch {
      decoded = -1;
    }
    r.check("vlen decode " + e.length, decoded === e.length, decoded + " want " + e.length);
  }
  r.family("deserialization", entries.length + " vector lengths");
}

export async function pskSecret(r: Report): Promise<void> {
  const entries = (await suite("psk_secret")).filter((v: any) => v.psks.length > 0);
  const id = (p: any): Uint8Array =>
    new Writer().u8(1).vec(hex(p.psk_id)).vec(hex(p.psk_nonce)).out();
  for (const v of entries) {
    r.equal("count " + v.psks.length, S.makePskSecret(v.psks.map((p: any) => hex(p.psk)), v.psks.map(id)), v.psk_secret);
  }
  r.family("psk_secret", entries.length + " entries");
}