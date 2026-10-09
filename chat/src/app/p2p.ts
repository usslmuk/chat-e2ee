export type Signal = (to: string, data: SignalBody) => void;
export type Deliver = (to: string, payload: Uint8Array) => void;

export type SignalBody =
  | { kind: "offer"; sdp: RTCSessionDescriptionInit }
  | { kind: "answer"; sdp: RTCSessionDescriptionInit }
  | { kind: "ice"; cand: RTCIceCandidateInit };

export type Peer = {
  id: string;
  pc: RTCPeerConnection;
  dc: RTCDataChannel | null;
  open: boolean;
  remoteSet: boolean;
};

export type Mesh = {
  link: string;
  self: string;
  peers: Map<string, Peer>;
  online: Set<string>;
  signal: Signal;
  deliver: Deliver;
  onData: (from: string, payload: Uint8Array) => void;
  onChange: () => void;
};

const ICE: RTCIceServer[] = [{ urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"] }];
const MAX_PEERS = 24;

function make(id: string, initiator: boolean): Peer {
  const pc = new RTCPeerConnection({ iceServers: ICE, iceCandidatePoolSize: 2 });
  const p: Peer = { id, pc, dc: null, open: false, remoteSet: false };
  pc.oniceconnectionstatechange = () => {
    if (pc.iceConnectionState === "failed" || pc.iceConnectionState === "disconnected") {
      p.open = false;
    }
  };
  void initiator;
  return p;
}

function bind(m: Mesh, p: Peer): void {
  const attach = (dc: RTCDataChannel) => {
    p.dc = dc;
    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = 262144;
    dc.onopen = () => {
      p.open = true;
      m.onChange();
    };
    dc.onclose = () => {
      p.open = false;
      m.onChange();
    };
    dc.onmessage = (e) => {
      if (typeof e.data === "string") return;
      m.onData(p.id, new Uint8Array(e.data as ArrayBuffer));
    };
  };
  p.pc.ondatachannel = (e) => attach(e.channel);
  p.pc.onicecandidate = (e) => {
    if (e.candidate) m.signal(p.id, { kind: "ice", cand: e.candidate.toJSON() });
  };
}

export function mesh(link: string, self: string, signal: Signal, deliver: Deliver, onData: (from: string, p: Uint8Array) => void, onChange: () => void): Mesh {
  return { link, self, peers: new Map(), online: new Set(), signal, deliver, onData, onChange };
}

function slot(m: Mesh, id: string): Peer {
  const hit = m.peers.get(id);
  if (hit) return hit;
  if (m.peers.size >= MAX_PEERS) return m.peers.values().next().value as Peer;
  const p = make(id, true);
  bind(m, p);
  m.peers.set(id, p);
  return p;
}

export async function dial(m: Mesh, to: string): Promise<void> {
  if (to === m.self) return;
  const p = slot(m, to);
  if (p.pc.signalingState !== "stable") return;
  const dc = p.pc.createDataChannel("m", { ordered: true });
  bind(m, p);
  const offer = await p.pc.createOffer();
  await p.pc.setLocalDescription(offer);
  m.signal(to, { kind: "offer", sdp: p.pc.localDescription ?? offer });
}

export async function accept(m: Mesh, from: string, sdp: RTCSessionDescriptionInit): Promise<void> {
  if (from === m.self) return;
  const p = slot(m, from);
  await p.pc.setRemoteDescription(sdp);
  const answer = await p.pc.createAnswer();
  await p.pc.setLocalDescription(answer);
  m.signal(from, { kind: "answer", sdp: p.pc.localDescription ?? answer });
}

export async function settle(m: Mesh, from: string, sdp: RTCSessionDescriptionInit): Promise<void> {
  const p = m.peers.get(from);
  if (!p || p.remoteSet) return;
  if (p.pc.signalingState === "stable" && sdp.type === "offer") {
    await accept(m, from, sdp);
    return;
  }
  if (sdp.type !== "answer") return;
  p.remoteSet = true;
  await p.pc.setRemoteDescription(sdp);
}

export async function chill(m: Mesh, from: string, cand: RTCIceCandidateInit): Promise<void> {
  const p = m.peers.get(from);
  if (!p) return;
  try {
    await p.pc.addIceCandidate(cand);
  } catch (e) {}
}

export function send(m: Mesh, to: string, payload: Uint8Array): boolean {
  const p = m.peers.get(to);
  if (!p || !p.dc || p.dc.readyState !== "open") return false;
  try {
    p.dc.send(toView(payload));
    return true;
  } catch (e) {
    return false;
  }
}

function toView(v: Uint8Array): ArrayBufferView<ArrayBuffer> {
  return new Uint8Array(v) as unknown as ArrayBufferView<ArrayBuffer>;
}

export function spread(m: Mesh, payload: Uint8Array): number {
  let n = 0;
  for (const p of m.peers.values()) {
    if (p.dc && p.dc.readyState === "open") {
      try {
        p.dc.send(toView(payload));
        n++;
      } catch (e) {}
    }
  }
  return n;
}

export function hangUp(m: Mesh, id: string): void {
  const p = m.peers.get(id);
  if (!p) return;
  try {
    p.dc?.close();
    p.pc.close();
  } catch (e) {}
  m.peers.delete(id);
}

export function tearDown(m: Mesh): void {
  for (const id of [...m.peers.keys()]) hangUp(m, id);
  m.online.clear();
}

export function openPeers(m: Mesh): number {
  let n = 0;
  for (const p of m.peers.values()) if (p.open) n++;
  return n;
}

export function peersOnline(m: Mesh): string[] {
  return [...m.online].filter((x) => x !== m.self);
}