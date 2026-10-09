import { ToyKeySpace } from './csToyProof';
import type { CsCiphertext, CsPublicKey } from './cramerShoup';

type Request =
  | { id: number; kind: 'init'; publicKey: CsPublicKey }
  | { id: number; kind: 'histogram'; ct: CsCiphertext; alpha: bigint }
  | { id: number; kind: 'observe'; ct: CsCiphertext; alpha: bigint; accepted: boolean };

let space: ToyKeySpace | null = null;
self.onmessage = (event: MessageEvent<Request>) => {
  const request = event.data;
  try {
    if (request.kind === 'init') {
      space = new ToyKeySpace(request.publicKey);
      self.postMessage({ id: request.id, result: { q: space.q, w: space.w, C: space.C, D: space.D, remaining: space.remaining } });
      return;
    }
    if (!space) throw new Error('Start a toy proof session first.');
    const result = request.kind === 'histogram'
      ? space.histogram(request.ct, request.alpha)
      : space.observe(request.ct, request.alpha, request.accepted);
    self.postMessage({ id: request.id, result });
  } catch (error) {
    self.postMessage({ id: request.id, error: error instanceof Error ? error.message : 'Unknown proof error.' });
  }
};
