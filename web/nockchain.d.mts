/** uint64 values are canonical decimal strings; digests are Base58 strings. */
export type Uint64 = string;
export interface HeightRange { min?: Uint64 | null; max?: Uint64 | null }
export interface Lock { threshold: number; keys: string[]; timelock?: { relative: HeightRange; absolute: HeightRange } | null }
export interface Note { originPage: Uint64; first: string; last: string; noteDataJam: string; nicks: Uint64 }
export interface Spend { note: Note; lock: Lock; outputs: { lock: Lock; nicks: Uint64 }[]; fee: Uint64 }
export interface LockReview extends Lock { root: string }
export interface OutputReview { lockRoot: string; nicks: Uint64; parentHash: string; noteDataJam: string; lock: LockReview | null }
export interface Review { id: string; feeNicks: Uint64; outputNicks: Uint64; minimumFeeNicks: Uint64; spends: { first: string; last: string; lock: LockReview; fee: Uint64; signatureHash: string; signedKeys: string[]; outputs: OutputReview[] }[] }
export interface Wire { jam: string; summary: Review }
export interface API {
 call(method: 'receive', parameters: { zpub: string; index: number }): { index: number; address: string; lockRoot: string };
 call(method: 'derivePublic', parameters: { zpub: string; path: string }): { zpub: string; address: string; lockRoot: string };
 call(method: 'parseNocks', parameters: { amount: string }): Uint64;
 call(method: 'formatNocks', parameters: { nicks: Uint64 }): string;
 call(method: 'lock', parameters: { inputLocks: [Lock] }): LockReview & { first: string };
 call(method: 'minimumFee', parameters: { inputLocks: Lock[]; outputLocks: Lock[] }): Uint64;
 call(method: 'prepareTransaction', parameters: { plans: Spend[] }): Wire;
 call(method: 'inspect', parameters: { jam: string }): Review;
 call(method: 'verifySignatures', parameters: { jam: string }): true;
 call(method: 'validateInputs', parameters: { jam: string; notes: Note[]; height: Uint64 }): true;
 call(method: 'signTransaction', parameters: { jam: string; key: string }): Wire;
 call(method: 'mergeSignatures', parameters: { jam: string; otherJam: string }): Wire;
}
export function loadNockchain(source?: string | URL | Uint8Array | ArrayBuffer | WebAssembly.Module): Promise<API>;
