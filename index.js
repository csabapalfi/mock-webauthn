import { encodeCBOR } from "@levischuck/tiny-cbor";
import { fromArrayBuffer, toArrayBuffer } from "@hexagon/base64";
import { concat } from "uint8arrays/concat";

const FLAGS = {
  UP: 0x01, // User Present
  UV: 0x04, // User Verified
  BE: 0x40, // Backup Eligibility
  BS: 0x80, // Backup State
};

const COSE = {
  kty: 1,
  alg: 3,
  crv: -1,
  x: -2,
  y: -3,
};

export const base64url = (bytes) => fromArrayBuffer(bytes, true);

const sha256string = async (data) =>
  new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data))
  );

const sha256bytes = async (data) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", data));

function convertRawToDer(rawSignature) {
  const raw = new Uint8Array(rawSignature);
  const half = raw.length / 2;
  const r = trimLeadingZeroes(raw.slice(0, half));
  const s = trimLeadingZeroes(raw.slice(half));

  return concat([
    new Uint8Array([0x30, 2 + r.length + 2 + s.length]), // SEQUENCE
    new Uint8Array([0x02, r.length]), // INTEGER r
    r,
    new Uint8Array([0x02, s.length]), // INTEGER s
    s,
  ]);
}

function trimLeadingZeroes(arr) {
  let i = 0;
  while (i < arr.length && arr[i] === 0) i++;
  let slice = arr.slice(i);
  return slice[0] & 0x80 ? concat([new Uint8Array([0]), slice]) : slice;
}

export class MockCredentials {
  /** @type {Map<string, { privateKey: crypto.KeyObject, signatureCounter: number, userId: string }>} */
  credentials = new Map();

  /**
   * Creates client data JSON for WebAuthn operations
   * @private
   */
  createClientData(type, challenge, origin) {
    return new Uint8Array(
      new TextEncoder().encode(JSON.stringify({ type, challenge, origin }))
    );
  }

  /**
   * Generates authenticator data
   * @private
   */
  async createAuthData(rpId, flags, counter, attestedCredentialData = null) {
    const rpIdHash = await sha256string(rpId);
    const counterBuffer = new Uint8Array(4);
    new DataView(counterBuffer.buffer).setUint32(0, counter, false);

    return new Uint8Array(
      concat([
        rpIdHash,
        new Uint8Array([flags]),
        counterBuffer,
        ...(attestedCredentialData ? [attestedCredentialData] : []),
      ])
    );
  }

  /**
   * @param {string} origin
   * @param {RequestPasskeySetupSuccess} options
   */
  async create(origin, { rp, user: { id: userId }, challenge, attestation }) {
    if (attestation !== "none")
      throw new Error('Only "none" attestation supported');

    const clientDataJSON = this.createClientData(
      "webauthn.create",
      challenge,
      origin
    );

    const credentialIdBytes = new Uint8Array(32);
    crypto.getRandomValues(credentialIdBytes);
    const credentialId = base64url(credentialIdBytes);

    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true, // Allow exporting
      ["sign", "verify"]
    );

    const publicKey = keyPair.publicKey;

    const attestedCredentialData = await this.createAttestedCredentialData(
      credentialIdBytes,
      publicKey
    );

    const authData = await this.createAuthData(
      rp.id,
      FLAGS.UP | FLAGS.BE,
      0,
      attestedCredentialData
    );

    const attestationObject = base64url(
      encodeCBOR(
        new Map([
          ["fmt", "none"],
          ["attStmt", new Map()],
          ["authData", authData],
        ])
      )
    );

    const privateKey = keyPair.privateKey;
    this.credentials.set(credentialId, {
      privateKey,
      signatureCounter: 0,
      userId,
    });

    return {
      id: credentialId,
      rawId: credentialId,
      response: {
        clientDataJSON: base64url(clientDataJSON),
        attestationObject,
      },
      clientExtensionResults: {},
      type: "public-key",
    };
  }

  /**
   * @param {string} origin
   * @param {RequestPasskeyAuthenticationSuccess} options
   * @param {string} credentialId
   */
  async get(origin, { rpId, challenge }, credentialId) {
    const credential = this.credentials.get(credentialId);
    if (!credential) throw new Error("Credential not found");

    credential.signatureCounter += 1;

    const clientDataJSON = this.createClientData(
      "webauthn.get",
      challenge,
      origin
    );
    const authenticatorData = await this.createAuthData(
      rpId,
      FLAGS.UP,
      credential.signatureCounter
    );
    const clientDataHash = await sha256bytes(clientDataJSON);
    const data = concat([authenticatorData, clientDataHash]);

    const rawSignature = await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      credential.privateKey,
      data
    );

    const signature = convertRawToDer(rawSignature);

    return {
      id: credentialId,
      rawId: credentialId,
      response: {
        clientDataJSON: base64url(clientDataJSON),
        authenticatorData: base64url(authenticatorData),
        signature: base64url(signature),
        userHandle: credential.userId,
      },
      clientExtensionResults: {},
      type: "public-key",
    };
  }

  /**
   * Creates attested credential data
   * @private
   */
  async createAttestedCredentialData(credentialIdBuffer, publicKey) {
    const aaguid = new Uint8Array(16);
    const credentialIdLength = new Uint8Array(2);
    new DataView(credentialIdLength.buffer).setUint16(
      0,
      credentialIdBuffer.length,
      false
    );

    const jwk = await crypto.subtle.exportKey("jwk", publicKey);

    const cosePublicKey = encodeCBOR(
      new Map([
        [COSE.kty, 2], // EC2
        [COSE.alg, -7], // ES256
        [COSE.crv, 1], // P-256
        [COSE.x, new Uint8Array(toArrayBuffer(jwk.x, true))],
        [COSE.y, new Uint8Array(toArrayBuffer(jwk.y, true))],
      ])
    );

    return concat([
      aaguid,
      credentialIdLength,
      credentialIdBuffer,
      cosePublicKey,
    ]);
  }
}
