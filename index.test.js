import test from 'ava';
import { MockCredentials } from "./index.js";
import { verifyRegistrationResponse, verifyAuthenticationResponse } from "@simplewebauthn/server";

const credentials = new MockCredentials();
const origin = "https://localhost:8000";

test('create only supports attestation=none', async t => {
  await t.throwsAsync(async () => {
    await credentials.create(origin, { user: {}, attestation: "direct" });
  });
});

test('get requires existing credentialId', async t => {
  await t.throwsAsync(async () => {
    await credentials.get(origin, {}, "nonexistent-id");
  });
});

test('can register and auth against in-process relying party server', async t => {
  const setupChallenge = "RFMZLxsZFoHS6YOAxVo4yyoSEmwreexGX0Cf6t-9F6U";
  const assertionChallenge = "am3tdmXiCqTAms8uom9oTx7yiBKiVun4-4OCj4v_tTQ";
  const setupOptions = {
    challenge: setupChallenge,
    rp: { id: "example.com" },
    user: { id: crypto.randomUUID() },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    timeout: 60000,
    attestation: "none",
  };

  const setupResponse = await credentials.create(origin, setupOptions);

  const verification = await verifyRegistrationResponse({
    response: setupResponse,
    expectedChallenge: setupChallenge,
    expectedOrigin: origin,
    expectedRPID: setupOptions.rp.id,
    requireUserVerification: false,
  });

  t.true(verification.verified);

  const { credential } = verification.registrationInfo;

  const loginOptions = {
    challenge: assertionChallenge,
    rpId: setupOptions.rp.id,
    timeout: 60000,
    userVerification: "preferred",
  };

  const credentialId = credential.id.toString("base64url");

  const assertionResponse = await credentials.get(origin, loginOptions, credentialId);

  const authVerification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: origin,
    expectedRPID: setupOptions.rp.id,
    credential: credential,
    userHandle: setupOptions.user.id,
    requireUserVerification: false,
  });

  t.true(authVerification.verified);
});
