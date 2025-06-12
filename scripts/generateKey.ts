import {
  Oprf,
  derivePrivateKey,
  generatePublicKey,
  randomPrivateKey,
} from "@cloudflare/voprf-ts";
import { fromUint8Array, toUint8Array } from "js-base64";

const generateKey = async () => {
  const suite = Oprf.Suite.P256_SHA256;
  const privateKey = await randomPrivateKey(suite);
  const publicKey = generatePublicKey(suite, privateKey);

  // use buffer to convert to base64
  const privateKeyBase64 = fromUint8Array(privateKey, true);
  const publicKeyBase64 = fromUint8Array(publicKey, true);

  const privateKeyBytes = toUint8Array(privateKeyBase64);
  const publicKeyBytes = toUint8Array(publicKeyBase64);

  // compare two uint8arrays
  console.log(
    privateKeyBytes.every((byte, index) => byte === privateKey[index])
  );
  console.log(publicKeyBytes.every((byte, index) => byte === publicKey[index]));

  console.log("Private Key:", privateKeyBase64);
  console.log("Public Key:", publicKeyBase64);
};

generateKey();
