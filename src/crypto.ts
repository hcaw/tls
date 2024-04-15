import crypto from "node:crypto";
import { promisify } from "node:util";

export const createX25519KeyPair = () => {
  const keyType = "x25519";
  const format = "der";
  const options = {
    publicKeyEncoding: {
      type: "spki",
      format,
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format,
    },
  };
  const generateKeyPairPromise = promisify(crypto.generateKeyPair);
  return generateKeyPairPromise(keyType, options);
};
