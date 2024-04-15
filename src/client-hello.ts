/* eslint-disable @typescript-eslint/no-unused-vars */
import crypto from 'node:crypto';

// TODO: use host & publickey
export const clientHello = (publicKey: Uint8Array, host?: string) => {
  const handshakeRecord = Buffer.from([0x16]);

  // Recc. to use TLS1.0 (0x03, 0x01) for backwards compat. (see https://tls13.xargs.org/#client-hello/annotated)
  const tlsVersion = Buffer.from([0x03, 0x01]);

  const length = Buffer.from([0x00, 0x00]); // TODO: calculate the length of the remaining

  const recordHeader = Buffer.concat([handshakeRecord, tlsVersion, length]);

  const clientHello = Buffer.from([0x01]);

  const length2 = Buffer.from([0x00, 0x00, 0x00]); // TODO: calculate the length of the remaining

  const handshakeHeader = Buffer.concat([clientHello, length2]);

  // TLS 1.2 given (see note in https://tls13.xargs.org/#client-hello/annotated)
  const clientVersion = Buffer.from([0x03, 0x03]);

  const clientRandom = crypto.randomBytes(32);

  const sessionIdLength = Buffer.from([0x20]); // Session id length (32 bytes === 0x20)
  const randomSessionId = crypto.randomBytes(32);
  const sessionId = Buffer.concat([sessionIdLength, randomSessionId]);

  const ciphersLength = Buffer.from([0x00, 0x02]);
  const supportedCiphers = Buffer.from([0x13, 0x01]); // We will only support TLS_AES_128_GCM_SHA256
  const cipherSuites = Buffer.concat([ciphersLength, supportedCiphers]);

  const compressionLength = Buffer.from([0x01]);
  const compressionNull = Buffer.from([0x00]); // TLS 1.3 doesn't support compression
  const compressionMethods = Buffer.concat([
    compressionLength,
    compressionNull,
  ]);

  /**
   * Extensions
   */
  const extensionsLength = Buffer.from([0x00, 0xa3]); // TODO: Extensions length

  // Extension: server name indication
  const serverNameExt = Buffer.from([0x00, 0x00]);
  const serverNameLengthRemaining = Buffer.from([0x00, 0x0f]); // TODO: Change this if not using google.com
  const serverNameFirstEntryLength = Buffer.from([0x00, 0x0d]); // TODO: Change this if not using google.com
  const entryType = Buffer.from([0x00]); // Entry type for "DNS Hostname"
  const hostnameLength = Buffer.from([0x00, 0x0a]);
  const hostname = Buffer.from([
    0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
  ]); // google.com
  const extensionServerName = Buffer.concat([
    serverNameExt,
    serverNameLengthRemaining,
    serverNameFirstEntryLength,
    entryType,
    hostnameLength,
    hostname,
  ]);

  // Extension: Supported elliptic curve point formats
  const ecPointFormatsExt = Buffer.from([0x00, 0x0b]);
  const ecPointFormatsLengthRemaining = Buffer.from([0x00, 0x02]);
  const ecPointFormatsLength = Buffer.from([0x01]);
  const ecPointFormatsUncompressed = Buffer.from([0x00]);
  const extensionEcPointFormats = Buffer.concat([
    ecPointFormatsExt,
    ecPointFormatsLengthRemaining,
    ecPointFormatsLength,
    ecPointFormatsUncompressed,
  ]);

  // Extension: Supported groups for key exchange
  const supportedGroupsExt = Buffer.from([0x00, 0x0a]);
  const groupsDataLength = Buffer.from([0x00, 0x04]);
  const groupsLength = Buffer.from([0x00, 0x02]);
  const secp256r1 = Buffer.from([0x00, 0x17]);
  const extensionSupportedGroups = Buffer.concat([
    supportedGroupsExt,
    groupsDataLength,
    groupsLength,
    secp256r1,
  ]);

  // const extensionSessionTicket = Buffer.concat([]);
  // const extensionEncryptThenMAC = Buffer.concat([]);
  // const extensionExtendedMasterSecret = Buffer.concat([]);

  // Extension: signature algorithms
  const signatureAlgorithmsExt = Buffer.from([0x00, 0x0d]);
  const signatureAlgorithmsDataLength = Buffer.from([0x00, 0x06]);
  const signatureAlgorithmsLength = Buffer.from([0x00, 0x04]);
  const ecdsa_secp256r1_sha256 = Buffer.from([0x04, 0x03]);
  const rsa_pss_rsae_sha256 = Buffer.from([0x08, 0x04]);
  const extensionSignatureAlgorithms = Buffer.concat([
    signatureAlgorithmsExt,
    signatureAlgorithmsDataLength,
    signatureAlgorithmsLength,
    ecdsa_secp256r1_sha256,
    rsa_pss_rsae_sha256,
  ]);

  // Extension: supported TLS versions
  const supportedTLSVersionsExt = Buffer.from([0x00, 0x2b]);
  const supportedTLSVersionsDataLength = Buffer.from([0x00, 0x03]);
  const supportedTLSVersionsLength = Buffer.from([0x02]);
  const tlsVersion1dot3 = Buffer.from([0x03, 0x04]);
  const extensionSupportedTLSVersions = Buffer.concat([
    supportedTLSVersionsExt,
    supportedTLSVersionsDataLength,
    supportedTLSVersionsLength,
    tlsVersion1dot3,
  ]);

  // const extensionPSKKeyExchangesModes = Buffer.concat([]);

  // Extension: Key share
  const keyShareExt = Buffer.from([0x00, 0x33]);
  const keyShareDataLength = Buffer.from([0x00, 0x00]); // TODO: this
  const keyShareLength = Buffer.from([0x00, 0x00]); // TODO: this
  
  const extensionKeyShare = Buffer.concat([]);

  const extensions = Buffer.concat([
    extensionServerName,
    extensionEcPointFormats,
    extensionSupportedGroups,
    // extensionSessionTicket,
    // extensionEncryptThenMAC,
    // extensionExtendedMasterSecret,
    extensionSignatureAlgorithms,
    extensionSupportedTLSVersions,
    // extensionPSKKeyExchangesModes,
    extensionKeyShare,
  ]);

  return Buffer.concat([
    recordHeader,
    handshakeHeader,
    clientVersion,
    clientRandom,
    sessionId,
    cipherSuites,
    compressionMethods,
    extensions,
  ]);
};
