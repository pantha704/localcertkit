/**
 * certkit-lib — in-browser certificate & key utilities (RSA-first).
 *
 * UMD-ish: works as a <script> after forge.min.js (global `forge`, exports `CertKit`)
 * and as a CommonJS module in Node (require('node-forge') + module.exports).
 *
 * Gate-0 (spike):   PKCS#12 parse → key + chain + key-match + PEM export.
 * Gate-1 (MVP):     certificate / CSR decode, chain ordering, JWK inspection,
 *                   PEM → PKCS#12 write-back, ASN.1 → JSON views.
 *
 * Depends on node-forge for ASN.1/DER + crypto primitives.
 * v1 is RSA-only: EC/Ed25519 X.509 objects throw a friendly EC_UNSUPPORTED error.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('node-forge'));
  } else {
    root.CertKit = factory(root.forge);
  }
})(typeof self !== 'undefined' ? self : globalThis, function (forge) {
  'use strict';

  if (!forge) throw new Error('node-forge not found');

  // ---------- helpers ----------

  function bytesToBinaryString(bytes) {
    let s = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return s;
  }

  function binaryStringToBytes(str) {
    const out = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
    return out;
  }

  const now = () =>
    typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now();

  function toHex(binary) {
    let out = '';
    for (let i = 0; i < binary.length; i++) {
      out += (binary.charCodeAt(i) & 0xff).toString(16).padStart(2, '0');
    }
    return out;
  }

  function hexTrunc(binary, max = 96) {
    if (typeof binary !== 'string') return null;
    if (binary.length <= max) return toHex(binary);
    return toHex(binary.slice(0, max)) + '… (' + binary.length + ' bytes)';
  }

  function colonHex(binary) {
    return (toHex(binary).match(/.{2}/g) || []).join(':').toUpperCase();
  }

  /** Accepts PEM text, base64 text, Uint8Array or ArrayBuffer → Uint8Array */
  function toBytes(input) {
    if (input instanceof Uint8Array) return input;
    if (typeof ArrayBuffer !== 'undefined' && input instanceof ArrayBuffer) {
      return new Uint8Array(input);
    }
    if (typeof input === 'string') {
      const b64 = input
        .replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, '');
      if (/^[A-Za-z0-9+/=]+$/.test(b64)) {
        return binaryStringToBytes(forge.util.decode64(b64));
      }
      throw new Error('Input does not look like PEM or base64 data.');
    }
    throw new Error('Unsupported input type: expected PEM text, base64, or bytes.');
  }

  function isPemText(input) {
    return typeof input === 'string' && /-----BEGIN/.test(input);
  }

  function ecUnsupportedError() {
    const err = new Error(
      'This looks like an EC or Ed25519 object. CertKit v1 handles RSA only — ' +
        'EC/Ed25519 support is on the roadmap (v1.1).'
    );
    err.code = 'EC_UNSUPPORTED';
    return err;
  }

  /** Wrap forge parse failures with friendlier messages for the UI. */
  function friendlyParseError(prefix, e) {
    const msg = e && e.message ? e.message : String(e);
    if (/OID is not RSA|not RSA|Unsupported public key|unsupported key/i.test(msg)) {
      return ecUnsupportedError();
    }
    const err = new Error(prefix + ': ' + msg);
    err.cause = e;
    return err;
  }

  /** Friendlier message for private-key PEM inputs forge cannot read. */
  function keyFormatError(pem, e) {
    const text = String(pem || '');
    if (/-----BEGIN EC PRIVATE KEY-----|-----BEGIN ED25519 PRIVATE KEY-----/.test(text)) {
      return ecUnsupportedError();
    }
    if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(text)) {
      const err = new Error(
        'Encrypted private keys are not supported yet — decrypt the key first, e.g. ' +
          '`openssl rsa -in encrypted.key -out decrypted.key`.'
      );
      err.code = 'KEY_ENCRYPTED';
      return err;
    }
    const err = new Error(
      'Could not read the private key: expected an unencrypted RSA private key in PEM ' +
        'format (PKCS#1 or PKCS#8). EC/Ed25519 keys are on the roadmap (v1.1).'
    );
    err.code = 'KEY_FORMAT';
    err.cause = e;
    return err;
  }

  // PBE / PRF OIDs we can name (for evidence output).
  const OID_NAMES = {
    '1.2.840.113549.1.12.1.1': 'pbeWithSHAAnd128BitRC4',
    '1.2.840.113549.1.12.1.2': 'pbeWithSHAAnd40BitRC4',
    '1.2.840.113549.1.12.1.3': 'pbeWithSHAAnd3-KeyTripleDES-CBC',
    '1.2.840.113549.1.12.1.4': 'pbeWithSHAAnd2-KeyTripleDES-CBC',
    '1.2.840.113549.1.12.1.5': 'pbeWithSHAAnd128BitRC2-CBC',
    '1.2.840.113549.1.12.1.6': 'pbeWithSHAAnd40BitRC2-CBC',
    '1.2.840.113549.1.5.1': 'pbeWithMD2AndDES-CBC',
    '1.2.840.113549.1.5.3': 'pbeWithMD5AndDES-CBC',
    '1.2.840.113549.1.5.4': 'pbeWithMD2AndRC2-CBC',
    '1.2.840.113549.1.5.6': 'pbeWithMD5AndRC2-CBC',
    '1.2.840.113549.1.5.10': 'pbeWithSHA1AndDES-CBC',
    '1.2.840.113549.1.5.11': 'pbeWithSHA1AndRC2-CBC',
    '1.2.840.113549.1.5.12': 'pbkdf2',
    '1.2.840.113549.1.5.13': 'pbkdf2',
    '1.2.840.113549.2.7': 'hmacWithSHA1',
    '1.2.840.113549.2.9': 'hmacWithSHA256',
    '1.2.840.113549.3.7': 'des-ede3-cbc',
    '2.16.840.1.101.3.4.1.42': 'aes256-CBC-PAD',
  };

  const SIGNATURE_ALGORITHMS = {
    '1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption',
    '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    '1.3.101.112': 'Ed25519',
  };

  const KEY_USAGE_NAMES = {
    digitalSignature: 'Digital signature',
    nonRepudiation: 'Content commitment',
    keyEncipherment: 'Key encipherment',
    dataEncipherment: 'Data encipherment',
    keyAgreement: 'Key agreement',
    keyCertSign: 'Certificate signing',
    cRLSign: 'CRL signing',
    encipherOnly: 'Encipher only',
    decipherOnly: 'Decipher only',
  };

  const EKU_NAMES = {
    serverAuth: 'TLS server auth',
    clientAuth: 'TLS client auth',
    codeSigning: 'Code signing',
    emailProtection: 'Email protection',
    timeStamping: 'Timestamping',
    ocspSigning: 'OCSP signing',
    ipsecEndSystem: 'IPSec end system',
    ipsecTunnel: 'IPSec tunnel',
    ipsecUser: 'IPSec user',
    anyExtendedKeyUsage: 'Any extended key usage',
  };

  // ---------- generic ASN.1 → JSON ----------

  function asn1ToJson(node, depth) {
    if (!node) return null;
    const T = forge.asn1.Type;
    const typeName =
      Object.keys(T).find((k) => T[k] === node.type) || String(node.type);
    const out = { type: typeName };
    if (
      node.tagClass !== undefined &&
      node.tagClass !== T.UNIVERSAL
    ) {
      out.tagClass =
        node.tagClass === T.CONTEXT
          ? 'context'
          : node.tagClass === T.APPLICATION
            ? 'application'
            : 'private';
    }
    const v = node.value;
    if (Array.isArray(v)) {
      out.value = v.map((c) => asn1ToJson(c, (depth || 0) + 1));
    } else if (v === null || v === undefined) {
      out.value = null;
    } else if (typeof v === 'string') {
      if (node.type === T.OID) {
        try {
          out.value = forge.asn1.derToOid(v);
        } catch (_) {
          out.value = hexTrunc(v);
        }
      } else if (node.type === T.BOOLEAN) {
        out.value = v.length ? v.charCodeAt(0) !== 0 : false;
      } else if (
        node.type === T.UTCTIME ||
        node.type === T.GENERALIZEDTIME
      ) {
        out.value = v;
      } else if (
        node.type === T.INTEGER ||
        node.type === T.BITSTRING ||
        node.type === T.OCTETSTRING
      ) {
        out.value = hexTrunc(v);
      } else if (
        node.type === T.UTF8 ||
        node.type === T.PRINTABLESTRING ||
        node.type === T.IA5STRING ||
        node.type === T.VIDEOTEXSTRING ||
        node.type === T.GRAPHICSTRING ||
        node.type === T.VISIBLESTRING ||
        node.type === T.GENERALSTRING ||
        node.type === T.UNIVERSALSTRING ||
        node.type === T.BMPSTRING
      ) {
        out.value = v;
      } else {
        out.value = hexTrunc(v);
      }
    } else {
      out.value = String(v);
    }
    return out;
  }

  // ---------- cert details ----------

  function attrList(attrs) {
    return (attrs || []).map((a) => ({
      short: a.shortName,
      name: a.name,
      value: String(a.value),
    }));
  }

  function formatAltName(n) {
    const type = { 1: 'email', 2: 'DNS', 6: 'URI', 7: 'IP' }[n.type] || 'type' + n.type;
    let value = n.value;
    if (n.type === 7 && typeof value === 'string') {
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(value) && value.length === 4) {
        value = [...value].map((c) => c.charCodeAt(0) & 0xff).join('.');
      }
    }
    return { type, value };
  }

  function attrSubjectKey(attrs) {
    return (attrs || [])
      .map((a) => a.shortName + '=' + String(a.value))
      .sort()
      .join('|');
  }

  function getExtensionSafe(cert, name) {
    try {
      const ext = cert.getExtension(name);
      return ext || null;
    } catch (_) {
      return null;
    }
  }

  function summariseExtension(name, ext) {
    if (!ext) return null;
    try {
      switch (name) {
        case 'basicConstraints': {
          let s = ext.cA ? 'CA:TRUE' : 'Not a CA';
          if (ext.pathLenConstraint !== undefined && ext.pathLenConstraint !== null) {
            s += ', path length: ' + ext.pathLenConstraint;
          }
          return s;
        }
        case 'keyUsage': {
          const on = Object.keys(KEY_USAGE_NAMES).filter((k) => ext[k] === true);
          return on.length ? on.map((k) => KEY_USAGE_NAMES[k]).join(', ') : 'present';
        }
        case 'extKeyUsage': {
          const on = Object.keys(EKU_NAMES).filter((k) => ext[k] === true);
          return on.length ? on.map((k) => EKU_NAMES[k]).join(', ') : 'present';
        }
        case 'subjectAltName': {
          const names = (ext.altNames || []).map(formatAltName);
          return names.length ? names.map((n) => n.type + ':' + n.value).join(', ') : 'present';
        }
        case 'subjectKeyIdentifier': {
          const v = ext.subjectKeyIdentifier || ext.value;
          return typeof v === 'string' ? colonHex(v) : 'present';
        }
        case 'authorityKeyIdentifier': {
          const v = ext.keyIdentifier || ext.authorityKeyIdentifier;
          return typeof v === 'string' ? colonHex(v) : 'present';
        }
        default:
          return 'present';
      }
    } catch (_) {
      return 'present';
    }
  }

  const KNOWN_EXTENSIONS = [
    'basicConstraints',
    'keyUsage',
    'extKeyUsage',
    'subjectAltName',
    'subjectKeyIdentifier',
    'authorityKeyIdentifier',
    'certificatePolicies',
    'crlDistributionPoints',
    'authorityInfoAccess',
    'nameConstraints',
  ];

  /**
   * Base cert summary (Gate-0 shape, kept stable for the spike tests) — subject,
   * issuer, serial, validity, SANs, self-signed flag, RSA bits, SHA-256 fingerprint.
   */
  function certInfo(cert) {
    const sanExt = cert.getExtension('subjectAltName');
    const san = sanExt
      ? (sanExt.altNames || []).map(formatAltName)
      : [];
    let fingerprint = null;
    let der = null;
    try {
      der =
        typeof forge.pki.certificateToDer === 'function'
          ? forge.pki.certificateToDer(cert)
          : forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
      const md = forge.md.sha256.create();
      md.update(der);
      fingerprint = colonHex(md.digest().getBytes());
    } catch (e) {
      fingerprint = 'error: ' + e.message;
    }
    const isRsa = !!(cert.publicKey && cert.publicKey.n);
    return {
      subject: attrList(cert.subject.attributes),
      issuer: attrList(cert.issuer.attributes),
      serialNumber: cert.serialNumber,
      validFrom: cert.validity.notBefore.toISOString(),
      validTo: cert.validity.notAfter.toISOString(),
      expired: cert.validity.notAfter.getTime() < Date.now(),
      san,
      selfSigned:
        JSON.stringify(attrList(cert.subject.attributes)) ===
        JSON.stringify(attrList(cert.issuer.attributes)),
      publicKeyType: isRsa ? 'RSA' : 'unknown/unsupported',
      rsaBits: isRsa ? cert.publicKey.n.bitLength() : null,
      sha256Fingerprint: fingerprint,
      // internal: raw DER as a binary string (not serialized in tests)
      _derBinary: der,
    };
  }

  /** Gate-1 full cert view: adds signature algorithm, key usage, extensions, JSON. */
  function certInfoFull(cert, opts) {
    const base = certInfo(cert);
    const options = opts || {};
    const md1 = forge.md.sha1.create();
    let sha1fp = null;
    try {
      md1.update(base._derBinary);
      sha1fp = colonHex(md1.digest().getBytes());
    } catch (_) {
      sha1fp = null;
    }
    const sigOid = cert.siginfo ? cert.siginfo.algorithmOid : cert.signatureOid;
    const bc = getExtensionSafe(cert, 'basicConstraints');
    const extensions = [];
    for (const name of KNOWN_EXTENSIONS) {
      const ext = getExtensionSafe(cert, name);
      if (!ext) continue;
      extensions.push({
        name,
        critical: !!ext.critical,
        summary: summariseExtension(name, ext),
      });
    }
    const nowMs = Date.now();
    return {
      ...base,
      _derBinary: undefined,
      serialHex: base.serialNumber,
      notYetValid: cert.validity.notBefore.getTime() > nowMs,
      daysToExpiry: Math.floor(
        (cert.validity.notAfter.getTime() - nowMs) / 86400000
      ),
      sha1Fingerprint: sha1fp,
      signatureAlgorithm: sigOid
        ? { oid: sigOid, name: SIGNATURE_ALGORITHMS[sigOid] || sigOid }
        : null,
      isCA: !!(bc && bc.cA),
      pathLen: bc && bc.pathLenConstraint !== undefined ? bc.pathLenConstraint : null,
      extensions,
      asn1: options.withAsn1 === false ? undefined : asn1ToJson(forge.pki.certificateToAsn1(cert), 0),
    };
  }

  // ---------- key <-> cert match ----------

  function keyMatchesCert(privateKey, cert) {
    const pub = cert.publicKey || {};
    let modulusEqual = null;
    if (privateKey.n && pub.n) {
      const eEq =
        privateKey.e && pub.e && privateKey.e.compareTo
          ? privateKey.e.compareTo(pub.e) === 0
          : privateKey.e === pub.e;
      modulusEqual = privateKey.n.compareTo(pub.n) === 0 && eEq;
    }
    let signVerify = null;
    let signVerifyError = null;
    try {
      const md1 = forge.md.sha256.create();
      md1.update('certkit-key-match-test');
      const sig = privateKey.sign(md1);
      const md2 = forge.md.sha256.create();
      md2.update('certkit-key-match-test');
      signVerify = pub.verify(md2.digest().bytes(), sig);
    } catch (e) {
      signVerifyError = e.message;
    }
    return {
      match: modulusEqual === true && signVerify !== false,
      modulusEqual,
      signVerify,
      signVerifyPassed: signVerify === true,
      signVerifyError,
    };
  }

  /** Parse a private key + certificate from user input and report the match. */
  function keyMatchReport(keyInput, certInput) {
    let privateKey;
    try {
      if (!isPemText(keyInput)) {
        throw new Error('A private key in PEM format is required.');
      }
      privateKey = forge.pki.privateKeyFromPem(keyInput);
    } catch (e) {
      throw keyFormatError(keyInput, e);
    }
    if (!privateKey || !privateKey.n) {
      if (privateKey && privateKey.curve) throw ecUnsupportedError();
      throw friendlyParseError('Could not read the private key', new Error('no RSA parameters found'));
    }
    const cert = decodeCertificate(certInput).cert;
    const report = keyMatchesCert(privateKey, cert);
    report.keyBits = privateKey.n.bitLength();
    report.certInfo = certInfo(cert);
    return report;
  }

  // ---------- certificate / CSR decoding ----------

  function certFromInput(input) {
    if (isPemText(input)) {
      return forge.pki.certificateFromPem(input);
    }
    const binary = bytesToBinaryString(toBytes(input));
    return forge.pki.certificateFromAsn1(
      forge.asn1.fromDer(forge.util.createBuffer(binary))
    );
  }

  function csrFromInput(input) {
    if (isPemText(input)) {
      return forge.pki.certificationRequestFromPem(input);
    }
    const binary = bytesToBinaryString(toBytes(input));
    return forge.pki.certificationRequestFromAsn1(
      forge.asn1.fromDer(forge.util.createBuffer(binary))
    );
  }

  /**
   * @returns {{ ok: true, cert: object, info: object, pem: string, der: Uint8Array }}
   * @throws Error with code EC_UNSUPPORTED for EC/Ed25519 certificates
   */
  function decodeCertificate(input) {
    let cert;
    try {
      cert = certFromInput(input);
    } catch (e) {
      throw friendlyParseError('Could not parse certificate', e);
    }
    const derBinary = forge.asn1
      .toDer(forge.pki.certificateToAsn1(cert))
      .getBytes();
    return {
      ok: true,
      cert,
      info: certInfoFull(cert),
      pem: forge.pki.certificateToPem(cert),
      der: binaryStringToBytes(derBinary),
    };
  }

  function csrExtensionRequest(csr) {
    let attr = null;
    try {
      attr = csr.getAttribute({ name: 'extensionRequest' });
    } catch (_) {
      attr = null;
    }
    if (!attr) {
      for (const a of csr.attributes || []) {
        if (a.value && Array.isArray(a.value.extensions)) {
          attr = a.value;
          break;
        }
      }
    }
    return attr;
  }

  /**
   * @returns {{ ok: true, csr: object, info: object, pem: string, der: Uint8Array }}
   */
  function decodeCsr(input) {
    let csr;
    try {
      csr = csrFromInput(input);
    } catch (e) {
      throw friendlyParseError('Could not parse certificate signing request', e);
    }
    const extReq = csrExtensionRequest(csr);
    const extensions = [];
    const sans = [];
    for (const ext of (extReq && extReq.extensions) || []) {
      const name = ext.name || 'unknown';
      const summary = summariseExtension(name, ext);
      extensions.push({ name, critical: !!ext.critical, summary });
      if (name === 'subjectAltName') {
        for (const n of ext.altNames || []) sans.push(formatAltName(n));
      }
    }
    let signatureValid = null;
    let signatureError = null;
    try {
      signatureValid = csr.verify();
    } catch (e) {
      signatureError = e.message;
    }
    const isRsa = !!(csr.publicKey && csr.publicKey.n);
    const derBinary = forge.asn1
      .toDer(forge.pki.certificationRequestToAsn1(csr))
      .getBytes();
    return {
      ok: true,
      csr,
      info: {
        subject: attrList(csr.subject.attributes),
        sans,
        extensions,
        publicKeyType: isRsa ? 'RSA' : 'unknown/unsupported',
        keyBits: isRsa ? csr.publicKey.n.bitLength() : null,
        signatureAlgorithm: csr.signatureOid
          ? {
              oid: csr.signatureOid,
              name: SIGNATURE_ALGORITHMS[csr.signatureOid] || csr.signatureOid,
            }
          : null,
        signatureValid,
        signatureError,
        attributeCount: (csr.attributes || []).length,
        asn1: asn1ToJson(forge.pki.certificationRequestToAsn1(csr), 0),
      },
      pem: forge.pki.certificationRequestToPem(csr),
      der: binaryStringToBytes(derBinary),
    };
  }

  // ---------- chain ordering ----------

  /** Split pasted text into individual PEM certificates. */
  function splitPemCertificates(text) {
    const out = [];
    const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
    let m;
    while ((m = re.exec(text))) out.push(m[0]);
    return out;
  }

  function chainEntry(cert) {
    const base = certInfo(cert);
    const bc = getExtensionSafe(cert, 'basicConstraints');
    return {
      subject: base.subject,
      issuer: base.issuer,
      subjectCN: (base.subject.find((a) => a.short === 'CN') || {}).value || null,
      issuerCN: (base.issuer.find((a) => a.short === 'CN') || {}).value || null,
      serialNumber: base.serialNumber,
      validTo: base.validTo,
      expired: base.expired,
      selfSigned: base.selfSigned,
      isCA: !!(bc && bc.cA),
      sha256Fingerprint: base.sha256Fingerprint,
    };
  }

  /**
   * Order a mixed bag of certificates leaf → intermediates → root, check each
   * issuer link's signature where possible, and report missing links.
   *
   * @param {Array<string|Uint8Array>} inputs PEM strings or DER bytes (any order)
   */
  function orderChain(inputs) {
    const certs = [];
    const parseErrors = [];
    for (const input of inputs) {
      try {
        certs.push(decodeCertificate(input).cert);
      } catch (e) {
        parseErrors.push(e.message);
      }
    }
    if (!certs.length) {
      const err = new Error(
        parseErrors.length
          ? 'No certificate could be parsed: ' + parseErrors[0]
          : 'No certificate found in the input.'
      );
      err.code = 'CHAIN_NO_CERTS';
      throw err;
    }

    // De-duplicate identical certs (same subject + serial).
    const seen = new Map();
    let duplicates = 0;
    const unique = [];
    for (const cert of certs) {
      const key = attrSubjectKey(cert.subject.attributes) + '#' + cert.serialNumber;
      if (seen.has(key)) {
        duplicates++;
      } else {
        seen.set(key, true);
        unique.push(cert);
      }
    }

    const subjectKeys = unique.map((c) => attrSubjectKey(c.subject.attributes));
    const issuerKeys = unique.map((c) => attrSubjectKey(c.issuer.attributes));
    const selfKeys = unique.map((c, i) => subjectKeys[i] === issuerKeys[i]);

    const isParentOf = (p, i) =>
      subjectKeys[p] === issuerKeys[i] && !selfKeys[i];
    const parentIndex = (child) => {
      for (let p = 0; p < unique.length; p++) {
        if (p !== child && isParentOf(p, child)) return p;
      }
      return -1;
    };

    // leaf = certificate that is not the issuer of any other certificate
    const issuersOfOthers = new Set();
    for (let i = 0; i < unique.length; i++) {
      const p = parentIndex(i);
      if (p !== -1) issuersOfOthers.add(p);
    }
    let start = -1;
    for (let i = 0; i < unique.length; i++) {
      if (!issuersOfOthers.has(i) && !selfKeys[i]) {
        start = i;
        break;
      }
    }
    if (start === -1) {
      // all self-signed or a broken input: start from a non-CA if possible
      start = unique.findIndex((c) => {
        const bc = getExtensionSafe(c, 'basicConstraints');
        return !bc || !bc.cA;
      });
      if (start === -1) start = 0;
    }

    const visited = new Set();
    const ordered = [];
    const links = [];
    const missing = [];
    let current = start;
    while (current !== -1 && !visited.has(current)) {
      visited.add(current);
      ordered.push({ index: current, entry: chainEntry(unique[current]) });
      if (selfKeys[current]) break;
      const parent = parentIndex(current);
      if (parent === -1) {
        missing.push({
          issuer: attrList(unique[current].issuer.attributes),
          issuerCN: chainEntry(unique[current]).issuerCN,
          neededByCN: chainEntry(unique[current]).subjectCN,
        });
        break;
      }
      let signatureValid = null;
      let signatureError = null;
      try {
        signatureValid = unique[parent].verify(unique[current]);
      } catch (e) {
        signatureError = e.message;
      }
      links.push({
        fromCN: chainEntry(unique[current]).subjectCN,
        toCN: chainEntry(unique[parent]).subjectCN,
        signatureValid,
        signatureError,
      });
      current = parent;
    }

    const unlinked = [];
    for (let i = 0; i < unique.length; i++) {
      if (!visited.has(i)) unlinked.push({ index: i, entry: chainEntry(unique[i]) });
    }

    return {
      ok: true,
      count: ordered.length,
      duplicates,
      parseErrors,
      ordered,
      links,
      missing,
      unlinked,
      allValid:
        missing.length === 0 &&
        unlinked.length === 0 &&
        links.every((l) => l.signatureValid !== false),
    };
  }

  // ---------- JWK inspection ----------

  function b64urlDecodeLength(s) {
    if (typeof s !== 'string') return 0;
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    try {
      return forge.util.decode64(s.replace(/-/g, '+').replace(/_/g, '/') + pad).length;
    } catch (_) {
      return 0;
    }
  }

  const CURVE_BITS = { 'P-256': 256, 'P-384': 384, 'P-521': 521, 'P-256K': 256 };

  function inspectJwkKey(key) {
    const warnings = [];
    const out = {
      kty: key.kty || null,
      kid: key.kid || null,
      alg: key.alg || null,
      use: key.use || null,
      key_ops: Array.isArray(key.key_ops) ? key.key_ops : null,
      crv: key.crv || null,
      bits: null,
      x5cCount: Array.isArray(key.x5c) ? key.x5c.length : 0,
      x5cSubject: null,
      hasPrivateMaterial: false,
    };
    if (key.kty === 'RSA') {
      const bytes = b64urlDecodeLength(key.n);
      out.bits = bytes ? bytes * 8 : null;
      if (!key.n || !key.e) warnings.push('RSA JWK is missing n and/or e.');
    } else if (key.kty === 'EC') {
      out.bits = key.crv ? CURVE_BITS[key.crv] || null : null;
      if (!key.x || !key.y) warnings.push('EC JWK is missing x and/or y coordinates.');
    } else if (key.kty === 'oct') {
      warnings.push('Symmetric key (kty "oct") — secret material.');
    } else if (key.kty) {
      warnings.push('Unrecognised key type "' + key.kty + '".');
    } else {
      warnings.push('Object has no "kty" field — not a valid JWK.');
    }
    if (key.d !== undefined) {
      out.hasPrivateMaterial = true;
      warnings.push(
        'This JWK contains PRIVATE key material ("d"). Inspect only — never share this file.'
      );
    }
    if (key.k !== undefined && !out.hasPrivateMaterial) {
      out.hasPrivateMaterial = true;
      warnings.push('This JWK contains symmetric key material ("k").');
    }
    if (key.oth !== undefined) {
      warnings.push('Multi-prime RSA ("oth") is present; parts of this key are not displayed.');
    }
    if (out.x5cCount) {
      try {
        const der = forge.util.decode64(key.x5c[0]);
        const cert = forge.pki.certificateFromAsn1(
          forge.asn1.fromDer(forge.util.createBuffer(der))
        );
        const cn = cert.subject.getField('CN');
        out.x5cSubject = cn ? String(cn.value) : null;
      } catch (_) {
        out.x5cSubject = null;
      }
    }
    return { ...out, warnings };
  }

  /**
   * Inspect a JWK or JWK set. Parses and describes only — performs NO
   * signature or key validation (stated in the UI).
   */
  function inspectJwk(text) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new Error('Input is not valid JSON: ' + e.message);
    }
    let keys = [];
    let kind = 'JWK';
    if (Array.isArray(parsed.keys)) {
      kind = 'JWK Set';
      keys = parsed.keys;
    } else if (parsed && typeof parsed === 'object' && parsed.kty) {
      keys = [parsed];
    } else {
      throw new Error(
        'Input is neither a JWK (object with "kty") nor a JWK set (object with a "keys" array).'
      );
    }
    const inspected = keys.map(inspectJwkKey);
    const warnings = [];
    for (const k of inspected) for (const w of k.warnings) if (!warnings.includes(w)) warnings.push(w);
    if (inspected.some((k) => k.hasPrivateMaterial)) {
      warnings.unshift(
        'Private key material detected in this file. CertKit does not upload anything, but do not paste real private keys into untrusted tools.'
      );
    }
    return {
      ok: true,
      kind,
      keyCount: inspected.length,
      keys: inspected,
      warnings,
      note: 'Parsed for inspection only — no signature verification or key validation is performed.',
    };
  }

  // ---------- pem → pfx (write path) ----------

  /**
   * Build a PKCS#12 (.pfx/.p12) from PEM inputs.
   *
   * Honest limitations of the node-forge writer (v1):
   *  - MAC is HMAC-SHA-1 (universally readable, but legacy);
   *  - certificate bags are left unencrypted inside the file;
   *  - the private key bag is AES-256-CBC (PBES2).
   *
   * @returns {{ bytes: Uint8Array, base64: string, match: object, certCount: number }}
   */
  function pemToPfx({ keyPem, certPems, password, friendlyName }) {
    if (!keyPem || !String(keyPem).trim()) {
      throw new Error('A private key (PEM) is required.');
    }
    const certs = [];
    for (const pem of certPems || []) {
      if (!pem || !String(pem).trim()) continue;
      try {
        certs.push(forge.pki.certificateFromPem(pem));
      } catch (e) {
        throw friendlyParseError('Could not parse certificate', e);
      }
    }
    if (!certs.length) {
      throw new Error('At least one certificate (PEM) is required.');
    }
    let key;
    try {
      key = forge.pki.privateKeyFromPem(keyPem);
    } catch (e) {
      throw keyFormatError(keyPem, e);
    }
    if (!key || !key.n) throw ecUnsupportedError();
    if (typeof password !== 'string' || password.length === 0) {
      throw new Error('Enter a password to protect the PFX file.');
    }
    const match = keyMatchesCert(key, certs[0]);
    if (!match.match) {
      const err = new Error(
        'The private key does not match the first certificate — refusing to build a broken PFX. ' +
          'Use the Key & Certificate Match tool to check your files.'
      );
      err.code = 'KEY_MISMATCH';
      throw err;
    }
    const asn1 = forge.pkcs12.toPkcs12Asn1(key, certs, password, {
      algorithm: 'aes256',
      friendlyName: friendlyName || undefined,
    });
    const derBinary = forge.asn1.toDer(asn1).getBytes();
    return {
      bytes: binaryStringToBytes(derBinary),
      base64: forge.util.encode64(derBinary),
      match,
      certCount: certs.length,
    };
  }

  // ---------- main PKCS#12 parse (Gate-0, unchanged API) ----------

  /**
   * @param {Uint8Array} bytes
   * @param {string|null} password
   * @returns parsed result object
   */
  function parsePfx(bytes, password) {
    const t0 = now();
    const binary = bytesToBinaryString(bytes);
    const tDer0 = now();
    const p12Asn1 = forge.asn1.fromDer(forge.util.createBuffer(binary));
    const tDer = now() - tDer0;

    const attempts = password == null || password === '' ? [password, ''] : [password];
    let p12 = null;
    let lastError = null;
    for (const pw of attempts) {
      try {
        // Important: do NOT swallow crypto errors for the correct password; we only
        // retry for the empty-password edge case.
        p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pw);
        lastError = null;
        break;
      } catch (e) {
        lastError = e;
      }
    }
    if (!p12) {
      let msg = lastError ? lastError.message : 'PKCS#12 parse failed';
      if (/tagClass|not RSA|Unsupported|unsupported/i.test(msg)) {
        msg =
          'Unsupported key or certificate algorithm (node-forge handles RSA only; ' +
          'EC/Ed25519 not supported): ' +
          msg;
      }
      const err = new Error(msg);
      err.cause = lastError;
      throw err;
    }

    const tBags0 = now();
    // forge getBags() takes exactly ONE bagType per call (no array support).
    const allBags = {};
    for (const bt of [
      forge.pki.oids.pkcs8ShroudedKeyBag,
      forge.pki.oids.keyBag,
      forge.pki.oids.certBag,
      forge.pki.oids.crlBag,
      forge.pki.oids.secretBag,
    ]) {
      const got = p12.getBags({ bagType: bt });
      allBags[bt] = got[bt] || [];
    }
    const keyBags = [
      ...(allBags[forge.pki.oids.pkcs8ShroudedKeyBag] || []),
      ...(allBags[forge.pki.oids.keyBag] || []),
    ];
    const certBags = allBags[forge.pki.oids.certBag] || [];
    const certs = [];
    for (let i = 0; i < certBags.length; i++) {
      const b = certBags[i];
      let c = null;
      try {
        // forge 1.4 returns bag.cert already parsed (a pkix Certificate).
        // Older forge returned raw ASN.1; support both.
        c =
          b.cert && b.cert.subject && b.cert.getExtension
            ? b.cert
            : b.cert
              ? forge.pki.certificateFromAsn1(b.cert)
              : null;
      } catch (e) {
        c = null;
      }
      if (!c) {
        throw new Error(
          'Certificate bag #' + (i + 1) + ' could not be parsed: unsupported or malformed certificate ' +
          '(node-forge handles RSA certificates only; EC/Ed25519 certificates are not supported).'
        );
      }
      certs.push(c);
    }
    const privateKey = keyBags.length ? keyBags[0].key : null;
    if (privateKey && !privateKey.n) {
      throw new Error(
        'Unsupported private key type in PKCS#12: node-forge supports RSA keys only ' +
        '(EC/Ed25519 private keys are not supported in this build).'
      );
    }
    const tBags = now() - tBags0;

    const matches = privateKey && certs.length ? keyMatchesCert(privateKey, certs[0]) : null;

    // PEM exports
    const tPem0 = now();
    let privateKeyPem = null;
    if (privateKey) {
      try {
        privateKeyPem = forge.pki.privateKeyToPem(privateKey);
      } catch (e) {
        privateKeyPem = 'ERROR: ' + e.message;
      }
    }
    const certificatesPem = certs.map((c) => forge.pki.certificateToPem(c)).join('\n');
    const tPem = now() - tPem0;

    return {
      ok: true,
      elapsedMs: +(now() - t0).toFixed(1),
      timings: {
        der: +tDer.toFixed(1),
        bagsDecrypt: +tBags.toFixed(1),
        pemExport: +tPem.toFixed(1),
      },
      fileBytes: bytes.length,
      bagCounts: {
        pkcs8ShroudedKeyBag: (allBags[forge.pki.oids.pkcs8ShroudedKeyBag] || []).length,
        keyBag: (allBags[forge.pki.oids.keyBag] || []).length,
        certBag: certBags.length,
      },
      hasPrivateKey: !!privateKey,
      privateKeyType: privateKey ? (privateKey.n ? 'RSA' : 'unsupported') : null,
      certs: certs.map(certInfo),
      keyMatch: matches,
      pems: {
        privateKey: privateKeyPem,
        certificates: certificatesPem,
        bundle:
          (privateKeyPem ? privateKeyPem + '\n' : '') + certificatesPem,
      },
      // raw forge objects (not serializable; for tests/advanced use only)
      raw: { privateKey, certs },
      rawOids: scanOids(bytes),
    };
  }

  /** Recursively collect OIDs from raw DER, descending into nested DER carried
   *  inside OCTET STRINGs (PKCS#12 AuthenticatedSafe / SafeContents). Informational;
   *  used to report what encryption algorithms a file actually contains. */
  function scanOids(bytes) {
    const out = new Set();
    const T = forge.asn1.Type;
    function walkDer(binary, depth) {
      if (depth > 6) return;
      let asn1;
      try {
        asn1 = forge.asn1.fromDer(forge.util.createBuffer(binary));
      } catch (_) {
        return;
      }
      (function walk(node) {
        if (!node || node.value == null) return;
        if (node.type === T.OID && typeof node.value === 'string') {
          try {
            out.add(forge.asn1.derToOid(node.value));
          } catch (_) {
            /* not a decodable OID */
          }
        }
        if (node.type === T.OCTETSTRING && typeof node.value === 'string' && depth < 6) {
          walkDer(node.value, depth + 1);
        }
        if (Array.isArray(node.value)) node.value.forEach(walk);
      })(asn1);
    }
    walkDer(bytesToBinaryString(bytes), 0);
    return [...out]
      .map((oid) => ({ oid, name: OID_NAMES[oid] || null }))
      .filter((x) => x.name);
  }

  return {
    // Gate 0
    parsePfx,
    certInfo,
    keyMatchesCert,
    scanOids,
    bytesToBinaryString,
    binaryStringToBytes,
    // Gate 1
    certInfoFull,
    decodeCertificate,
    decodeCsr,
    keyMatchReport,
    orderChain,
    splitPemCertificates,
    inspectJwk,
    pemToPfx,
    asn1ToJson,
    SIGNATURE_ALGORITHMS,
  };
});
