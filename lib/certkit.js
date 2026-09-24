/**
 * certkit-lib — in-browser PKCS#12 (.pfx/.p12) parsing + cert inspection + PEM export.
 *
 * UMD-ish: works as a <script> after forge.min.js (global `forge`, exports `CertKit`)
 * and as a CommonJS module in Node (require('node-forge') + module.exports).
 *
 * Depends on node-forge for ASN.1/DER + crypto primitives.
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

  // PBE / PRF OIDs we can name (for evidence output). Forge supports PKCS#12 PBE
  // (SHA-1 based) but NOT PBES2 (AES) or SCRYPT; names are informational only.
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

  // ---------- cert details ----------

  function attrList(attrs) {
    return (attrs || []).map((a) => ({
      short: a.shortName,
      name: a.name,
      value: String(a.value),
    }));
  }

  function certInfo(cert) {
    const sanExt = cert.getExtension('subjectAltName');
    const san = sanExt
      ? (sanExt.altNames || []).map((n) => {
          const type =
            { 1: 'email', 2: 'DNS', 6: 'URI', 7: 'IP' }[n.type] || ('type' + n.type);
          return { type, value: n.value };
        })
      : [];
    let fingerprint = null;
    try {
      const der =
        typeof forge.pki.certificateToDer === 'function'
          ? forge.pki.certificateToDer(cert)
          : forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
      const md = forge.md.sha256.create();
      md.update(der);
      fingerprint = md.digest().toHex().match(/.{2}/g).join(':').toUpperCase();
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
      selfSigned: JSON.stringify(attrList(cert.subject.attributes)) === JSON.stringify(attrList(cert.issuer.attributes)),
      publicKeyType: isRsa ? 'RSA' : 'unknown/unsupported',
      rsaBits: isRsa ? cert.publicKey.n.bitLength() : null,
      sha256Fingerprint: fingerprint,
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
      signVerifyError,
    };
  }

  // ---------- main parse ----------

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

  return {
    parsePfx,
    certInfo,
    keyMatchesCert,
    scanOids,
    bytesToBinaryString,
    binaryStringToBytes,
  };
});
