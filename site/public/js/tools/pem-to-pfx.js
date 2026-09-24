/**
 * PEM → PFX tool. Builds a PKCS#12 container from a PEM key + certificate
 * chain, with key/cert mismatch protection and honest compatibility notes.
 */
(function () {
  'use strict';
  var UI = window.CertKitUI;
  var CK = window.CertKit;

  var form = document.getElementById('tool-form');
  var pfxBytes = null;

  UI.wireDropzones();
  UI.wireOutputActions();

  /** Load a chosen file's text into the matching textarea. */
  function wireFileToTextarea(inputId, textareaId) {
    var input = document.getElementById(inputId);
    var ta = document.getElementById(textareaId);
    if (!input || !ta) return;
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (!file) return;
      UI.readFile(file).then(function (f) {
        if (/-----BEGIN/.test(f.text)) ta.value = f.text.trim();
      });
    });
  }
  wireFileToTextarea('key-file', 'key-pem');
  wireFileToTextarea('cert-file', 'cert-pems');

  function fail(err) {
    var msg = (err && err.message) || String(err);
    UI.hide('results');
    if (err && err.code === 'KEY_MISMATCH') {
      UI.setError(msg, { href: '/key-cert-match/', label: 'Check a key and certificate pair' });
      UI.announce('Error: the key does not match the certificate.');
    } else if (err && err.code === 'EC_UNSUPPORTED') {
      UI.setError(msg, { href: '/roadmap/', label: 'See the roadmap' });
      UI.announce('Error: unsupported key type.');
    } else {
      UI.setError(msg);
      UI.announce('Error: ' + msg.slice(0, 120));
    }
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    UI.setError('');
    var keyPem = document.getElementById('key-pem').value;
    var certText = document.getElementById('cert-pems').value;
    var password = document.getElementById('pfx-password').value;
    var friendlyName = document.getElementById('friendly-name').value;

    if (!keyPem.trim()) {
      UI.setError('Paste the private key (PEM) or choose a key file first.');
      return;
    }
    var certPems = CK.splitPemCertificates(certText);
    if (!certPems.length && /-----BEGIN CERTIFICATE-----/.test(certText)) {
      certPems = [certText.trim()];
    }
    if (!certPems.length) {
      UI.setError('Paste at least one certificate in PEM format (-----BEGIN CERTIFICATE-----).');
      return;
    }

    var r;
    try {
      r = CK.pemToPfx({
        keyPem: keyPem,
        certPems: certPems,
        password: password,
        friendlyName: friendlyName.trim() || undefined,
      });
    } catch (err) {
      fail(err);
      return;
    }

    pfxBytes = r.bytes;
    var base64 = r.base64.match(/.{1,64}/g).join('\n');
    UI.setOutput('out-base64', base64);

    UI.setBadge(document.getElementById('match-badge'), 'ok', 'key matches certificate');
    UI.fillSummary(document.getElementById('file-summary'), [
      ['Certificates included', String(r.certCount)],
      ['Key', 'RSA, ' + r.match.keyBits + '-bit'],
      ['PFX size', UI.fmtBytes(r.bytes.length)],
      ['MAC', 'HMAC-SHA-1 (documented limit)'],
      ['Certificate bags', 'stored unencrypted inside the container (documented limit)'],
      ['Private key bag', 'AES-256-CBC (PBES2)'],
    ]);

    UI.show('results');
    UI.announce('PFX created: ' + r.certCount + ' certificate(s), ' + UI.fmtBytes(r.bytes.length) + '. Ready to download.');
  });

  document.getElementById('download-pfx').addEventListener('click', function () {
    if (pfxBytes) UI.downloadBytes('certkit.pfx', pfxBytes, 'application/x-pkcs12');
  });
})();
