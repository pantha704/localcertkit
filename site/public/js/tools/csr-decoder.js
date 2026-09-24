/**
 * CSR decoder — subject, requested SANs/extensions, key info, signature check,
 * raw ASN.1 JSON.
 */
(function () {
  'use strict';
  var UI = window.CertKitUI;
  var CK = window.CertKit;

  var form = document.getElementById('tool-form');
  var fileInput = document.getElementById('csr-file');
  var textarea = document.getElementById('csr-input');

  UI.wireDropzones();
  UI.wireOutputActions();
  UI.wireToggle(
    [document.getElementById('view-human'), document.getElementById('view-json')],
    { human: 'pane-human', json: 'pane-json' }
  );

  function fail(err) {
    UI.hide('results');
    if (err && err.code === 'EC_UNSUPPORTED') {
      UI.setError(err.message, { href: '/roadmap/', label: 'See the roadmap' });
      UI.announce('Error: EC signing requests are not supported yet.');
    } else {
      UI.setError((err && err.message) || String(err));
      UI.announce('Error: could not decode the signing request.');
    }
  }

  function render(r) {
    var info = r.info;
    if (info.signatureValid === true) {
      UI.setBadge(document.getElementById('sig-badge'), 'ok', 'signature verified');
    } else if (info.signatureValid === false) {
      UI.setBadge(document.getElementById('sig-badge'), 'bad', 'signature check FAILED');
    } else {
      UI.setBadge(document.getElementById('sig-badge'), 'warn', 'signature check unavailable');
    }

    UI.fillSummary(document.getElementById('csr-summary'), [
      ['Subject', UI.formatDN(info.subject)],
      ['Public key', info.publicKeyType + ' ' + (info.keyBits || '?') + '-bit'],
      ['Signature algorithm', info.signatureAlgorithm ? info.signatureAlgorithm.name : 'unknown'],
      [
        'Signature check',
        info.signatureValid === true
          ? 'Verified — signed by the matching private key'
          : info.signatureValid === false
            ? 'Failed — the signature does not match the public key'
            : 'Could not be checked' + (info.signatureError ? ': ' + info.signatureError : ''),
      ],
      ['Requested extensions', info.extensions.length ? String(info.extensions.length) : 'none'],
    ]);

    var sanList = document.getElementById('san-list');
    sanList.textContent = '';
    if (info.sans.length) {
      info.sans.forEach(function (s) {
        sanList.appendChild(UI.el('li', { class: 'mono', text: s.type + ': ' + s.value }));
      });
    } else {
      sanList.appendChild(UI.el('li', { class: 'muted', text: 'No SANs requested in this CSR — some CAs will add them, some will reject it.' }));
    }

    UI.fillSummary(
      document.getElementById('ext-summary'),
      info.extensions.length
        ? info.extensions.map(function (ext) {
            return [ext.name + (ext.critical ? ' (critical)' : ''), ext.summary];
          })
        : [['Requested extensions', 'none']]
    );

    document.getElementById('csr-json').textContent = JSON.stringify(info.asn1, null, 1);
    UI.setOutput('out-pem', r.pem);

    UI.show('results');
    UI.announce(
      'CSR decoded. Subject: ' +
        UI.formatDN(info.subject) +
        '. Signature ' +
        (info.signatureValid === true ? 'verified.' : info.signatureValid === false ? 'check failed.' : 'not verifiable.')
    );
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    UI.setError('');
    var file = fileInput.files && fileInput.files[0];
    var input = textarea.value.trim();

    function decode(value) {
      try {
        render(CK.decodeCsr(value));
      } catch (err) {
        fail(err);
      }
    }

    if (file) {
      UI.readFile(file).then(function (f) {
        decode(/-----BEGIN/.test(f.text) ? f.text : f.bytes);
      }, fail);
    } else if (input) {
      decode(input);
    } else {
      UI.setError('Paste a CSR (PEM or base64 DER) or choose a file first.');
      UI.announce('Error: no CSR provided.');
    }
  });
})();
