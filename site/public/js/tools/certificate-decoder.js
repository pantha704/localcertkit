/**
 * Certificate decoder — PEM / base64-DER input, human-readable view + raw ASN.1 JSON.
 */
(function () {
  'use strict';
  var UI = window.CertKitUI;
  var CK = window.CertKit;

  var form = document.getElementById('tool-form');
  var fileInput = document.getElementById('cert-file');
  var textarea = document.getElementById('cert-input');

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
      UI.announce('Error: EC certificates are not supported yet.');
    } else {
      UI.setError((err && err.message) || String(err));
      UI.announce('Error: could not decode the certificate.');
    }
  }

  function validityBadge(info) {
    if (info.expired) {
      return { kind: 'bad', label: 'Expired' };
    }
    if (info.notYetValid) {
      return { kind: 'warn', label: 'Not valid yet' };
    }
    return {
      kind: 'ok',
      label: 'Valid · expires in ' + info.daysToExpiry + ' day' + (info.daysToExpiry === 1 ? '' : 's'),
    };
  }

  function render(r) {
    var info = r.info;
    var badge = validityBadge(info);
    UI.setBadge(document.getElementById('validity-badge'), badge.kind, badge.label);

    var ku = info.extensions.filter(function (e) {
      return e.name === 'keyUsage';
    })[0];
    var eku = info.extensions.filter(function (e) {
      return e.name === 'extKeyUsage';
    })[0];

    UI.fillSummary(document.getElementById('cert-summary'), [
      ['Subject', UI.formatDN(info.subject)],
      ['Issuer', UI.formatDN(info.issuer)],
      ['Serial number', String(info.serialNumber)],
      ['Valid from', UI.fmtDate(info.validFrom)],
      ['Valid to', UI.fmtDate(info.validTo)],
      ['Public key', info.publicKeyType + ' ' + (info.rsaBits || '?') + '-bit'],
      ['Signature algorithm', info.signatureAlgorithm ? info.signatureAlgorithm.name : 'unknown'],
      ['Self-signed', info.selfSigned ? 'Yes' : 'No'],
      ['CA certificate', info.isCA ? 'Yes' + (info.pathLen !== null ? ' (path length ' + info.pathLen + ')' : '') : 'No'],
      ['Key usage', ku ? ku.summary : 'not specified'],
      ['Extended key usage', eku ? eku.summary : 'not specified'],
      ['SHA-256 fingerprint', info.sha256Fingerprint],
      ['SHA-1 fingerprint', info.sha1Fingerprint || 'unavailable'],
    ]);

    var sanList = document.getElementById('san-list');
    sanList.textContent = '';
    if (info.san.length) {
      info.san.forEach(function (s) {
        sanList.appendChild(UI.el('li', { class: 'mono', text: s.type + ': ' + s.value }));
      });
    } else {
      sanList.appendChild(UI.el('li', { class: 'muted', text: 'No subjectAltName extension in this certificate.' }));
    }

    UI.fillSummary(
      document.getElementById('ext-summary'),
      info.extensions.length
        ? info.extensions.map(function (ext) {
            return [ext.name + (ext.critical ? ' (critical)' : ''), ext.summary];
          })
        : [['Extensions', 'none of the known extensions were found']]
    );

    document.getElementById('cert-json').textContent = JSON.stringify(info.asn1, null, 1);
    UI.setOutput('out-pem', r.pem);
    document.getElementById('download-der').onclick = function () {
      UI.downloadBytes('certificate.der', r.der, 'application/pkix-cert');
    };

    UI.show('results');
    UI.announce('Certificate decoded. Subject: ' + UI.formatDN(info.subject) + '.');
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    UI.setError('');
    var file = fileInput.files && fileInput.files[0];
    var input = textarea.value.trim();

    function decode(value) {
      try {
        render(CK.decodeCertificate(value));
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
      UI.setError('Paste a certificate (PEM or base64 DER) or choose a certificate file first.');
      UI.announce('Error: no certificate provided.');
    }
  });
})();
