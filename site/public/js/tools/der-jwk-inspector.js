/**
 * DER certificate + JWK inspector.
 *  - DER section: decode a DER/base64 certificate into a compact summary.
 *  - JWK section: parse a JWK / JWK-set and describe keys. No verification claims.
 */
(function () {
  'use strict';
  var UI = window.CertKitUI;
  var CK = window.CertKit;

  var derForm = document.getElementById('der-form');
  var derFile = document.getElementById('der-file');
  var derInput = document.getElementById('der-input');
  var jwkForm = document.getElementById('jwk-form');
  var jwkFile = document.getElementById('jwk-file');
  var jwkInput = document.getElementById('jwk-input');

  UI.wireDropzones();

  function fail(err) {
    document.getElementById('der-results').hidden = true;
    document.getElementById('jwk-results').hidden = true;
    if (err && err.code === 'EC_UNSUPPORTED') {
      UI.setError(err.message, { href: '/roadmap/', label: 'See the roadmap' });
    } else {
      UI.setError((err && err.message) || String(err));
    }
  }

  // ---------- DER certificate ----------

  derForm.addEventListener('submit', function (e) {
    e.preventDefault();
    UI.setError('');
    var file = derFile.files && derFile.files[0];
    var value = derInput.value.trim();

    function run(input) {
      try {
        var r = CK.decodeCertificate(input);
        var info = r.info;
        UI.fillSummary(document.getElementById('der-summary'), [
          ['Subject', UI.formatDN(info.subject)],
          ['Issuer', UI.formatDN(info.issuer)],
          ['Serial number', String(info.serialNumber)],
          ['Valid from', UI.fmtDate(info.validFrom)],
          ['Valid to', UI.fmtDate(info.validTo)],
          ['Public key', info.publicKeyType + ' ' + (info.rsaBits || '?') + '-bit'],
          ['Signature algorithm', info.signatureAlgorithm ? info.signatureAlgorithm.name : 'unknown'],
          ['SANs', info.san.length ? info.san.map(function (s) { return s.type + ':' + s.value; }).join(', ') : 'none'],
          ['SHA-256 fingerprint', info.sha256Fingerprint],
        ]);
        document.getElementById('der-results').hidden = false;
        UI.announce('DER certificate inspected. Subject: ' + UI.formatDN(info.subject) + '.');
      } catch (err) {
        fail(err);
      }
    }

    if (file) {
      UI.readFile(file).then(function (f) {
        run(/-----BEGIN/.test(f.text) ? f.text : f.bytes);
      }, fail);
    } else if (value) {
      run(value);
    } else {
      UI.setError('Choose a DER file or paste base64 DER / PEM first.');
    }
  });

  // ---------- JWK ----------

  jwkFile.addEventListener('change', function () {
    var file = jwkFile.files && jwkFile.files[0];
    if (!file) return;
    UI.readFile(file).then(function (f) {
      jwkInput.value = f.text.trim();
    });
  });

  jwkForm.addEventListener('submit', function (e) {
    e.preventDefault();
    UI.setError('');
    var text = jwkInput.value.trim();
    if (!text) {
      UI.setError('Paste JWK / JWK-set JSON or choose a .json file first.');
      return;
    }
    var r;
    try {
      r = CK.inspectJwk(text);
    } catch (err) {
      fail(err);
      return;
    }

    UI.fillSummary(document.getElementById('jwk-summary'), [
      ['Input type', r.kind],
      ['Keys', String(r.keyCount)],
      ['Verification', 'none performed (parse-only inspector)'],
    ]);

    var warnBox = document.getElementById('jwk-warnings');
    warnBox.textContent = '';
    if (r.warnings.length) {
      r.warnings.forEach(function (w) {
        warnBox.appendChild(UI.el('p', { text: w }));
      });
      warnBox.hidden = false;
    } else {
      warnBox.hidden = true;
    }

    var tbody = document.querySelector('#jwk-table tbody');
    tbody.textContent = '';
    r.keys.forEach(function (key, i) {
      var tr = UI.el('tr', null, [
        UI.el('th', { scope: 'row', text: String(i + 1) }),
        UI.el('td', { text: key.kty || '—' }),
        UI.el('td', { class: 'mono', text: key.kid || '—' }),
        UI.el('td', { class: 'mono', text: key.alg || '—' }),
        UI.el('td', { text: key.use || (key.key_ops ? key.key_ops.join(', ') : '—') }),
        UI.el('td', { text: (key.bits ? key.bits + '-bit' : '—') + (key.crv ? ' (' + key.crv + ')' : '') }),
        UI.el('td', { text: key.hasPrivateMaterial ? 'YES — private material' : 'no' }),
      ]);
      tbody.appendChild(tr);
    });
    document.getElementById('jwk-caption').textContent =
      r.kind + ' — ' + r.keyCount + ' key' + (r.keyCount === 1 ? '' : 's');

    document.getElementById('jwk-results').hidden = false;
    UI.announce(r.kind + ' parsed: ' + r.keyCount + ' key(s). No verification performed.');
  });
})();
