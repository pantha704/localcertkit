/**
 * Key ↔ certificate match — RSA modulus comparison + real sign/verify round-trip.
 */
(function () {
  'use strict';
  var UI = window.CertKitUI;
  var CK = window.CertKit;

  var form = document.getElementById('tool-form');
  var keyFile = document.getElementById('key-file');
  var certFile = document.getElementById('cert-file');
  var keyInput = document.getElementById('key-input');
  var certInput = document.getElementById('cert-input');

  UI.wireDropzones();
  UI.wireOutputActions();

  function fillFromFile(inputId, textareaId) {
    var input = document.getElementById(inputId);
    var ta = document.getElementById(textareaId);
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (!file) return;
      UI.readFile(file).then(function (f) {
        if (/-----BEGIN/.test(f.text)) ta.value = f.text.trim();
      });
    });
  }
  fillFromFile('key-file', 'key-input');
  fillFromFile('cert-file', 'cert-input');

  function fail(err) {
    UI.hide('results');
    if (err && err.code === 'EC_UNSUPPORTED') {
      UI.setError(err.message, { href: '/roadmap/', label: 'See the roadmap' });
      UI.announce('Error: EC objects are not supported yet.');
    } else {
      UI.setError((err && err.message) || String(err));
      UI.announce('Error: could not check the pair.');
    }
  }

  function render(r, keyName, certName) {
    var badge = document.getElementById('match-badge');
    if (r.match) {
      UI.setBadge(badge, 'ok', 'MATCH — this key belongs to this certificate');
    } else {
      UI.setBadge(badge, 'bad', 'NO MATCH — key and certificate are not a pair');
    }

    var cn = UI.attrValue(r.certInfo.subject, 'CN');
    var sigText;
    if (r.signVerifyPassed) sigText = 'Passed — the private key signed a test message that this certificate verified';
    else if (r.signVerifyError) sigText = 'Failed — ' + r.signVerifyError;
    else if (r.signVerify === false) sigText = 'Failed — the certificate did not verify the signature';
    else sigText = 'Not performed';

    UI.fillSummary(document.getElementById('match-summary'), [
      ['Private key', 'RSA ' + r.keyBits + '-bit' + (keyName ? ' (' + keyName + ')' : '')],
      ['Certificate', (cn ? 'CN=' + cn : UI.formatDN(r.certInfo.subject)) + (certName ? ' (' + certName + ')' : '')],
      [
        'Modulus comparison',
        r.modulusEqual === true ? 'Identical modulus and public exponent' : 'Modulus differs — different key pair',
      ],
      ['Sign / verify round-trip', sigText],
      ['Certificate validity', r.certInfo.expired ? 'Expired' : 'Within validity window'],
    ]);

    document.getElementById('match-advice').textContent = r.match
      ? 'Good pair: this key and certificate belong together and will work as a pair (for example in a TLS server config).'
      : 'These do not belong together. A common cause: a renewed certificate saved next to the previous key. Find the key that was used when this certificate was created (or the certificate that matches this key).';

    UI.show('results');
    UI.announce(r.match ? 'Result: match.' : 'Result: no match.');
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    UI.setError('');
    var keyText = keyInput.value.trim();
    var certValue = certInput.value.trim();
    var keyName = keyFile.files && keyFile.files[0] ? keyFile.files[0].name : null;
    var certName = certFile.files && certFile.files[0] ? certFile.files[0].name : null;

    function run(kv, cv) {
      try {
        render(CK.keyMatchReport(kv, cv), keyName, certName);
      } catch (err) {
        fail(err);
      }
    }

    var jobs = [];
    if (keyFile.files && keyFile.files[0]) {
      jobs.push(UI.readFile(keyFile.files[0]).then(function (f) {
        keyText = /-----BEGIN/.test(f.text) ? f.text.trim() : keyText;
      }));
    }
    if (certFile.files && certFile.files[0]) {
      jobs.push(
        UI.readFile(certFile.files[0]).then(function (f) {
          certValue = /-----BEGIN/.test(f.text) ? f.text.trim() : f.bytes;
        })
      );
    }
    Promise.all(jobs).then(function () {
      if (!keyText) {
        UI.setError('Provide the private key — paste it or choose a key file.');
        return;
      }
      if (!certValue) {
        UI.setError('Provide the certificate — paste it or choose a certificate file.');
        return;
      }
      run(keyText, certValue);
    }, fail);
  });
})();
