/**
 * PFX/P12 → PEM tool. Reads a PKCS#12 file locally and renders the key,
 * the certificate chain and a bundle, with a key-match badge.
 */
(function () {
  'use strict';
  var UI = window.CertKitUI;
  var CK = window.CertKit;

  var form = document.getElementById('tool-form');
  var fileInput = document.getElementById('pfx-file');
  var pwInput = document.getElementById('pfx-password');

  UI.wireDropzones();
  UI.wireOutputActions();

  function fail(err) {
    var msg = (err && err.message) || String(err);
    UI.hide('results');
    if (/MAC could not be verified/i.test(msg)) {
      UI.setError(
        'Wrong password, or the file is damaged — the PKCS#12 integrity check (MAC) failed. ' +
          'Passwords are case-sensitive, so check for typos.'
      );
      UI.announce('Error: wrong password or damaged file.');
    } else if (/RSA only|EC\/Ed25519|not supported|not RSA/i.test(msg)) {
      UI.setError(
        'This file contains EC or Ed25519 keys/certificates and CertKit v1 handles RSA only. ' +
          'EC support is planned.',
        { href: '/roadmap/', label: 'See the roadmap' }
      );
      UI.announce('Error: unsupported key type.');
    } else {
      UI.setError('Could not read this file as PKCS#12 (.pfx / .p12). ' + msg);
      UI.announce('Error: could not parse the file.');
    }
  }

  function matchBadge(match) {
    if (!match) return { kind: 'neutral', label: 'no key/cert pair found' };
    if (match.match) return { kind: 'ok', label: 'key matches certificate' };
    if (match.signVerifyError) {
      return { kind: 'bad', label: 'key does NOT match certificate' };
    }
    return { kind: 'bad', label: 'key does NOT match certificate' };
  }

  function render(file, r) {
    var badge = matchBadge(r.keyMatch);
    UI.setBadge(document.getElementById('match-badge'), badge.kind, badge.label);

    var encryption = (r.rawOids || [])
      .map(function (o) {
        return o.name;
      })
      .filter(function (v, i, a) {
        return a.indexOf(v) === i;
      });

    UI.fillSummary(document.getElementById('file-summary'), [
      ['File', file.name + ' · ' + UI.fmtBytes(file.size)],
      [
        'Private key',
        r.hasPrivateKey
          ? 'RSA, ' + (r.raw && r.raw.privateKey && r.raw.privateKey.n ? r.raw.privateKey.n.bitLength() : '?') + '-bit'
          : 'none found',
      ],
      ['Certificates', String(r.certs.length) + (r.certs.length === 1 ? ' certificate' : ' certificates')],
      ['File encryption', encryption.length ? encryption.join(', ') : 'none detected'],
      ['Parse time', r.elapsedMs + ' ms'],
    ]);

    UI.setOutput('out-key', r.pems.privateKey || '');
    UI.setOutput('out-certs', r.pems.certificates || '');
    UI.setOutput('out-bundle', r.pems.bundle || '');

    UI.show('results');
    UI.announce(
      'Converted. ' +
        r.certs.length +
        ' certificate(s), private key ' +
        (r.hasPrivateKey ? 'found' : 'not found') +
        (r.keyMatch ? (r.keyMatch.match ? ', key matches certificate.' : ', key does not match certificate.') : '.')
    );
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    UI.setError('');
    var file = fileInput.files && fileInput.files[0];
    if (!file) {
      UI.setError('Choose a .pfx / .p12 file first — drag & drop it onto the file box or use the picker.');
      UI.announce('Error: no file selected.');
      return;
    }
    UI.readFile(file)
      .then(function (f) {
        var r = CK.parsePfx(f.bytes, pwInput.value);
        render(file, r);
      })
      .catch(fail);
  });
})();
