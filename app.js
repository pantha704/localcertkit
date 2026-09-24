/* DOM wiring for the certkit spike page. Uses global `CertKit` (lib/certkit.js). */
(function () {
  'use strict';
  var fileInput = document.getElementById('pfx');
  var pwInput = document.getElementById('pw');
  var parseBtn = document.getElementById('parse');
  var statusEl = document.getElementById('status');
  var resultsEl = document.getElementById('results');

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  function attrRows(attrs) {
    return attrs.map(function (a) {
      return '<tr><td>' + esc(a.short) + '</td><td>' + esc(a.value) + '</td></tr>';
    }).join('');
  }

  function certCard(c, i) {
    return (
      '<div class="card"><h2>Certificate #' + (i + 1) + (c.selfSigned ? ' <span class="badge">self-signed</span>' : '') + '</h2>' +
      '<table>' +
      '<tr><th>Subject</th><td><table>' + attrRows(c.subject) + '</table></td></tr>' +
      '<tr><th>Issuer</th><td><table>' + attrRows(c.issuer) + '</table></td></tr>' +
      '<tr><th>Serial</th><td><code>' + esc(c.serialNumber) + '</code></td></tr>' +
      '<tr><th>Valid</th><td>' + esc(c.validFrom) + ' &rarr; ' + esc(c.validTo) +
      (c.expired ? ' <span class="bad">EXPIRED</span>' : '') + '</td></tr>' +
      '<tr><th>SAN</th><td>' + (c.san.length ? c.san.map(function (s) { return '<code>' + esc(s.type + ':' + s.value) + '</code>'; }).join('<br>') : '<span class="muted">none</span>') + '</td></tr>' +
      '<tr><th>Public key</th><td>' + esc(c.publicKeyType) + (c.rsaBits ? ' ' + c.rsaBits + ' bits' : '') + '</td></tr>' +
      '<tr><th>SHA-256 fp</th><td class="muted"><code>' + esc(c.sha256Fingerprint) + '</code></td></tr>' +
      '</table></div>'
    );
  }

  function pemSection(title, id, text) {
    if (!text) return '';
    return (
      '<h2>' + esc(title) + '</h2>' +
      '<div class="row"><button data-copy="' + id + '">Copy</button>' +
      '<button data-dl="' + id + '" data-name="' + esc(id) + '.pem">Download</button>' +
      '<span class="muted">' + text.length + ' chars</span></div>' +
      '<textarea id="' + id + '" readonly>' + esc(text) + '</textarea>'
    );
  }

  function render(result) {
    var html = '';
    var km = result.keyMatch;
    html += '<div class="card"><h2>Summary</h2><table>' +
      '<tr><th>File size</th><td>' + result.fileBytes + ' bytes</td></tr>' +
      '<tr><th>Parse time</th><td>' + result.elapsedMs + ' ms (der ' + result.timings.der + ' ms, bags ' + result.timings.bagsDecrypt + ' ms, pem ' + result.timings.pemExport + ' ms)</td></tr>' +
      '<tr><th>Bags</th><td>' + esc(JSON.stringify(result.bagCounts)) + '</td></tr>' +
      '<tr><th>Private key</th><td>' + (result.hasPrivateKey ? esc(result.privateKeyType) : '<span class="bad">none found</span>') + '</td></tr>' +
      '<tr><th>Certificates</th><td>' + result.certs.length + '</td></tr>' +
      '<tr><th>Key &harr; cert match</th><td>' + (km ? (km.match ? '<span class="ok">YES</span>' : '<span class="bad">NO</span>') +
        ' <span class="muted">(modulus equal: ' + km.modulusEqual + ', sign/verify: ' + km.signVerify + (km.signVerifyError ? ', err: ' + esc(km.signVerifyError) : '') + ')</span>' : '<span class="warn">n/a</span>') + '</td></tr>' +
      '</table></div>';

    result.certs.forEach(function (c, i) { html += certCard(c, i); });

    if (result.rawOids && result.rawOids.length) {
      html += '<h2>Raw algorithm OIDs seen in file (informational)</h2><pre class="muted">' +
        esc(result.rawOids.map(function (o) { return o.oid + '  ' + o.name; }).join('\n')) + '</pre>';
    }

    html += pemSection('Private key (PEM)', 'pem-key', result.pems.privateKey);
    html += pemSection('Certificates (PEM, file order)', 'pem-certs', result.pems.certificates);
    html += pemSection('Bundle (key + chain)', 'pem-bundle', result.pems.bundle);
    resultsEl.innerHTML = html;
  }

  function fail(err) {
    resultsEl.innerHTML = '<div class="card"><h2 class="bad">FAILED</h2><pre>' + esc(err && err.message ? err.message : String(err)) + '</pre></div>';
  }

  function readFileAsBytes(file) {
    return file.arrayBuffer().then(function (ab) { return new Uint8Array(ab); });
  }

  parseBtn.addEventListener('click', function () {
    window.__certkit_result = null;
    window.__certkit_state = 'running';
    statusEl.textContent = 'parsing…';
    statusEl.className = 'muted';
    var f = fileInput.files && fileInput.files[0];
    if (!f) { statusEl.textContent = 'pick a file first'; return; }
    readFileAsBytes(f).then(function (bytes) {
      var pw = pwInput.value === '' ? null : pwInput.value;
      try {
        var t0 = performance.now();
        var result = CertKit.parsePfx(bytes, pw);
        result.wallMs = +(performance.now() - t0).toFixed(1);
        result.fileName = f.name;
        window.__certkit_result = result;
        window.__certkit_state = 'done';
        render(result);
        statusEl.textContent = 'parsed in ' + result.wallMs + ' ms';
        statusEl.className = 'ok';
      } catch (e) {
        window.__certkit_result = { ok: false, error: e.message, fileName: f.name, fileBytes: bytes.length };
        window.__certkit_state = 'done';
        fail(e);
        statusEl.textContent = 'failed';
        statusEl.className = 'bad';
      }
    }).catch(function (e) {
      window.__certkit_result = { ok: false, error: 'read error: ' + e.message, fileName: f.name };
      window.__certkit_state = 'done';
      fail(e);
    });
  });

  document.addEventListener('click', function (ev) {
    var t = ev.target;
    if (t.dataset && t.dataset.copy) {
      var ta = document.getElementById(t.dataset.copy);
      if (ta) navigator.clipboard && navigator.clipboard.writeText(ta.value);
    }
    if (t.dataset && t.dataset.dl) {
      var ta2 = document.getElementById(t.dataset.dl);
      if (ta2) {
        var blob = new Blob([ta2.value], { type: 'application/x-pem-file' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = t.dataset.name || 'export.pem';
        a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
      }
    }
  });
})();
