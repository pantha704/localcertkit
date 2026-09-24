/**
 * Chain order — order certificates leaf → intermediate → root, verify issuer
 * links, report missing issuers / unlinked certificates / duplicates.
 */
(function () {
  'use strict';
  var UI = window.CertKitUI;
  var CK = window.CertKit;

  var form = document.getElementById('tool-form');
  var filesInput = document.getElementById('chain-files');
  var textarea = document.getElementById('chain-input');

  UI.wireDropzones();

  function fail(err) {
    UI.hide('results');
    UI.setError((err && err.message) || String(err));
    UI.announce('Error: could not order the chain.');
  }

  function roleFor(entry, index) {
    if (index === 0) return entry.selfSigned ? 'self-signed certificate' : 'leaf';
    return entry.selfSigned ? 'root (self-signed)' : 'intermediate';
  }

  function render(r) {
    var badge = document.getElementById('chain-badge');
    if (r.allValid) {
      UI.setBadge(badge, 'ok', 'chain complete — all links verified');
    } else if (r.missing.length) {
      UI.setBadge(badge, 'warn', r.missing.length + ' missing issuer link' + (r.missing.length === 1 ? '' : 's'));
    } else if (r.unlinked.length) {
      UI.setBadge(badge, 'warn', r.unlinked.length + ' certificate' + (r.unlinked.length === 1 ? '' : 's') + ' could not be linked');
    } else {
      UI.setBadge(badge, 'warn', 'chain needs attention');
    }

    var list = document.getElementById('chain-list');
    list.textContent = '';
    r.ordered.forEach(function (item, i) {
      var entry = item.entry;
      var li = UI.el('li', null, [
        UI.el('strong', { text: entry.subjectCN || UI.formatDN(entry.subject) }),
        UI.el('span', { class: 'chain-role', text: roleFor(entry, i) }),
        UI.el('p', {
          class: 'small',
          text:
            'Issuer: ' +
            (entry.issuerCN ? 'CN=' + entry.issuerCN : UI.formatDN(entry.issuer)) +
            ' · Serial: ' +
            entry.serialNumber +
            ' · Expires: ' +
            UI.fmtDate(entry.validTo) +
            (entry.expired ? ' (expired)' : ''),
        }),
      ]);
      list.appendChild(li);
    });

    var linksList = document.getElementById('links-list');
    linksList.textContent = '';
    if (r.links.length) {
      r.links.forEach(function (link) {
        var verified = link.signatureValid === true;
        linksList.appendChild(
          UI.el('li', {
            text:
              (link.fromCN || '(certificate)') +
              ' ← issued by ' +
              (link.toCN || '(certificate)') +
              ' — ' +
              (verified ? 'signature verified' : link.signatureValid === false ? 'SIGNATURE CHECK FAILED' : 'signature not verifiable'),
          })
        );
      });
    } else {
      linksList.appendChild(UI.el('li', { class: 'muted', text: 'No issuer links found in this input.' }));
    }

    var missingBlock = document.getElementById('missing-block');
    var missingList = document.getElementById('missing-list');
    missingList.textContent = '';
    if (r.missing.length) {
      r.missing.forEach(function (m) {
        missingList.appendChild(
          UI.el('li', {
            text:
              'Missing issuer for ' +
              (m.neededByCN || '(certificate)') +
              ': expected issuer ' +
              (m.issuerCN ? 'CN=' + m.issuerCN : UI.formatDN(m.issuer)),
          })
        );
      });
      missingBlock.hidden = false;
    } else {
      missingBlock.hidden = true;
    }

    var unlinkedBlock = document.getElementById('unlinked-block');
    var unlinkedList = document.getElementById('unlinked-list');
    unlinkedList.textContent = '';
    if (r.unlinked.length) {
      r.unlinked.forEach(function (u) {
        unlinkedList.appendChild(
          UI.el('li', {
            text:
              'CN=' +
              (u.entry.subjectCN || '(no CN)') +
              ' — issuer ' +
              (u.entry.issuerCN ? 'CN=' + u.entry.issuerCN : UI.formatDN(u.entry.issuer)) +
              ' (not part of the ordered chain)',
          })
        );
      });
      unlinkedBlock.hidden = false;
    } else {
      unlinkedBlock.hidden = true;
    }

    var notes = [];
    if (r.duplicates) {
      notes.push(r.duplicates + ' duplicate certificate' + (r.duplicates === 1 ? '' : 's') + ' ignored.');
    }
    if (r.parseErrors.length) {
      r.parseErrors.forEach(function (msg) {
        notes.push('Input could not be parsed: ' + msg);
      });
    }
    var notesBlock = document.getElementById('notes-block');
    var notesList = document.getElementById('notes-list');
    notesList.textContent = '';
    if (notes.length) {
      notes.forEach(function (n) {
        notesList.appendChild(UI.el('li', { text: n }));
      });
      notesBlock.hidden = false;
    } else {
      notesBlock.hidden = true;
    }

    UI.show('results');
    UI.announce(
      'Chain ordered: ' +
        r.ordered
          .map(function (o) {
            return o.entry.subjectCN || '(certificate)';
          })
          .join(' → ') +
        (r.missing.length ? '. Missing issuer: ' + r.missing.length : '.')
    );
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    UI.setError('');
    var text = textarea.value;
    var inputs = CK.splitPemCertificates(text);
    var fileJobs = [];

    Array.prototype.forEach.call(filesInput.files || [], function (file) {
      fileJobs.push(
        UI.readFile(file).then(function (f) {
          if (/-----BEGIN CERTIFICATE-----/.test(f.text)) {
            var parts = CK.splitPemCertificates(f.text);
            if (parts.length) {
              parts.forEach(function (p) {
                inputs.push(p);
              });
              return;
            }
          }
          inputs.push(f.bytes);
        })
      );
    });

    Promise.all(fileJobs).then(function () {
      if (!inputs.length) {
        UI.setError('Paste at least one certificate or choose certificate file(s) first.');
        UI.announce('Error: no certificates provided.');
        return;
      }
      try {
        render(CK.orderChain(inputs));
      } catch (err) {
        fail(err);
      }
    }, fail);
  });
})();
