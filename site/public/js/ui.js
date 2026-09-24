/**
 * CertKit UI helpers — shared by all tool pages.
 * Plain ES5-ish browser script, no dependencies besides window.CertKit.
 */
(function () {
  'use strict';

  var $ = function (sel, root) {
    return (root || document).querySelector(sel);
  };
  var $$ = function (sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  };

  /** Screen-reader announcement (role=status element on each tool page). */
  function announce(message) {
    var el = document.getElementById('tool-status');
    if (!el) return;
    el.textContent = '';
    window.setTimeout(function () {
      el.textContent = message;
    }, 30);
  }

  /**
   * Show an error in the page's role=alert box.
   * @param {string} message
   * @param {{href: string, label: string}} [link] optional follow-up link
   */
  function setError(message, link) {
    var el = document.getElementById('tool-error');
    if (!el) return;
    el.textContent = '';
    if (!message) {
      el.hidden = true;
      return;
    }
    el.appendChild(document.createTextNode(message));
    if (link) {
      var p = document.createElement('p');
      var a = document.createElement('a');
      a.href = link.href;
      a.textContent = link.label;
      p.appendChild(a);
      el.appendChild(p);
    }
    el.hidden = false;
  }

  function show(id) {
    var el = document.getElementById(id);
    if (el) el.hidden = false;
  }

  function hide(id) {
    var el = document.getElementById(id);
    if (el) el.hidden = true;
  }

  /** Route dropped files into the matching <input type=file> and fire change. */
  function wireDropzones(root) {
    $$('[data-dropzone]', root).forEach(function (zone) {
      var input = $('input[type="file"]', zone);
      if (!input) return;
      ['dragenter', 'dragover'].forEach(function (ev) {
        zone.addEventListener(ev, function (e) {
          e.preventDefault();
          zone.classList.add('is-dragging');
        });
      });
      ['dragleave', 'dragend'].forEach(function (ev) {
        zone.addEventListener(ev, function () {
          zone.classList.remove('is-dragging');
        });
      });
      zone.addEventListener('drop', function (e) {
        e.preventDefault();
        zone.classList.remove('is-dragging');
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
          try {
            input.files = e.dataTransfer.files;
          } catch (_) {
            /* browser refused the assignment; user can still use the picker */
          }
          input.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
    });
  }

  /** Read a File into { name, size, bytes, text } (ArrayBuffer via FileReader). */
  function readFile(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onerror = function () {
        reject(new Error('Could not read ' + file.name + ' from disk.'));
      };
      reader.onload = function () {
        var bytes = new Uint8Array(reader.result);
        var text = '';
        try {
          text = new TextDecoder('utf-8').decode(bytes);
        } catch (_) {
          text = '';
        }
        resolve({ name: file.name, size: file.size, bytes: bytes, text: text });
      };
      reader.readAsArrayBuffer(file);
    });
  }

  /** Copy text with a fallback for non-secure contexts. Reports success. */
  function copyText(text, statusEl) {
    function done(ok) {
      if (!statusEl) return;
      statusEl.textContent = ok ? 'Copied' : 'Copy failed — select the text and copy manually';
      window.setTimeout(function () {
        statusEl.textContent = '';
      }, 2500);
    }
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '-1000px';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try {
        ok = document.execCommand('copy');
      } catch (_) {
        ok = false;
      }
      document.body.removeChild(ta);
      done(ok);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard
        .writeText(text)
        .then(function () {
          done(true);
        })
        .catch(fallback);
    } else {
      fallback();
    }
  }

  function downloadBlob(name, blob) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 4000);
  }

  function downloadText(name, text, mime) {
    downloadBlob(name, new Blob([text], { type: mime || 'text/plain;charset=utf-8' }));
  }

  function downloadBytes(name, bytes, mime) {
    downloadBlob(name, new Blob([bytes], { type: mime || 'application/octet-stream' }));
  }

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  }

  function fmtDate(iso) {
    try {
      return new Date(iso).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch (_) {
      return iso;
    }
  }

  function attrValue(attrs, short) {
    var hit = (attrs || []).filter(function (a) {
      return a.short === short;
    })[0];
    return hit ? hit.value : null;
  }

  function formatDN(attrs) {
    if (!attrs || !attrs.length) return '(empty)';
    return attrs
      .map(function (a) {
        return (a.short || a.name) + '=' + a.value;
      })
      .join(', ');
  }

  /** Set a badge element's variant + label. */
  function setBadge(el, kind, label) {
    if (!el) return;
    el.className = 'badge badge-' + kind;
    el.textContent = label;
  }

  /** Tiny DOM builder: el('div', {class:'x', text:'hi'}, [childNode]) */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'text') node.textContent = attrs[k];
        else if (k === 'class') node.className = attrs[k];
        else node.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      node.appendChild(c);
    });
    return node;
  }

  /**
   * Fill a <dl class="summary-dl"> with [term, valueNode|string] rows.
   */
  function fillSummary(dl, rows) {
    dl.textContent = '';
    rows.forEach(function (row) {
      if (!row) return;
      var dt = document.createElement('dt');
      dt.textContent = row[0];
      var dd = document.createElement('dd');
      if (typeof row[1] === 'string' || typeof row[1] === 'number') {
        dd.textContent = String(row[1]);
      } else if (row[1]) {
        dd.appendChild(row[1]);
      }
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
  }

  /** Textarea helpers: output panes are readonly textareas. */
  function setOutput(id, value) {
    var el = document.getElementById(id);
    if (el) el.value = value || '';
  }

  function getOutput(id) {
    var el = document.getElementById(id);
    return el ? el.value : '';
  }

  /** Segmented control: two buttons toggling two panes. */
  function wireToggle(buttons, panes) {
    buttons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        var target = btn.getAttribute('data-pane');
        buttons.forEach(function (b) {
          b.setAttribute('aria-pressed', b === btn ? 'true' : 'false');
        });
        Object.keys(panes).forEach(function (key) {
          var pane = document.getElementById(panes[key]);
          if (pane) pane.hidden = key !== target;
        });
      });
    });
  }

  /**
   * Wire [data-copy] and [data-download] buttons to their output panes.
   * Copy status goes to the element with id `data-copy-status` value.
   */
  function wireOutputActions(root) {
    $$('[data-copy]', root).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var src = document.getElementById(btn.getAttribute('data-copy'));
        var statusId = btn.getAttribute('data-copy-status');
        var statusEl = statusId ? document.getElementById(statusId) : null;
        copyText(src ? src.value : '', statusEl);
      });
    });
    $$('[data-download]', root).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var src = document.getElementById(btn.getAttribute('data-download'));
        var name = btn.getAttribute('data-filename') || 'certkit.txt';
        var mime = btn.getAttribute('data-mime') || 'text/plain;charset=utf-8';
        if (src && src.value) downloadText(name, src.value, mime);
      });
    });
  }

  window.CertKitUI = {
    $: $,
    $$: $$,
    announce: announce,
    setError: setError,
    show: show,
    hide: hide,
    wireDropzones: wireDropzones,
    readFile: readFile,
    copyText: copyText,
    downloadText: downloadText,
    downloadBytes: downloadBytes,
    fmtBytes: fmtBytes,
    fmtDate: fmtDate,
    attrValue: attrValue,
    formatDN: formatDN,
    setBadge: setBadge,
    el: el,
    fillSummary: fillSummary,
    setOutput: setOutput,
    getOutput: getOutput,
    wireToggle: wireToggle,
    wireOutputActions: wireOutputActions,
  };
})();
