/* SomoTechs SOC — Theme Visual Effects
   Matrix rain, scanlines, glow pulses, glitch.
   Loaded deferred; responds to data-theme attribute changes. */
(function () {
  var scanlines = null;
  var matrixCanvas = null, matrixCtx = null, matrixTimer = null;
  var matrixW = 0, matrixH = 0, matrixDrops = [];

  var CHARS = 'アイウエオカキクケコサシスセソタチツテトハヒフヘホナニヌネノ' +
              'ラリルレロワヲン0123456789ABCDEF<>{}[]/\\|=+-';
  var COL = 16;

  /* ── scanline overlay ─────────────────────────────── */
  function ensureScanlines() {
    if (scanlines) return;
    scanlines = document.createElement('div');
    scanlines.id = 'fx-scanlines';
    document.body.appendChild(scanlines);
  }

  /* ── matrix rain ──────────────────────────────────── */
  function resizeMatrix() {
    matrixW = matrixCanvas.width  = window.innerWidth;
    matrixH = matrixCanvas.height = window.innerHeight;
    var cols = Math.floor(matrixW / COL);
    matrixDrops = [];
    for (var i = 0; i < cols; i++) {
      matrixDrops[i] = -(Math.random() * 40 | 0);
    }
  }

  function drawMatrix() {
    /* fade trail */
    matrixCtx.fillStyle = 'rgba(0,13,0,0.045)';
    matrixCtx.fillRect(0, 0, matrixW, matrixH);
    matrixCtx.font = '13px "Courier New",monospace';
    for (var i = 0; i < matrixDrops.length; i++) {
      var row = matrixDrops[i];
      if (row <= 0) { matrixDrops[i]++; continue; }
      var x = i * COL;
      var y = row * COL;
      var ch = CHARS[Math.floor(Math.random() * CHARS.length)];
      /* bright lead glyph */
      matrixCtx.fillStyle = '#c8ffc8';
      matrixCtx.fillText(ch, x, y);
      /* dim the one just behind */
      if (row > 1) {
        matrixCtx.fillStyle = '#00cc33';
        matrixCtx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], x, (row - 1) * COL);
      }
      if (y > matrixH && Math.random() > 0.972) {
        matrixDrops[i] = 0;
      } else {
        matrixDrops[i]++;
      }
    }
  }

  function startMatrix() {
    if (matrixCanvas) return;
    matrixCanvas = document.createElement('canvas');
    matrixCanvas.id = 'fx-matrix-rain';
    matrixCanvas.style.cssText =
      'position:fixed;inset:0;pointer-events:none;z-index:1;opacity:.15;mix-blend-mode:screen;';
    document.body.insertBefore(matrixCanvas, document.body.firstChild);
    matrixCtx = matrixCanvas.getContext('2d');
    resizeMatrix();
    window.addEventListener('resize', resizeMatrix);
    matrixTimer = setInterval(drawMatrix, 45);
  }

  function stopMatrix() {
    if (matrixTimer) { clearInterval(matrixTimer); matrixTimer = null; }
    if (matrixCanvas) {
      window.removeEventListener('resize', resizeMatrix);
      matrixCanvas.remove();
      matrixCanvas = null;
      matrixCtx = null;
    }
  }

  /* ── theme switch ─────────────────────────────────── */
  function apply(theme) {
    document.body.classList.remove('fx-matrix', 'fx-crimson', 'fx-solar', 'fx-slate');
    stopMatrix();
    if (theme === 'matrix') {
      document.body.classList.add('fx-matrix');
      startMatrix();
    } else if (theme === 'crimson') {
      document.body.classList.add('fx-crimson');
    } else if (theme === 'solar') {
      document.body.classList.add('fx-solar');
    } else if (theme === 'slate') {
      document.body.classList.add('fx-slate');
    }
  }

  /* ── init ─────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    ensureScanlines();
    var t = localStorage.getItem('soc-theme') || 'midnight';
    apply(t);

    new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        if (m.attributeName === 'data-theme') {
          apply(document.documentElement.getAttribute('data-theme') || 'midnight');
        }
      });
    }).observe(document.documentElement, { attributes: true });
  });
})();
