// Neon-flavored Chart.js helpers to draw crisp, high-contrast charts.
// Provides gradient fills for lines and a stylized ring chart with soft depth.

(function () {
  if (typeof Chart === 'undefined') return;

  const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
  Chart.defaults.global.devicePixelRatio = dpr;
  Chart.defaults.global.defaultFontFamily = "'Space Grotesk','Manrope','Segoe UI',sans-serif";
  Chart.defaults.global.defaultFontColor = '#e5ecff';
  Chart.defaults.global.defaultFontSize = 13;
  Chart.defaults.global.elements.line.borderWidth = 2;
  Chart.defaults.global.elements.line.tension = 0.3;
  Chart.defaults.global.elements.point.radius = 3;
  Chart.defaults.global.elements.point.hoverRadius = 5;
  Chart.defaults.global.legend.labels.boxWidth = 14;

  const palette = {
    critical: '#ff5d73',
    high: '#ff8f3f',
    medium: '#facc15',
    low: '#4dd4ff',
    info: '#7f5af0',
    surface: '#121828'
  };

  function makeLineGradient(ctx, stroke) {
    const grad = ctx.createLinearGradient(0, 0, 0, ctx.canvas.height);
    grad.addColorStop(0, Chart.helpers.color(stroke).alpha(0.25).rgbString());
    grad.addColorStop(0.5, Chart.helpers.color(stroke).alpha(0.08).rgbString());
    grad.addColorStop(1, Chart.helpers.color(stroke).alpha(0).rgbString());
    return grad;
  }

  // Plugin to paint soft background rings behind doughnuts.
  const backgroundRings = {
    beforeDraw(chart) {
      const { ctx, chartArea } = chart;
      if (!chartArea) return;
      const cx = (chartArea.left + chartArea.right) / 2;
      const cy = (chartArea.top + chartArea.bottom) / 2;
      const maxR = Math.min(chartArea.right - chartArea.left, chartArea.bottom - chartArea.top) / 2;
      const rings = [
        { r: maxR * 0.95, alpha: 0.08 },
        { r: maxR * 0.78, alpha: 0.06 },
        { r: maxR * 0.62, alpha: 0.05 },
        { r: maxR * 0.48, alpha: 0.04 }
      ];
      ctx.save();
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      rings.forEach(({ r, alpha }) => {
        ctx.beginPath();
        ctx.lineWidth = 14;
        ctx.strokeStyle = `rgba(255,255,255,${alpha})`;
        ctx.shadowColor = 'rgba(0,0,0,0.35)';
        ctx.shadowBlur = 8;
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
      });
      ctx.restore();
    }
  };

  // Plugin to render center text (value + label) on doughnuts.
  const centerText = {
    afterDraw(chart, args, opts) {
      if (!opts || !opts.display) return;
      const { ctx, chartArea } = chart;
      if (!chartArea) return;
      const cx = (chartArea.left + chartArea.right) / 2;
      const cy = (chartArea.top + chartArea.bottom) / 2;
      ctx.save();
      ctx.fillStyle = '#f8fafc';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '600 26px "Space Grotesk", "Manrope", "Segoe UI", sans-serif';
      ctx.fillText(opts.text || '', cx, cy - 8);
      if (opts.subtext) {
        ctx.globalAlpha = 0.75;
        ctx.font = '500 14px "Space Grotesk", "Manrope", "Segoe UI", sans-serif';
        ctx.fillText(opts.subtext, cx, cy + 14);
      }
      ctx.restore();
    }
  };

  // Add a soft glow on arc draw
  const arcGlow = {
    afterDatasetDraw(chart, args) {
      const { ctx } = chart;
      const meta = args.meta;
      if (!meta || !meta.data) return;
      ctx.save();
      ctx.shadowColor = 'rgba(0,0,0,0.35)';
      ctx.shadowBlur = 14;
      ctx.shadowOffsetX = 0;
      ctx.shadowOffsetY = 6;
      meta.data.forEach(el => el.draw());
      ctx.restore();
    }
  };

  function renderRingChart(canvasId, values, labels, colors) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || typeof Chart === 'undefined') return null;
    const ctx = canvas.getContext('2d');

    // Map incoming values to labels for easier ordering
    const mapped = {};
    labels.forEach((label, idx) => {
      mapped[label.toLowerCase()] = {
        value: parseFloat(values[idx]) || 0,
        color: colors[idx] || palette.info
      };
    });

    // Inner to outer order
    const ringOrder = [
      { key: 'low', weight: 1.4 },
      { key: 'medium', weight: 1.6 },
      { key: 'high', weight: 1.8 },
      { key: 'critical', weight: 2.0 }
    ];

    const total = ringOrder.reduce((sum, item) => sum + (mapped[item.key]?.value || 0), 0);
    const centerLabel = (window.NEON_CHART && window.NEON_CHART.centerLabel) || canvas.dataset.label || '';

    // Accessible description
    const altText = `Issues total ${total}. Critical ${mapped.critical?.value || 0}, High ${mapped.high?.value || 0}, Medium ${mapped.medium?.value || 0}, Low ${mapped.low?.value || 0}`;
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', altText);
    canvas.setAttribute('title', altText);

    const datasets = ringOrder.map((item, idx) => {
      const severity = mapped[item.key] || { value: 0, color: palette.surface };
      const remainder = Math.max(total - severity.value, 0);
      return {
        label: item.key.charAt(0).toUpperCase() + item.key.slice(1),
        data: [severity.value, remainder],
        backgroundColor: [
          severity.color,
          'rgba(255,255,255,0.06)'
        ],
        borderColor: 'rgba(0,0,0,0)',
        borderWidth: 10,
        hoverBorderWidth: 12,
        hoverBorderColor: [
          Chart.helpers.color(severity.color).alpha(0.4).rgbString(),
          'rgba(255,255,255,0.08)'
        ],
        weight: item.weight,
        cutoutPercentage: 35 + idx * 3 // subtle gradation
      };
    });

    return new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels,
        datasets
      },
      plugins: [backgroundRings, centerText, arcGlow],
      options: {
        devicePixelRatio: dpr,
        responsive: true,
        maintainAspectRatio: true,
        cutoutPercentage: 30,
        rotation: -Math.PI / 2,
        layout: { padding: 16 },
        animation: {
          animateRotate: true,
          animateScale: true,
          duration: 900,
          easing: 'easeOutQuart'
        },
        legend: { display: false },
        tooltips: {
          backgroundColor: 'rgba(9,12,20,0.92)',
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          bodyFontSize: 13,
          xPadding: 12,
          yPadding: 8,
          displayColors: false,
          callbacks: {
            label: function (tooltipItem, data) {
              if (tooltipItem.index !== 0) return null; // skip remainder slice
              const ds = data.datasets[tooltipItem.datasetIndex];
              const value = ds.data[0];
              return `${ds.label}: ${value}`;
            }
          }
        },
        doughnutCenterText: {
          display: true,
          text: total || 0,
          subtext: centerLabel
        }
      }
    });
  }

  // Export helpers to the global scope used in templates.
  window.NEON_CHART = {
    palette,
    makeLineGradient,
    renderRingChart,
    centerLabel: ''
  };
})();
