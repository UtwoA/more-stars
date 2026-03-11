def render_admin_panel(authed: bool) -> str:
    if not authed:
        return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin Login</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#0e0f12;color:#e9eef7;margin:0;padding:24px}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{width:100%;max-width:420px;background:#15181d;border:1px solid #1f232b;border-radius:16px;padding:20px}
    .btn{display:block;width:100%;padding:12px 14px;border-radius:10px;border:0;background:#2a8bf2;color:#fff;font-weight:700;margin-top:10px;cursor:pointer}
    .input{width:100%;padding:12px;border-radius:10px;border:1px solid #2a2f38;background:#0e1116;color:#e9eef7}
    .muted{color:#8b93a7;font-size:12px;margin-top:8px}
  </style>
</head>
<body>
  <div class="wrap">
  <div class="card">
    <h2>Admin Access</h2>
    <div class="muted">Request one-time code in Telegram, then enter it here.</div>
    <button class="btn" onclick="requestCode()">Send code</button>
    <div style="height:12px"></div>
    <input class="input" id="code" placeholder="6-digit code" />
    <button class="btn" onclick="verifyCode()">Verify</button>
    <div id="status" class="muted"></div>
  </div>
  </div>
  <script>
    async function requestCode(){
      const res = await fetch('/admin/otp/request', {method:'POST', credentials:'include'});
      document.getElementById('status').textContent = res.ok ? 'Code sent' : 'Failed to send';
    }
    async function verifyCode(){
      const code = document.getElementById('code').value.trim();
      if(!code) return;
      const res = await fetch('/admin/otp/verify', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({code}),
        credentials:'include'
      });
      if(res.ok){ location.reload(); return; }
      document.getElementById('status').textContent = 'Invalid code';
    }
    async function requestCode(){
      const res = await fetch('/admin/otp/request', {method:'POST', credentials:'include'});
      document.getElementById('status').textContent = res.ok ? 'Code sent' : 'Failed to send';
    }
    async function verifyCode(){
      const code = document.getElementById('code').value.trim();
      if(!code) return;
      const res = await fetch('/admin/otp/verify', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({code}),
        credentials:'include'
      });
      if(res.ok){ location.reload(); return; }
      document.getElementById('status').textContent = 'Invalid code';
    }
  </script>
</body>
</html>
"""

    return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Админка</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#0e0f12;color:#e9eef7;margin:0}
    h1{margin:0 0 16px 0}
    .layout{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
    .sidebar{background:#0b0d11;border-right:1px solid #1f232b;padding:18px;display:flex;flex-direction:column;gap:10px}
    .brand{font-weight:800;font-size:16px;margin-bottom:8px}
    .nav{display:flex;flex-direction:column;gap:6px}
    .nav a{display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:10px;color:#c9d1e4;text-decoration:none;border:1px solid transparent}
    .nav a.active{background:#15181d;border-color:#2a2f38;color:#fff}
    .content{padding:24px}
    .grid{display:grid;grid-template-columns:1fr;gap:16px}
    .card{background:#15181d;border:1px solid #1f232b;border-radius:16px;padding:16px}
    .card[data-page]{display:none}
    .card[data-page].active{display:block}
    .section-title{font-weight:800;margin:0 0 10px 0}
    .muted{color:#8b93a7;font-size:12px}
    .btn{display:inline-flex;gap:8px;align-items:center;padding:8px 12px;border-radius:10px;border:1px solid #2a2f38;background:#101318;color:#e9eef7;cursor:pointer}
    .btn.primary{background:#2a8bf2;border-color:#2a8bf2}
    .field{display:flex;flex-direction:column;gap:6px;margin-top:10px}
    .input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a2f38;background:#0e1116;color:#e9eef7}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:10px}
    .metric{background:#101318;border:1px solid #212632;border-radius:12px;padding:12px}
    .metric .label{color:#8b93a7;font-size:12px;margin-bottom:6px}
    .metric .value{font-size:18px;font-weight:800}
    .table{width:100%;border-collapse:collapse;font-size:13px}
    .table th,.table td{padding:8px 10px;border-bottom:1px solid #232834;text-align:left}
    .table th{color:#9aa3b5;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
    .badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:11px;border:1px solid #2a2f38}
    .badge.active{background:#0f2c1e;border-color:#1c6b4b;color:#7fe8b8}
    .badge.expired{background:#2a1b1b;border-color:#6b2a2a;color:#f1a3a3}
    .badge.used{background:#2a231b;border-color:#6b562a;color:#f5d38a}
    .badge.disabled{background:#1e1f26;border-color:#2a2f38;color:#9aa3b5}
    .progress{height:8px;border-radius:999px;background:#0e1116;border:1px solid #232834;overflow:hidden}
    .bar{height:100%;background:#2a8bf2}
    .bars{display:grid;gap:6px}
    .bar-row{display:grid;grid-template-columns:120px 1fr 60px;gap:10px;align-items:center}
    .bar-label{font-size:12px;color:#9aa3b5}
    .bar-value{font-size:12px;color:#c9d1e4;text-align:right}
    .bar-track{height:8px;border-radius:999px;background:#0e1116;border:1px solid #232834;overflow:hidden}
    .bar-fill{height:100%;background:linear-gradient(90deg,#2a8bf2,#6b5bff)}
    .stack{display:flex;flex-direction:column;gap:8px}
    .pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:#9aa3b5}
    .pill b{color:#e9eef7}
    .chart{background:#101318;border:1px solid #212632;border-radius:12px;padding:12px}
    .chart svg{width:100%;height:180px;display:block}
    .chart-title{font-size:13px;color:#9aa3b5;margin-bottom:8px}
    .chart-legend{display:flex;gap:12px;font-size:11px;color:#9aa3b5;margin-top:6px}
    pre{white-space:pre-wrap;word-break:break-word;color:#c9d1e4;font-size:13px}
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">Админка</div>
      <nav class="nav">
        <a href="#dashboard" data-page="dashboard" class="active">Дашборд</a>
        <a href="#analytics" data-page="analytics">Аналитика</a>
        <a href="#users" data-page="users">Пользователи</a>
        <a href="#promos" data-page="promos">Промокоды</a>
        <a href="#bonuses" data-page="bonuses">Бонусы</a>
        <a href="#raffle" data-page="raffle">Розыгрыш</a>
        <a href="#settings" data-page="settings">Настройки</a>
      </nav>
    </aside>
    <main class="content">
      <h1>Панель администратора</h1>
      <div class="grid">
    <div class="card" data-page="dashboard">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Аудит · 24 часа</div>
        <button class="btn" onclick="loadToday()">Обновить</button>
      </div>
      <pre id="today">Загрузка...</pre>
    </div>
    <div class="card" data-page="dashboard">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Аудит · Последние</div>
        <button class="btn" onclick="loadRecent()">Обновить</button>
      </div>
      <pre id="recent">Загрузка...</pre>
      <div class="muted">Последние 200 оплаченных заказов на звёзды.</div>
    </div>
    <div class="card" data-page="analytics">
      <div class="section-title">Графики по дням (30 дней)</div>
      <div class="chart">
        <div class="chart-title">Выручка, ₽</div>
        <div id="chart-revenue"></div>
      </div>
      <div class="chart" style="margin-top:10px">
        <div class="chart-title">Прибыль, ₽</div>
        <div id="chart-profit"></div>
      </div>
      <div class="chart" style="margin-top:10px">
        <div class="chart-title">Заказы, шт</div>
        <div id="chart-orders"></div>
      </div>
    </div>
    <div class="card" data-page="analytics">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Аналитика</div>
        <button class="btn" onclick="loadAnalytics()">Обновить</button>
      </div>
      <div class="metrics" id="analytics-metrics">
        <div class="metric"><div class="label">Открытия</div><div class="value">—</div></div>
      </div>
      <div class="stack" style="margin-top:12px">
        <div class="pill">Период: <b id="analytics-period">—</b></div>
        <div class="pill">Воронка (уник.): <b id="analytics-funnel-label">—</b></div>
        <div class="bars" id="funnel-bars">
          <div class="bar-row">
            <div class="bar-label">Открыли</div>
            <div class="bar-track"><div id="funnel-open" class="bar-fill" style="width:100%"></div></div>
            <div class="bar-value" id="funnel-open-val">—</div>
          </div>
          <div class="bar-row">
            <div class="bar-label">Выбрали</div>
            <div class="bar-track"><div id="funnel-select" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="funnel-select-val">—</div>
          </div>
          <div class="bar-row">
            <div class="bar-label">Оплатили</div>
            <div class="bar-track"><div id="funnel-paid" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="funnel-paid-val">—</div>
          </div>
        </div>
      </div>
      <div class="stack" style="margin-top:14px">
        <div class="pill">P&L: <b id="analytics-pl-label">—</b></div>
        <div class="bars">
          <div class="bar-row">
            <div class="bar-label">Выручка</div>
            <div class="bar-track"><div id="pl-revenue" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="pl-revenue-val">—</div>
          </div>
          <div class="bar-row">
            <div class="bar-label">Себестоимость</div>
            <div class="bar-track"><div id="pl-cost" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="pl-cost-val">—</div>
          </div>
          <div class="bar-row">
            <div class="bar-label">Прибыль</div>
            <div class="bar-track"><div id="pl-profit" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="pl-profit-val">—</div>
          </div>
        </div>
        <div class="muted" id="pl-rate-note"></div>
      </div>
      <div style="margin-top:14px">
        <div class="section-title" style="font-size:14px">Провайдеры</div>
        <table class="table" id="analytics-providers">
          <thead>
            <tr><th>Провайдер</th><th>Заказы</th><th>Выручка ₽</th><th>Конв. %</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div style="margin-top:14px">
        <div class="section-title" style="font-size:14px">ТОП пользователей (выручка)</div>
        <table class="table" id="analytics-top">
          <thead>
            <tr><th>Пользователь</th><th>Выручка ₽</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
    <div class="card" data-page="users">
      <div class="section-title">Поиск пользователей и прибыль</div>
      <div class="row">
        <div class="field">
          <label class="muted">Поиск (id / @username)</label>
          <input class="input" id="user-search" placeholder="683310989 или @username"/>
        </div>
        <div class="field">
          <label class="muted">Период (дней)</label>
          <input class="input" id="user-search-days" type="number" min="1" value="30"/>
        </div>
      </div>
      <button class="btn" onclick="loadUserSearch()" style="margin-top:10px">Искать</button>
      <table class="table" id="users-table" style="margin-top:12px">
        <thead>
          <tr><th>Пользователь</th><th>Выручка ₽</th><th>Себестоимость ₽</th><th>Прибыль ₽</th><th>Заказы</th><th>⭐</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="card" data-page="promos">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Промокоды</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn" onclick="loadPromos()">Все</button>
          <button class="btn" onclick="loadPromos('active')">Активные</button>
          <button class="btn" onclick="loadPromos('expired')">Истёкшие</button>
          <button class="btn" onclick="loadPromos('used')">Использованы</button>
        </div>
      </div>
      <table class="table" id="promo-table">
        <thead>
          <tr><th>Код</th><th>%</th><th>Исп.</th><th>Статус</th><th>До</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="card" data-page="bonuses">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Бонусы</div>
        <button class="btn" onclick="loadBonuses()">Обновить</button>
      </div>
      <table class="table" id="bonus-table">
        <thead>
          <tr><th>Пользователь</th><th>⭐</th><th>Статус</th><th>Источник</th><th>До</th><th>Создан</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="card" data-page="bonuses">
      <strong>Массовая выдача бонусов</strong>
      <div class="field">
        <label class="muted">User IDs (через запятую/пробел/перенос)</label>
        <textarea class="input" id="bonus_bulk_ids" rows="4" placeholder="12345, 67890"></textarea>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Звёзды</label>
          <input class="input" id="bonus_bulk_stars" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">TTL (мин)</label>
          <input class="input" id="bonus_bulk_ttl" type="number" min="1"/>
        </div>
      </div>
      <div class="field">
        <label class="muted">Источник</label>
        <input class="input" id="bonus_bulk_source" placeholder="admin_bulk"/>
      </div>
      <button class="btn" onclick="bulkBonus()" style="margin-top:10px">Выдать бонусы</button>
      <div id="bonus-bulk-status" class="muted"></div>
    </div>
    <div class="card" data-page="raffle">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <strong>Управление розыгрышем</strong>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn" onclick="resetRaffle()">Сбросить период</button>
          <button class="btn" onclick="recalcRaffle()">Пересчитать топ</button>
          <button class="btn" onclick="loadRaffleSummary()">Сводка</button>
          <a class="btn" href="/admin/raffle/participants?format=csv" target="_blank" rel="noopener">Экспорт CSV</a>
        </div>
      </div>
      <div class="muted">Сбросить период — начинается новый период с текущего момента.</div>
      <div class="muted">Пересчитать топ — мгновенно обновляет рейтинг участников.</div>
      <div class="muted">Сводка — кто лидирует и есть ли победитель дня.</div>
      <div class="muted">Экспорт CSV — полный список участников с шансами.</div>
      <div id="raffle-status" class="muted" style="margin-top:8px;"></div>
    </div>
    <div class="card" data-page="settings">
      <strong>Настройки</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Время отчёта (HH:MM)</label>
          <input class="input" id="report_time" placeholder="00:00"/>
        </div>
        <div class="field">
          <label class="muted">Реферальный %</label>
          <input class="input" id="ref_percent" type="number" min="0" max="100"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Цена tier 1 (<=1000)</label>
          <input class="input" id="rate1" type="number" step="0.01"/>
        </div>
        <div class="field">
          <label class="muted">Цена tier 2 (<=5000)</label>
          <input class="input" id="rate2" type="number" step="0.01"/>
        </div>
      </div>
      <div class="field">
        <label class="muted">Цена tier 3 (>5000)</label>
        <input class="input" id="rate3" type="number" step="0.01"/>
      </div>
      <div class="field">
        <label class="muted">Приз (заголовок)</label>
        <input class="input" id="raffle_prize_title" placeholder="NFT-подарок или бонусные звёзды"/>
      </div>
      <div class="field">
        <label class="muted">Приз (описание)</label>
        <input class="input" id="raffle_prize_desc" placeholder="Победитель получит приз после розыгрыша."/>
      </div>
      <div class="field">
        <label class="muted">Ссылка на приз (URL)</label>
        <input class="input" id="raffle_prize_image" placeholder="https://..."/>
      </div>
      <div class="field">
        <label class="muted">Баннер включён (true/false)</label>
        <input class="input" id="banner_enabled" placeholder="false"/>
      </div>
      <div class="field">
        <label class="muted">Заголовок баннера</label>
        <input class="input" id="banner_title" placeholder="Акция недели"/>
      </div>
      <div class="field">
        <label class="muted">Текст баннера</label>
        <input class="input" id="banner_text" placeholder="Скидка 5% на звёзды"/>
      </div>
      <div class="field">
        <label class="muted">Ссылка баннера</label>
        <input class="input" id="banner_url" placeholder="https://t.me/..."/>
      </div>
      <div class="field">
        <label class="muted">Баннер до (YYYY-MM-DD или ISO)</label>
        <input class="input" id="banner_until" placeholder="2026-03-30"/>
      </div>
      <div class="field">
        <label class="muted">Текст под промокодом</label>
        <input class="input" id="promo_text" placeholder="Скидки и промокоды в нашем канале"/>
      </div>
      <button class="btn" onclick="saveSettings()" style="margin-top:10px">Сохранить</button>
      <div id="settings-status" class="muted"></div>
    </div>
    <div class="card" data-page="promos">
      <strong>Создать промокод</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Код</label>
          <input class="input" id="promo_code" placeholder="PROMO2026"/>
        </div>
        <div class="field">
          <label class="muted">Процент</label>
          <input class="input" id="promo_percent" type="number" min="1" max="100"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Лимит использований</label>
          <input class="input" id="promo_max" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">Истекает (YYYY-MM-DD)</label>
          <input class="input" id="promo_exp" placeholder="2026-12-31"/>
        </div>
      </div>
      <button class="btn" onclick="createPromo()" style="margin-top:10px">Создать</button>
      <div id="promo-status" class="muted"></div>
    </div>
    <div class="card" data-page="bonuses">
      <strong>Создать бонус-ссылку</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Звёзды</label>
          <input class="input" id="bonus_stars" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">TTL (мин)</label>
          <input class="input" id="bonus_ttl" type="number" min="1"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Лимит использований</label>
          <input class="input" id="bonus_max" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">Источник</label>
          <input class="input" id="bonus_source" placeholder="promo_tg"/>
        </div>
      </div>
      <button class="btn" onclick="createBonus()" style="margin-top:10px">Создать ссылку</button>
      <div id="bonus-status" class="muted"></div>
    </div>
    </main>
  </div>
  <script>
    function setPage(page){
      const links = document.querySelectorAll('.nav a');
      links.forEach(a => {
        if (a.dataset.page === page) a.classList.add('active');
        else a.classList.remove('active');
      });
      document.querySelectorAll('.card[data-page]').forEach(card => {
        if (card.dataset.page === page) card.classList.add('active');
        else card.classList.remove('active');
      });
      if (page === 'dashboard') { loadToday(); loadRecent(); }
      if (page === 'analytics') { loadAnalytics(); loadAnalyticsDaily(); }
      if (page === 'users') { loadUserSearch(); }
      if (page === 'promos') { loadPromos(); }
      if (page === 'bonuses') { loadBonuses(); }
      if (page === 'raffle') { loadRaffleSummary(); }
      if (page === 'settings') { loadSettings(); }
    }
    const navRoot = document.querySelector('.nav');
    if (navRoot) {
      navRoot.addEventListener('click', (e) => {
        const link = e.target.closest('a[data-page]');
        if (!link) return;
        e.preventDefault();
        const page = link.dataset.page;
        if (!page) return;
        history.replaceState(null, '', `#${page}`);
        setPage(page);
      });
      const initialPage = (location.hash || '#dashboard').replace('#','');
      setPage(initialPage);
      window.addEventListener('hashchange', () => {
        const page = (location.hash || '#dashboard').replace('#','');
        setPage(page);
      });
    }

    function renderLineChart(containerId, points, color){
      const el = document.getElementById(containerId);
      if (!el) return;
      if (!points || points.length === 0) {
        el.innerHTML = '<div class="muted">Нет данных</div>';
        return;
      }
      const w = 600, h = 180, pad = 20;
      const vals = points.map(p => p.y);
      const max = Math.max(...vals, 1);
      const min = Math.min(...vals, 0);
      const span = max - min || 1;
      const step = (w - pad * 2) / Math.max(1, points.length - 1);
      let d = '';
      points.forEach((p, i) => {
        const x = pad + i * step;
        const y = h - pad - ((p.y - min) / span) * (h - pad * 2);
        d += `${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)} `;
      });
      const area = `${d} L ${pad + (points.length - 1) * step} ${h - pad} L ${pad} ${h - pad} Z`;
      el.innerHTML = `
        <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
          <path d="${area}" fill="${color}22"></path>
          <path d="${d}" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"></path>
        </svg>
      `;
    }

    async function loadToday(){
      const res = await fetch('/admin/audit/today', {credentials:'include'});
      const data = await res.json();
      document.getElementById('today').textContent = (data.items || []).join('\\n') || 'Нет данных';
    }
    async function loadRecent(){
      const res = await fetch('/admin/audit/recent', {credentials:'include'});
      const data = await res.json();
      document.getElementById('recent').textContent = (data.items || []).join('\\n') || 'Нет данных';
    }
    async function loadAnalytics(){
      const res = await fetch('/admin/analytics', {credentials:'include'});
      const data = await res.json();
      if(!res.ok){
        const metrics = document.getElementById('analytics-metrics');
        if (metrics) metrics.innerHTML = '<div class="metric"><div class="label">Ошибка</div><div class="value">Не удалось</div></div>';
        return;
      }
      const metrics = document.getElementById('analytics-metrics');
      if (metrics) {
        metrics.innerHTML = '';
        const items = [
          {label:'Открытия', value:`${data.opens} (${data.opens_unique} уник.)`},
          {label:'Выборы', value:`${data.selects} (${data.selects_unique} уник.)`},
          {label:'Создано', value:data.created_orders},
          {label:'Оплачено', value:data.paid_orders},
          {label:'Неудачи', value:data.failed_orders},
          {label:'Выручка', value:`${data.paid_total_rub} ₽`},
          {label:'Себестоимость', value:`${data.cost_total_rub ?? 0} ₽`},
          {label:'Прибыль', value:`${data.profit_total_rub ?? 0} ₽`},
          {label:'Средний чек', value:`${data.avg_check_rub} ₽`},
          {label:'Звёзды', value:`${data.stars_total} +${data.bonus_total}`},
        ];
        items.forEach(it => {
          const el = document.createElement('div');
          el.className = 'metric';
          el.innerHTML = `<div class="label">${it.label}</div><div class="value">${it.value}</div>`;
          metrics.appendChild(el);
        });
      }
      const periodEl = document.getElementById('analytics-period');
      if (periodEl) periodEl.textContent = `${data.period_start} → ${data.period_end}`;
      const funnelLabel = document.getElementById('analytics-funnel-label');
      if (funnelLabel) funnelLabel.textContent = `${data.opens_unique} → ${data.selects_unique} → ${data.paid_orders}`;
      const openBar = document.getElementById('funnel-open');
      const selectBar = document.getElementById('funnel-select');
      const paidBar = document.getElementById('funnel-paid');
      const openVal = Math.max(1, data.opens_unique || 0);
      const selectPct = data.opens_unique ? (data.selects_unique / openVal) * 100 : 0;
      const paidPct = data.opens_unique ? (data.paid_orders / openVal) * 100 : 0;
      if (openBar) openBar.style.width = '100%';
      if (selectBar) selectBar.style.width = `${Math.min(100, selectPct).toFixed(1)}%`;
      if (paidBar) paidBar.style.width = `${Math.min(100, paidPct).toFixed(1)}%`;
      const openValEl = document.getElementById('funnel-open-val');
      const selectValEl = document.getElementById('funnel-select-val');
      const paidValEl = document.getElementById('funnel-paid-val');
      if (openValEl) openValEl.textContent = `${data.opens_unique || 0}`;
      if (selectValEl) selectValEl.textContent = `${data.selects_unique || 0}`;
      if (paidValEl) paidValEl.textContent = `${data.paid_orders || 0}`;

      const revenue = Number(data.paid_total_rub || 0);
      const cost = Number(data.cost_total_rub || 0);
      const profit = Number(data.profit_total_rub || 0);
      const maxPL = Math.max(1, revenue, cost, Math.abs(profit));
      const plLabel = document.getElementById('analytics-pl-label');
      if (plLabel) plLabel.textContent = `${revenue} ₽ / ${cost} ₽ / ${profit} ₽`;
      const plRevenue = document.getElementById('pl-revenue');
      const plCost = document.getElementById('pl-cost');
      const plProfit = document.getElementById('pl-profit');
      if (plRevenue) {
        plRevenue.style.width = `${Math.min(100, (revenue / maxPL) * 100).toFixed(1)}%`;
        plRevenue.style.background = 'linear-gradient(90deg,#2a8bf2,#6b5bff)';
      }
      if (plCost) {
        plCost.style.width = `${Math.min(100, (cost / maxPL) * 100).toFixed(1)}%`;
        plCost.style.background = 'linear-gradient(90deg,#f59e0b,#f97316)';
      }
      if (plProfit) {
        plProfit.style.width = `${Math.min(100, (Math.abs(profit) / maxPL) * 100).toFixed(1)}%`;
        plProfit.style.background = profit >= 0
          ? 'linear-gradient(90deg,#22c55e,#86efac)'
          : 'linear-gradient(90deg,#ef4444,#f97316)';
      }
      const plRevenueVal = document.getElementById('pl-revenue-val');
      const plCostVal = document.getElementById('pl-cost-val');
      const plProfitVal = document.getElementById('pl-profit-val');
      if (plRevenueVal) plRevenueVal.textContent = `${revenue} ₽`;
      if (plCostVal) plCostVal.textContent = `${cost} ₽`;
      if (plProfitVal) plProfitVal.textContent = `${profit} ₽`;
      const rateNote = document.getElementById('pl-rate-note');
      if (rateNote) {
        rateNote.textContent = data.usdtrub_rate
          ? `Курс для себестоимости: ${data.cost_rate_label || 'USD/RUB'} ${data.usdtrub_rate} ₽`
          : '';
      }

      const providersTbody = document.querySelector('#analytics-providers tbody');
      if (providersTbody) {
        providersTbody.innerHTML = '';
        const providers = data.by_provider || {};
        Object.keys(providers).forEach((key) => {
          const revenue = (data.revenue_by_provider || {})[key] ?? 0;
          const conv = (data.provider_conversion_pct || {})[key] ?? 0;
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${key}</td><td>${providers[key]}</td><td>${revenue}</td><td>${conv}%</td>`;
          providersTbody.appendChild(tr);
        });
        if (!Object.keys(providers).length) {
          providersTbody.innerHTML = '<tr><td colspan="4" class="muted">Нет данных</td></tr>';
        }
      }

      const topTbody = document.querySelector('#analytics-top tbody');
      if (topTbody) {
        topTbody.innerHTML = '';
        const top = data.top_users_by_revenue || [];
        top.forEach(item => {
          const name = item.display || `id ${item.user_id}`;
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${name}</td><td>${item.revenue_rub}</td>`;
          topTbody.appendChild(tr);
        });
        if (!top.length) {
          topTbody.innerHTML = '<tr><td colspan="2" class="muted">Нет данных</td></tr>';
        }
      }
    }
    async function loadAnalyticsDaily(){
      const res = await fetch('/admin/analytics/daily?days=30', {credentials:'include'});
      const data = await res.json();
      if(!res.ok || !data.items){ 
        renderLineChart('chart-revenue', [], '#2a8bf2');
        renderLineChart('chart-profit', [], '#22c55e');
        renderLineChart('chart-orders', [], '#f59e0b');
        return;
      }
      const revenue = data.items.map((d,i)=>({x:i, y:Number(d.revenue||0)}));
      const profit = data.items.map((d,i)=>({x:i, y:Number(d.profit||0)}));
      const orders = data.items.map((d,i)=>({x:i, y:Number(d.orders||0)}));
      renderLineChart('chart-revenue', revenue, '#2a8bf2');
      renderLineChart('chart-profit', profit, '#22c55e');
      renderLineChart('chart-orders', orders, '#f59e0b');
    }

    async function loadUserSearch(){
      const q = (document.getElementById('user-search')?.value || '').trim();
      const days = Number(document.getElementById('user-search-days')?.value || 30) || 30;
      const qs = `?days=${encodeURIComponent(days)}${q ? `&q=${encodeURIComponent(q)}` : ''}`;
      const res = await fetch(`/admin/users/search${qs}`, {credentials:'include'});
      const data = await res.json();
      const body = document.querySelector('#users-table tbody');
      if (!body) return;
      if(!res.ok){ body.innerHTML = '<tr><td colspan="6" class="muted">Не удалось</td></tr>'; return; }
      const items = data.items || [];
      body.innerHTML = '';
      items.forEach(item => {
        const name = item.display || `id ${item.user_id}`;
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${name}</td><td>${item.revenue}</td><td>${item.cost}</td><td>${item.profit}</td><td>${item.orders}</td><td>${item.stars}</td>`;
        body.appendChild(tr);
      });
      if (!items.length) body.innerHTML = '<tr><td colspan="6" class="muted">Нет данных</td></tr>';
    }
    async function loadPromos(filter){
      const qs = filter ? `?filter=${encodeURIComponent(filter)}` : '';
      const res = await fetch(`/admin/promos${qs}`, {credentials:'include'});
      const data = await res.json();
      const body = document.querySelector('#promo-table tbody');
      if (!body) return;
      if(!res.ok){ body.innerHTML = '<tr><td colspan="5" class="muted">Не удалось</td></tr>'; return; }
      const items = data.items || [];
      body.innerHTML = '';
      items.forEach(p => {
        const tr = document.createElement('tr');
        const status = p.status || (p.active ? 'active' : 'disabled');
        const statusLabel = status === 'active' ? 'активен'
          : status === 'expired' ? 'истёк'
          : status === 'used' ? 'исчерпан'
          : 'выключен';
        tr.innerHTML = `
          <td>${p.code}</td>
          <td>${p.percent}%</td>
          <td>${p.uses}/${p.max_uses ?? '∞'}</td>
          <td><span class="badge ${status}">${statusLabel}</span></td>
          <td>${p.expires_at || '—'}</td>
        `;
        body.appendChild(tr);
      });
      if (!items.length) body.innerHTML = '<tr><td colspan="5" class="muted">Нет данных</td></tr>';
    }
    async function loadBonuses(){
      const res = await fetch('/admin/bonuses', {credentials:'include'});
      const data = await res.json();
      const body = document.querySelector('#bonus-table tbody');
      if (!body) return;
      if(!res.ok){ body.innerHTML = '<tr><td colspan="6" class="muted">Не удалось</td></tr>'; return; }
      const items = data.items || [];
      body.innerHTML = '';
      items.forEach(b => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${b.user_id}</td>
          <td>${b.stars} ⭐</td>
          <td>${b.status}</td>
          <td>${b.source || '—'}</td>
          <td>${b.expires_at || '—'}</td>
          <td>${b.created_at || '—'}</td>
        `;
        body.appendChild(tr);
      });
      if (!items.length) body.innerHTML = '<tr><td colspan="6" class="muted">Нет данных</td></tr>';
    }
    async function resetRaffle(){
      const res = await fetch('/admin/raffle/reset', {method:'POST', credentials:'include'});
      document.getElementById('raffle-status').textContent = res.ok ? 'Период сброшен' : 'Сброс не удался';
    }
    async function recalcRaffle(){
      const res = await fetch('/admin/raffle/recalc', {method:'POST', credentials:'include'});
      const data = await res.json().catch(() => ({}));
      document.getElementById('raffle-status').textContent = res.ok ? `Пересчёт OK (${data.recalc_at || ''})` : 'Пересчёт не удался';
    }
    async function loadRaffleSummary(){
      const res = await fetch('/admin/raffle/summary', {credentials:'include'});
      const data = await res.json();
      if(!res.ok){ document.getElementById('raffle-status').textContent = 'Сводка не получена'; return; }
      const win = data.winner ? `победитель ${data.winner.user_id} (${data.winner.total_stars} ⭐)` : 'победитель —';
      document.getElementById('raffle-status').textContent = `${data.period_start} → ${data.period_end} | участников ${data.total_participants} | звёзд ${data.total_stars} | ${win}`;
    }
    async function loadSettings(){
      const res = await fetch('/admin/settings', {credentials:'include'});
      if(!res.ok) return;
      const data = await res.json();
      document.getElementById('report_time').value = data.report_time || '';
      document.getElementById('ref_percent').value = data.referral_percent ?? '';
      document.getElementById('rate1').value = data.stars_rate_1 ?? '';
      document.getElementById('rate2').value = data.stars_rate_2 ?? '';
      document.getElementById('rate3').value = data.stars_rate_3 ?? '';
      document.getElementById('raffle_prize_title').value = data.raffle_prize_title ?? '';
      document.getElementById('raffle_prize_desc').value = data.raffle_prize_desc ?? '';
      document.getElementById('raffle_prize_image').value = data.raffle_prize_image ?? '';
      document.getElementById('banner_enabled').value = (data.banner_enabled ?? false).toString();
      document.getElementById('banner_title').value = data.banner_title ?? '';
      document.getElementById('banner_text').value = data.banner_text ?? '';
      document.getElementById('banner_url').value = data.banner_url ?? '';
      document.getElementById('banner_until').value = data.banner_until ?? '';
      document.getElementById('promo_text').value = data.promo_text ?? '';
    }
    async function saveSettings(){
      const payload = {
        report_time: document.getElementById('report_time').value.trim() || null,
        referral_percent: Number(document.getElementById('ref_percent').value || 0) || null,
        stars_rate_1: Number(document.getElementById('rate1').value || 0) || null,
        stars_rate_2: Number(document.getElementById('rate2').value || 0) || null,
        stars_rate_3: Number(document.getElementById('rate3').value || 0) || null,
        raffle_prize_title: document.getElementById('raffle_prize_title').value.trim() || null,
        raffle_prize_desc: document.getElementById('raffle_prize_desc').value.trim() || null,
        raffle_prize_image: document.getElementById('raffle_prize_image').value.trim() || null,
        banner_enabled: (document.getElementById('banner_enabled').value || '').trim().toLowerCase() === 'true',
        banner_title: document.getElementById('banner_title').value.trim() || null,
        banner_text: document.getElementById('banner_text').value.trim() || null,
        banner_url: document.getElementById('banner_url').value.trim() || null,
        banner_until: document.getElementById('banner_until').value.trim() || null,
        promo_text: document.getElementById('promo_text').value.trim() || null,
      };
      const res = await fetch('/admin/settings', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      document.getElementById('settings-status').textContent = res.ok ? 'Сохранено' : 'Ошибка сохранения';
    }
    async function createPromo(){
      const payload = {
        code: document.getElementById('promo_code').value.trim(),
        percent: Number(document.getElementById('promo_percent').value || 0),
        max_uses: Number(document.getElementById('promo_max').value || 0) || null,
        expires_at: document.getElementById('promo_exp').value.trim() || null,
        active: true
      };
      const res = await fetch('/admin/promo/create', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      const data = await res.json().catch(() => ({}));
      document.getElementById('promo-status').textContent = res.ok ? `OK: ${data.code || payload.code}` : 'Не удалось';
    }
    async function createBonus(){
      const payload = {
        stars: Number(document.getElementById('bonus_stars').value || 0),
        ttl_minutes: Number(document.getElementById('bonus_ttl').value || 0) || null,
        max_uses: Number(document.getElementById('bonus_max').value || 0) || null,
        source: document.getElementById('bonus_source').value.trim() || null,
      };
      const res = await fetch('/admin/bonus/claim', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      const data = await res.json().catch(() => ({}));
      document.getElementById('bonus-status').textContent = res.ok
        ? `Ссылка: ${data.link || ''}`
        : 'Не удалось';
    }
    async function bulkBonus(){
      const payload = {
        user_ids: document.getElementById('bonus_bulk_ids').value.trim(),
        stars: Number(document.getElementById('bonus_bulk_stars').value || 0),
        ttl_minutes: Number(document.getElementById('bonus_bulk_ttl').value || 0) || null,
        source: document.getElementById('bonus_bulk_source').value.trim() || null,
      };
      const res = await fetch('/admin/bonus/grant_bulk', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      const data = await res.json().catch(() => ({}));
      document.getElementById('bonus-bulk-status').textContent = res.ok
        ? `Создано: ${data.created || 0}`
        : 'Не удалось';
    }
  </script>
</body>
</html>
"""


