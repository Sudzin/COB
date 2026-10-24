import { STATUS_LABEL, STATUS_ORDER } from '../constants.js';
import { esc } from '../utils/esc.js';

/**
 * Панель фильтров: чипы статусов, выпадающие списки по полям, поиск по тексту.
 * Значения IP / пользователь / служба / узел / файл подтягиваются из самих логов.
 *
 * @param {HTMLElement} root     контейнер, куда рисуется панель
 * @param {Array} fields         поля фильтра (см. filterFields.js)
 * @param {{onChange: Function, onExport: Function}} handlers
 */
export function createFilterBar(root, fields, { onChange, onExport }) {
  const sel = {};
  const statuses = new Set();
  let query = '';
  let source = [];
  fields.forEach(f => { sel[f.key] = new Set(); });

  let html = '<div><span class="fbar-label">Статус операции</span><div class="chips"></div></div><div class="fbar-grid">';
  fields.forEach(f => {
    html += '<div class="ff" data-key="' + f.key + '"><span class="fbar-label">' + f.label + '</span>' +
      '<div class="fsel"><button type="button" class="ctl fsel-btn"><span class="v">Все</span><span class="caret">▾</span></button>' +
      '<div class="fsel-pop"><input type="text" class="ctl fsel-search" placeholder="Найти значение…">' +
      '<div class="fsel-list"></div>' +
      '<div class="fsel-foot"><button type="button" class="btn-ghost" data-act="clear">Очистить</button></div>' +
      '</div></div></div>';
  });
  html += '<div class="ff ff-search"><span class="fbar-label">Поиск по тексту строки</span>' +
    '<input type="text" class="ctl q" style="width:100%;" placeholder="Любая часть строки: IP, пользователь, служба, порт…"></div></div>' +
    '<div class="fbar-foot"><span class="fcount"></span><div class="fbar-actions">' +
    '<button type="button" class="btn-ghost" data-act="reset">Сбросить фильтры</button>' +
    '<button type="button" class="btn-action btn-sm" data-act="export">Экспорт отчёта в PDF</button></div></div>';
  root.classList.add('fbar');
  root.innerHTML = html;

  const chipsEl = root.querySelector('.chips');
  const countEl = root.querySelector('.fcount');
  const qEl = root.querySelector('.q');

  function ffEl(key) {
    return root.querySelector('.ff[data-key="' + key + '"]');
  }

  function closeAll() {
    root.querySelectorAll('.fsel.open').forEach(b => b.classList.remove('open'));
  }

  function updateLabel(f) {
    const s = sel[f.key];
    const ff = ffEl(f.key);
    ff.querySelector('.fsel-btn .v').textContent =
      s.size === 0 ? 'Все' : (s.size === 1 ? Array.from(s)[0] : 'Выбрано: ' + s.size);
    ff.querySelector('.fsel').classList.toggle('active', s.size > 0);
  }

  function refreshChips() {
    const cnt = {};
    source.forEach(r => { cnt[r.opStatus] = (cnt[r.opStatus] || 0) + 1; });
    Array.from(statuses).forEach(s => { if (!cnt[s]) statuses.delete(s); });

    let h = '<button type="button" class="chip' + (statuses.size === 0 ? ' on' : '') + '" data-st="*">Все <span class="cnt">' + source.length + '</span></button>';
    STATUS_ORDER.forEach(s => {
      if (cnt[s]) {
        h += '<button type="button" class="chip' + (statuses.has(s) ? ' on' : '') + '" data-st="' + s + '">' +
          STATUS_LABEL[s] + ' <span class="cnt">' + cnt[s] + '</span></button>';
      }
    });
    chipsEl.innerHTML = h;
  }

  function refreshFields() {
    fields.forEach(f => {
      const t = {};
      source.forEach(r => {
        const v = f.get(r);
        if (v && v !== '—') t[v] = (t[v] || 0) + 1;
      });
      const keys = Object.keys(t);
      Array.from(sel[f.key]).forEach(v => { if (!t[v]) sel[f.key].delete(v); });
      keys.sort((a, b) => t[b] - t[a] || a.localeCompare(b, undefined, { numeric: true }));

      const ff = ffEl(f.key);
      ff.hidden = !!f.hideSingle && keys.length < 2;
      ff.querySelector('.fsel-list').innerHTML = keys.length ? keys.map(k =>
        '<label class="fsel-opt"><input type="checkbox" data-v="' + esc(k) + '"' + (sel[f.key].has(k) ? ' checked' : '') + '>' +
        '<span class="ov">' + esc(k) + '</span><span class="n">' + t[k] + '</span></label>'
      ).join('') : '<div class="fsel-empty">Нет значений</div>';
      ff.querySelector('.fsel-search').value = '';
      updateLabel(f);
    });
  }

  function reset(silent) {
    statuses.clear();
    fields.forEach(f => sel[f.key].clear());
    query = '';
    qEl.value = '';
    refreshChips();
    refreshFields();
    if (!silent) onChange();
  }

  root.addEventListener('click', e => {
    const chip = e.target.closest('.chip');
    if (chip) {
      const st = chip.getAttribute('data-st');
      if (st === '*') statuses.clear();
      else if (statuses.has(st)) statuses.delete(st);
      else statuses.add(st);
      refreshChips();
      onChange();
      return;
    }

    const btn = e.target.closest('.fsel-btn');
    if (btn) {
      const box = btn.closest('.fsel');
      const wasOpen = box.classList.contains('open');
      closeAll();
      if (!wasOpen) {
        box.classList.add('open');
        box.querySelector('.fsel-search').focus();
      }
      return;
    }

    const act = e.target.closest('[data-act]');
    if (act) {
      const what = act.getAttribute('data-act');
      if (what === 'reset') {
        reset(false);
      } else if (what === 'export') {
        onExport();
      } else {
        const key = act.closest('.ff').getAttribute('data-key');
        sel[key].clear();
        refreshFields();
        onChange();
      }
      return;
    }

    if (!e.target.closest('.fsel')) closeAll();
  });

  root.addEventListener('change', e => {
    const cb = e.target;
    if (cb.type !== 'checkbox') return;
    const key = cb.closest('.ff').getAttribute('data-key');
    const v = cb.getAttribute('data-v');
    if (cb.checked) sel[key].add(v);
    else sel[key].delete(v);
    fields.forEach(f => { if (f.key === key) updateLabel(f); });
    onChange();
  });

  root.addEventListener('input', e => {
    const t = e.target;
    if (t.classList.contains('q')) {
      query = t.value.toLowerCase().trim();
      onChange();
    } else if (t.classList.contains('fsel-search')) {
      const needle = t.value.toLowerCase().trim();
      t.closest('.fsel-pop').querySelectorAll('.fsel-opt').forEach(o => {
        o.style.display = o.querySelector('.ov').textContent.toLowerCase().indexOf(needle) >= 0 ? '' : 'none';
      });
    }
  });

  document.addEventListener('click', e => { if (!root.contains(e.target)) closeAll(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeAll(); });

  return {
    setSource(rows) {
      source = rows;
      refreshChips();
      refreshFields();
    },
    reset,
    setCount(shown, total) {
      countEl.innerHTML = 'Найдено: <b>' + shown + '</b> из ' + total + ' записей';
    },
    match(r) {
      if (statuses.size && !statuses.has(r.opStatus)) return false;
      for (let i = 0; i < fields.length; i++) {
        const s = sel[fields[i].key];
        if (s.size && !s.has(fields[i].get(r))) return false;
      }
      if (query && (r.fileName + ' ' + r.raw).toLowerCase().indexOf(query) < 0) return false;
      return true;
    }
  };
}
