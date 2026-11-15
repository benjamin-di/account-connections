(() => {
  const root = document.getElementById('connection-content');
  if (!root) return;
  const notice = document.getElementById('connection-notice');
  const originals = new WeakMap();
  let pending = false, active = null;
  const dialog = document.createElement('dialog');
  dialog.id = 'sharing-dialog';
  const close = document.createElement('button');
  close.type = 'button'; close.className = 'dialog-close'; close.textContent = 'Close';
  dialog.append(close); document.body.append(dialog);
  const values = form => JSON.stringify(Array.from(new FormData(form).entries()));
  const caps = form => Array.from(form.querySelectorAll('[name=capability]'))
    .filter(input => input.type === 'hidden' || input.checked)
    .map(input => input.dataset.label || input.value);
  function update(form) {
    const picker = form.querySelector('select[name=recipient]');
    const who = picker ? (picker.value ? picker.selectedOptions[0].textContent : '') :
      form.querySelector('[data-recipient-label]')?.dataset.recipientLabel;
    const names = caps(form).join(', ') || 'no permissions';
    form.querySelector('.share-summary').textContent =
      `Share ${form.dataset.account} with ${who || 'the person you choose'}: ${names}.`;
    const save = form.querySelector('[data-save]');
    const changed = values(form) !== originals.get(form);
    if (save) {
      save.disabled = pending || !!form.dataset.blocked || !who ||
        (form.dataset.edit === 'true' && !changed && form.dataset.renew !== 'true');
      save.textContent = form.dataset.edit === 'true' ? `Save access for ${who}` :
        (who ? `Share with ${who}` : 'Share access');
    }
    const reselection = form.querySelector('[data-reselection]');
    if (reselection) reselection.hidden = !changed && form.dataset.renew !== 'true';
  }
  function init() {
    root.querySelectorAll('.share-form').forEach(form => {
      originals.set(form, values(form));
      if (form.querySelector('[data-form-error]').textContent) form.dataset.blocked = 'true';
      form.querySelector('[data-refresh-people]')?.removeAttribute('hidden');
      update(form);
    });
  }
  function announce(message) { notice.textContent = message; notice.hidden = false; }
  function dismiss(force = false) {
    if (!active) return true;
    if (pending && !force) return false;
    const form = dialog.querySelector('form');
    if (!force && values(form) !== originals.get(form) &&
        !window.confirm('Discard your unsaved sharing changes?')) return false;
    if (!force) { form.reset(); update(form); }
    const current = active; active = null;
    current.details.append(current.content); dialog.close();
    current.summary.focus(); return true;
  }
  close.addEventListener('click', () => dismiss());
  dialog.addEventListener('cancel', event => { event.preventDefault(); dismiss(); });
  document.addEventListener('input', event => {
    const form = event.target.closest('.share-form');
    if (form) update(form);
  });
  document.addEventListener('change', event => {
    const form = event.target.closest('.share-form');
    if (form) update(form);
  });
  function error(form, message, blocked = false, signin = false, source = 'write') {
    const target = form.querySelector('[data-form-error]') || notice;
    if (source === 'people' && target.textContent && target.dataset.errorSource !== 'people') return;
    target.dataset.errorSource = source;
    target.textContent = message; target.hidden = false;
    if (blocked || signin) {
      const link = document.createElement('a');
      link.href = signin ? root.dataset.loginUrl : location.pathname;
      link.textContent = signin ? 'Sign in to Connections' : 'Refresh details before retrying';
      target.append(' ', link);
    }
    if (blocked) {
      form.dataset.blocked = 'true';
      form.querySelectorAll('button[type=submit]').forEach(button => { button.disabled = true; });
    }
    target.tabIndex = -1; target.focus();
  }
  document.addEventListener('click', async event => {
    const summary = event.target.closest('.sharing > summary');
    if (summary && root.contains(summary) && typeof dialog.showModal === 'function') {
      event.preventDefault();
      if (!dismiss()) return;
      const details = summary.parentElement, content = details.querySelector('.share-content');
      active = {details, summary, content}; dialog.append(content);
      dialog.setAttribute('aria-labelledby', content.querySelector('h3').id);
      dialog.showModal();
      (content.querySelector('select') || content.querySelector('input[type=checkbox]') || close).focus();
      return;
    }
    const copy = event.target.closest('[data-copy-link]');
    if (copy) {
      const link = copy.closest('.people-help')?.querySelector('[data-setup-link]');
      const url = link ? link.href : location.origin + location.pathname;
      try { await navigator.clipboard.writeText(url); copy.textContent = 'Link copied'; }
      catch (_) { announce(`Copy this app page link: ${url}`); }
      return;
    }
    const refresh = event.target.closest('[data-refresh-people]');
    if (!refresh) return;
    event.preventDefault();
    if (pending) return;
    const form = refresh.closest('form'), picker = form.querySelector('select');
    refresh.disabled = true;
    try {
      const response = await fetch(location.pathname, {cache:'no-store', redirect:'manual'});
      if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) throw new Error();
      const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = doc.getElementById(form.id);
      if (!next) throw new Error();
      const selected = picker.value;
      picker.replaceChildren(...Array.from(next.querySelector('select').childNodes));
      picker.value = selected;
      if (!picker.value) picker.value = '';
      const feedback = next.querySelector('[data-people-feedback]');
      const lookupFailed = feedback.dataset.lookupFailed === 'true';
      form.querySelector('[data-people-feedback]').replaceWith(feedback);
      const priorError = form.querySelector('[data-form-error]');
      if (priorError.dataset.errorSource === 'people') {
        priorError.textContent = ''; delete priorError.dataset.errorSource;
      }
      update(form);
      announce('People list refreshed. ' + (lookupFailed ? 'Some people couldn’t load. Try again. ' : '') +
        'Your permissions have been kept.');
    } catch (_) { error(form, 'People couldn’t load. Try again.', false, false, 'people'); }
    finally { refresh.disabled = pending || !!form.dataset.blocked; }
  });
  const identity = doc => doc.getElementById('connection-identity')?.outerHTML || '';
  document.addEventListener('submit', async event => {
    const form = event.target.closest('form[data-management]');
    if (!form || event.submitter?.hasAttribute('data-refresh-people')) return;
    event.preventDefault();
    if (pending || form.dataset.blocked) return;
    const button = event.submitter;
    const action = button?.getAttribute('formaction') || form.getAttribute('action');
    const payload = new URLSearchParams(new FormData(form));
    const namespace = payload.get('namespace');
    const sharing = action.endsWith('/share'), revoking = action.endsWith('/revoke');
    const who = form.querySelector('select')?.selectedOptions[0]?.textContent ||
      form.querySelector('[data-recipient-label]')?.dataset.recipientLabel || '';
    const editing = form.dataset.edit === 'true';
    pending = true;
    const controls = Array.from(form.querySelectorAll('input,select,button'));
    const disabled = controls.map(control => control.disabled);
    controls.forEach(control => { control.disabled = true; });
    try {
      const response = await fetch(action, {
        method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:payload, cache:'no-store'
      });
      const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
      if (!response.ok) {
        const message = doc.querySelector('[role=alert]')?.textContent ||
          (response.status === 401 ? 'Your sign-in has ended. Nothing was changed.' : 'The request was refused.');
        controls.forEach((control, i) => { control.disabled = disabled[i]; });
        error(form, message, response.status === 409 || response.status === 401 || response.status === 403,
          response.status === 401);
        return;
      }
      const next = doc.getElementById('connection-content');
      if (!next || identity(doc) !== identity(document)) throw new Error();
      dismiss(true);
      root.replaceChildren(...Array.from(next.childNodes)); pending = false; init();
      announce(sharing ? `${who} can now choose ${namespace}.` +
        (editing ? ' Permissions changed; they need to choose the account again.' : '') :
        revoking ? `Stopped sharing ${namespace} with ${who}. Your own connection is unchanged.` :
        action.endsWith('/leave') ? 'Access removed. The owner must share again before you can use this account.' :
        'Account selection updated.');
      root.querySelectorAll('article[data-namespace]').forEach(article => {
        if (article.dataset.namespace === namespace) article.focus();
      });
    } catch (_) {
      controls.forEach((control, i) => { control.disabled = disabled[i]; });
      error(form, 'The result is unknown. Refresh details to check before trying again.', true);
    } finally {
      pending = false;
      if (form.isConnected && form.matches('.share-form')) update(form);
    }
  });
  init();
})();
