'use strict';

const byId = id => document.getElementById(id);
const token = new URLSearchParams(location.hash.slice(1)).get('token');
if (token) history.replaceState(null, '', location.pathname);

let activePlan = null;
let identified = null;
let mascotAvailable = false;
let planning = false;
let printing = false;

function element(tag, value, className) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = value;
  if (className) node.className = className;
  return node;
}

function banner(error) {
  byId('error').textContent = error ? error.message : '';
  byId('error').hidden = !error;
  if (error) byId('error').scrollIntoView({block: 'nearest'});
}

async function api(action, body = {}, download = false) {
  if (!token) throw new Error('Open the session URL printed by the GUI command.');
  const response = await fetch('/api/' + action, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Goblin-Token': token},
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error((await response.json()).error);
  return download ? response.blob() : response.json();
}

function form(id, run) {
  byId(id).addEventListener('submit', async event => {
    event.preventDefault();
    const button = event.submitter || byId(id).querySelector('button');
    if (button.disabled) return;
    button.disabled = true;
    banner();
    try { await run(); }
    catch (error) { banner(error); }
    finally {
      button.disabled = false;
      confirmState();
    }
  });
}

function ports() {
  return byId('ports').value.split(',').map(part => Number(part.trim()));
}

function appendRow(parent, values) {
  const row = element('tr');
  for (const value of values) {
    const cell = element('td');
    if (value instanceof Node) cell.append(value);
    else cell.textContent = value;
    row.append(cell);
  }
  parent.append(row);
}

form('discover-form', async () => {
  const status = byId('discover-status');
  status.textContent = 'Discovery running…';
  try {
    const job = await api('discover', {cidr: byId('cidr').value, ports: ports()});
    let result;
    do {
      await new Promise(resolve => setTimeout(resolve, 350));
      result = await api('poll', job);
    } while (result.status === 'running');
    byId('hosts').replaceChildren();
    byId('addresses').replaceChildren();
    for (const host of result.hosts) {
      const option = element('option');
      option.value = host.ip;
      byId('addresses').append(option);
      const pick = element('input');
      pick.type = 'checkbox';
      pick.value = host.ip;
      pick.setAttribute('aria-label', 'Include ' + host.ip + ' in baseline');
      const address = element('button', host.ip, 'address');
      address.type = 'button';
      address.addEventListener('click', () => {
        byId('target').value = host.ip;
        targetChanged();
        byId('identify').scrollIntoView();
        byId('identify-form').requestSubmit();
      });
      appendRow(byId('hosts'), [pick, address, host.open_ports.join(', '), host.kind, host.model || '—']);
    }
    status.textContent = result.hosts.length
      ? result.hosts.length + ' hosts with open ports.' : 'No open ports found.';
  } catch (error) {
    status.textContent = 'Discovery failed.';
    throw error;
  }
});

form('identify-form', async () => {
  const target = byId('target').value;
  const device = await api('identify', {target});
  if (target !== byId('target').value) return;
  identified = device.ip;
  const facts = element('dl');
  for (const [label, value] of Object.entries({
    Address: device.ip, Type: device.kind, Model: device.model,
    Firmware: device.firmware, Serial: device.serial,
    Services: device.services.join(', '), Languages: device.languages.join(', '),
    TLS: Object.entries(device.tls || {}).map(([port, tls]) =>
      port + ' ' + (tls.version || 'no modern handshake') + ' (legacy ' + tls.legacy + ')'
    ).join(', ')
  })) {
    facts.append(element('dt', label), element('dd', value || '—'));
  }
  const list = element('ul');
  for (const finding of device.findings) {
    const item = element('li');
    item.append(element('span', finding.severity.toUpperCase(), 'chip ' + finding.severity),
                element('span', finding.basis, 'chip'),
                document.createTextNode(' ' + finding.title + ' · ' + finding.detail));
    list.append(item);
  }
  byId('device').replaceChildren(facts, list);
});

function confirmState() {
  byId('submit-print').disabled = printing || !activePlan || !byId('authorized').checked
    || byId('typed').value !== activePlan.ip;
}

function invalidatePlan() {
  activePlan = null;
  byId('preview-result').hidden = true;
  byId('print-target').textContent = 'Create a preview to select a print destination.';
  byId('authorized').checked = false;
  byId('typed').value = '';
  byId('print-status').textContent = '';
  confirmState();
}

function targetChanged() {
  identified = null;
  byId('device').replaceChildren();
  invalidatePlan();
}

byId('target').addEventListener('input', targetChanged);
byId('preview-form').addEventListener('input', invalidatePlan);
byId('authorized').addEventListener('change', confirmState);
byId('typed').addEventListener('input', confirmState);

function previewInput() {
  const port = byId('port').value;
  return {target: byId('target').value, format: byId('format').value, via: byId('via').value,
          paper: byId('paper').value, native_qr: !byId('raster').checked,
          port: port ? Number(port) : null};
}

form('preview-form', async () => {
  if (!byId('identify-form').reportValidity() || planning) return;
  planning = true;
  invalidatePlan();
  const input = previewInput();
  let plan;
  try { plan = await api('plan', input); }
  finally { planning = false; }
  if (JSON.stringify(input) !== JSON.stringify(previewInput())) return;
  activePlan = plan;
  // Segno emits an HTML-embeddable SVG without an XML namespace declaration.
  const qr = new DOMParser().parseFromString(plan.qr, 'text/html').querySelector('svg');
  qr.setAttribute('role', 'img');
  qr.setAttribute('aria-label', 'QR code for the remediation guide');
  const logo = element('span', '👹', 'mascot');
  logo.setAttribute('aria-hidden', 'true');
  if (mascotAvailable) {
    const image = element('img');
    image.src = '/mascot.png';
    image.alt = '';
    logo.replaceChildren(image);
  }
  const title = element('div', undefined, 'sheet-title');
  title.append(logo, element('h3', plan.headline));
  byId('sheet').replaceChildren(
    title, element('p', plan.lines.join('\n')), element('h4', plan.facts[0]),
    element('p', plan.facts.slice(1).join('\n')), qr, element('p', plan.url),
    element('p', plan.footer.join('\n'))
  );
  byId('sheet').className = plan.format === 'escpos' ? 'receipt paper-' + input.paper : '';
  byId('plan-route').textContent = plan.ip + ':' + plan.port + ' · '
    + plan.protocol.toUpperCase() + ' · ' + plan.format.toUpperCase();
  byId('preview-result').hidden = false;
  byId('print-target').textContent = 'Print destination ' + byId('plan-route').textContent;
});

byId('downloads').addEventListener('click', async event => {
  const fmt = event.target.dataset.format;
  if (!activePlan || !fmt) return;
  banner();
  try {
    const blob = await api('download', {plan_id: activePlan.plan_id, format: fmt}, true);
    const link = element('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'goblin-notice.' + (fmt === 'escpos' ? 'bin' : fmt);
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  } catch (error) { banner(error); }
});

form('print-form', async () => {
  if (!activePlan || printing) return;
  printing = true;
  const status = byId('print-status');
  status.textContent = 'Submitting…';
  try {
    const job = await api('print', {plan_id: activePlan.plan_id, typed_address: byId('typed').value,
                                    authorized: byId('authorized').checked});
    let result;
    do {
      await new Promise(resolve => setTimeout(resolve, 350));
      result = await api('print-status', job);
      if (result.message) status.textContent = result.message;
    } while (!result.done);
    byId('typed').value = '';
    byId('authorized').checked = false;
  } catch (error) {
    status.textContent = error.message;
    throw error;
  } finally { printing = false; }
});

async function refreshBaselines(selected) {
  const report = await api('baselines');
  const select = byId('baselines');
  select.replaceChildren(element('option', 'Choose a baseline'));
  select.options[0].value = '';
  for (const baseline of report.baselines) {
    const option = element('option', (baseline.label || 'Baseline') + ' · '
                           + new Date(baseline.created).toLocaleString());
    option.value = baseline.id;
    select.append(option);
  }
  if (selected) select.value = selected;
}

form('baseline-form', async () => {
  const targets = Array.from(byId('hosts').querySelectorAll('input:checked'), node => node.value);
  if (!targets.length && identified) targets.push(identified);
  const allowed = byId('baseline-allow').value.trim();
  const allow = allowed ? allowed.split(',').map(part => Number(part.trim())) : [];
  const saved = await api('baseline', {targets, ports: ports(), allow,
                                       label: byId('baseline-label').value});
  await refreshBaselines(saved.id);
  byId('verify-result').textContent = 'Baseline saved.';
});

form('verify-form', async () => {
  const file = byId('reference').files[0];
  let reference = null;
  if (file) {
    if (file.size > 65536) throw new Error('Reference file exceeds 64 KiB.');
    reference = JSON.parse(await file.text());
    if (!reference || typeof reference !== 'object' || Array.isArray(reference)) {
      throw new Error('Choose a reference snapshot JSON file.');
    }
  }
  const report = await api('verify', {id: byId('baselines').value, reference,
                                     printer_online: byId('printer-online').checked});
  const list = element('ul');
  for (const [ip, results] of Object.entries(report.results)) {
    for (const [port, result] of Object.entries(results)) {
      list.append(element('li', ip + ' · TCP ' + port + ' · expect ' + result.policy
                          + ' · ' + result.classification + ' (' + result.before + ' → '
                          + result.after + ')'));
    }
    list.append(element('li', 'Liveness for ' + ip + ' · '
                        + (report.liveness[ip].join(', ') || 'none')));
  }
  const pass = report.verdict === 'PASS';
  byId('verify-result').replaceChildren(
    element('strong', report.verdict, pass ? 'chip pass' : 'chip high'),
    element('p', report.explanation), element('p', report.note), list
  );
  if (report.vantage.behind_wsl_nat) {
    byId('verify-result').append(element('p',
      "Probed from inside WSL. The network sees this PC's Windows address."));
  }
  if (report.liveness_note) byId('verify-result').append(element('p', report.liveness_note));
});

const mascot = new Image();
mascot.alt = '';
mascot.addEventListener('load', () => {
  mascotAvailable = true;
  document.querySelector('header .mascot').replaceChildren(mascot);
});
mascot.src = '/mascot.png';
refreshBaselines().catch(banner);
