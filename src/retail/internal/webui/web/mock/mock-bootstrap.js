/**
 * Design-QA bootstrap. Installs the local fixture API, marks the page as mock,
 * then loads the production application module unmodified. No network request
 * leaves this origin and no token is required.
 */
import { readMockConfig, installMockApi } from './mock-api.js';

const config = readMockConfig();

// A placeholder token keeps the production auth gate closed during design QA.
try {
  sessionStorage.setItem('gedefense.retail.token', 'mock-preview-token');
  // The Access Gate has its own session. QA skips the login mask by default;
  // ?gateLogin=1 keeps it visible to screenshot the authentication panel.
  if (config.gateLogin) sessionStorage.removeItem('gedefense.retail.gateToken');
  else sessionStorage.setItem('gedefense.retail.gateToken', 'gst_dummy_mock_session');
} catch {
  /* storage unavailable: app still boots because fetch is mocked */
}

installMockApi(config);
markMockChrome(config);

// Same render code as production: only the data source is swapped.
await import('/js/app.js');


function markMockChrome(mockConfig) {
  document.title = `GeDefense Retail — Design-QA (Mock · ${mockConfig.state})`;
  document.documentElement.dataset.mockState = mockConfig.state;

  const banner = document.createElement('div');
  banner.className = 'mock-banner';
  banner.setAttribute('role', 'status');

  const title = document.createElement('strong');
  title.textContent = 'Design-QA · Mock-Daten';
  const note = document.createElement('span');
  note.textContent = 'Keine echte Sicherheitslage. Fixtures aus web/mock/fixtures.';
  banner.append(title, note);

  const scenarios = document.createElement('div');
  scenarios.className = 'mock-banner__scenarios';
  const options = [
    ['normal', 'Normal'],
    ['empty', 'Leer'],
    ['error', 'Fehler'],
    ['offline', 'Offline'],
    ['partial', 'Teil'],
  ];
  for (const [state, label] of options) {
    const link = document.createElement('a');
    const params = new URLSearchParams();
    params.set('state', state);
    if (mockConfig.delay !== 120) params.set('delay', String(mockConfig.delay));
    link.href = `${location.pathname}?${params.toString()}${location.hash || '#/overview'}`;
    link.textContent = label;
    if (state === mockConfig.state) link.setAttribute('aria-current', 'true');
    scenarios.append(link);
  }
  banner.append(scenarios);
  document.body.append(banner);
}
