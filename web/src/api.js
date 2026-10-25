// Vigil dashboard API client.

const BASE = '';

async function json(res) {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function listScans() {
  return json(await fetch(`${BASE}/api/scans`));
}

export async function createScan(req) {
  return json(await fetch(`${BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  }));
}

export async function getScan(id) {
  return json(await fetch(`${BASE}/api/scans/${encodeURIComponent(id)}`));
}

export async function getReport(id) {
  return json(await fetch(`${BASE}/api/scans/${encodeURIComponent(id)}/report?format=json`));
}

export function reportURL(id, format) {
  return `${BASE}/api/scans/${encodeURIComponent(id)}/report?format=${encodeURIComponent(format)}`;
}

// SSE stream for real-time scan events.
// Calls onFinding({finding}), onProgress({phase, tested, total, findings}), onDone().
export function subscribeScan(id, { onFinding, onProgress, onDone, onError }) {
  const url = `${BASE}/api/scans/${encodeURIComponent(id)}/events`;
  const es = new EventSource(url);

  es.addEventListener('finding', (e) => {
    try { onFinding?.(JSON.parse(e.data)); } catch {}
  });
  es.addEventListener('progress', (e) => {
    try { onProgress?.(JSON.parse(e.data)); } catch {}
  });
  es.addEventListener('done', () => {
    onDone?.();
    es.close();
  });
  es.addEventListener('error', () => {
    // SSE auto-reconnects; if server closed, treat as done
    if (es.readyState === EventSource.CLOSED) {
      onDone?.();
    }
  });
  es.onerror = () => {
    onError?.();
  };

  return () => es.close();
}
