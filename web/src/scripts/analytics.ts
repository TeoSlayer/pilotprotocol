// Single delegated event surface for GA4. Add new tracked behaviors via
// data-* attributes on call sites; this module never needs to know about
// specific elements.
//
// Conventions:
//   data-track="<event_name>"      - GA4 event name fired on click (e.g. "cta_click")
//   data-track-target="..."        - string label (cta target, modal id, ...)
//   data-track-location="..."      - optional context (section, page area)
//   data-track-section="<name>"    - section_view + section_dwell via IO
//   data-track-copy="<command>"    - install_command_copy on user copy
//   data-track-read="<slug>"       - blog_post_read at 75% scroll
//   data-track-hover="<event>"     - fires once after dwell threshold
//   data-track-hover-threshold-ms  - dwell time in ms (default 1500)
//
// Outbound <a> links auto-fire `outbound_click` (host != site).
// Scroll depth auto-fires at 25 / 50 / 75 / 100 percent.
// Engagement: section_dwell on exit, page_active_time on pagehide.
// Friction: web_vital (LCP/CLS/TTFB), dead_click on non-actionable clicks.

declare global {
  interface Window {
    dataLayer?: unknown[];
    gtag?: (...args: unknown[]) => void;
    pilotTrack?: (event: string, params?: Record<string, string | number | undefined>) => void;
  }
}

type GtagParams = Record<string, string | number | undefined>;

const SITE_DOMAIN = 'pilotprotocol.network';

function isInternalHost(host: string): boolean {
  return host === SITE_DOMAIN || host.endsWith('.' + SITE_DOMAIN);
}

function track(event: string, params: GtagParams = {}): void {
  if (typeof window === 'undefined' || typeof window.gtag !== 'function') return;
  const clean: GtagParams = {};
  for (const k in params) {
    const v = params[k];
    if (v !== undefined && v !== null && v !== '') clean[k] = v;
  }
  window.gtag('event', event, clean);
}

window.pilotTrack = track;

// --- PostHog (heatmaps + session recordings, gated on key only) --------
const POSTHOG_KEY = (import.meta as { env?: Record<string, string | undefined> }).env
  ?.PUBLIC_POSTHOG_KEY;
const POSTHOG_HOST =
  (import.meta as { env?: Record<string, string | undefined> }).env?.PUBLIC_POSTHOG_HOST ||
  'https://us.i.posthog.com';

if (POSTHOG_KEY) {
  import('posthog-js')
    .then((mod) => {
      const ph = (mod as { default: typeof mod }).default || mod;
      (ph as unknown as { init: (k: string, opts: Record<string, unknown>) => void }).init(
        POSTHOG_KEY,
        {
          api_host: POSTHOG_HOST,
          person_profiles: 'never',
          capture_pageview: true,
          autocapture: true,
          persistence: 'localStorage',
          session_recording: {
            maskAllInputs: true,
            maskTextSelector: '[data-private]',
          },
        },
      );
    })
    .catch((err) => {
      // PostHog is additive; failure must not break GA4.
      console.warn('[analytics] posthog init failed', err);
    });
}

// --- Click delegation (incl. outbound, blog→docs handoff, dead_click) ---
document.addEventListener('click', (e) => {
  const path = ((e as Event).composedPath?.() ?? []) as EventTarget[];
  let trackEl: HTMLElement | null = null;
  let anchorEl: HTMLAnchorElement | null = null;
  let buttonEl: HTMLElement | null = null;
  for (const node of path) {
    if (!(node instanceof HTMLElement)) continue;
    if (!trackEl && node.dataset && node.dataset.track) trackEl = node;
    if (!anchorEl && node.tagName === 'A') anchorEl = node as HTMLAnchorElement;
    if (!buttonEl && (node.tagName === 'BUTTON' || node.getAttribute('role') === 'button')) {
      buttonEl = node;
    }
    if (trackEl && anchorEl) break;
  }

  if (trackEl && trackEl.dataset.track) {
    track(trackEl.dataset.track, {
      target: trackEl.dataset.trackTarget,
      location: trackEl.dataset.trackLocation,
    });
  }

  if (anchorEl && anchorEl.href) {
    try {
      const u = new URL(anchorEl.href, window.location.href);
      if (u.protocol.startsWith('http')) {
        const internal = u.host === window.location.host || isInternalHost(u.host);
        if (!internal) {
          track('outbound_click', { target: u.host, href: u.href });
        } else if (
          window.location.pathname.startsWith('/blog/') &&
          u.pathname.startsWith('/docs/')
        ) {
          track('external_doc_click', { target: u.pathname });
        }
      }
    } catch {
      // mailto:, tel:, javascript: etc - skip
    }
  }

  // Friction: dead_click. Click that hit no link, no button, no tracked element,
  // no form input. Best-effort signal of "user expected something to happen".
  if (!trackEl && !anchorEl && !buttonEl) {
    const t = e.target as HTMLElement | null;
    const tag = t?.tagName;
    if (
      t &&
      tag &&
      tag !== 'INPUT' &&
      tag !== 'TEXTAREA' &&
      tag !== 'SELECT' &&
      tag !== 'LABEL' &&
      tag !== 'HTML' &&
      tag !== 'BODY'
    ) {
      const section = t.closest<HTMLElement>('[data-track-section]')?.dataset.trackSection;
      track('dead_click', {
        location: section || window.location.pathname,
        target: tag.toLowerCase(),
      });
    }
  }
});

// --- Section visibility + dwell (single IO observer) -------------------
const sectionsSeen = new Set<string>();
const sectionEnterAt = new Map<string, number>();
if ('IntersectionObserver' in window) {
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        const el = entry.target as HTMLElement;
        const name = el.dataset.trackSection || el.id;
        if (!name) continue;
        if (entry.isIntersecting) {
          if (!sectionsSeen.has(name)) {
            sectionsSeen.add(name);
            track('section_view', { target: name });
          }
          sectionEnterAt.set(name, performance.now());
        } else if (sectionEnterAt.has(name)) {
          const dur = Math.round(performance.now() - sectionEnterAt.get(name)!);
          sectionEnterAt.delete(name);
          if (dur > 250) {
            track('section_dwell', { target: name, duration_ms: dur });
          }
        }
      }
    },
    { threshold: 0.5 },
  );
  document
    .querySelectorAll<HTMLElement>('[data-track-section]')
    .forEach((el) => observer.observe(el));
}

// --- Scroll depth milestones --------------------------------------------
const milestones = [25, 50, 75, 100];
const seenDepth = new Set<number>();
let scrollScheduled = false;

function checkScrollDepth(): void {
  scrollScheduled = false;
  const doc = document.documentElement;
  const max = doc.scrollHeight - window.innerHeight;
  if (max <= 0) return;
  const pct = Math.min(100, Math.round((window.scrollY / max) * 100));
  for (const m of milestones) {
    if (pct >= m && !seenDepth.has(m)) {
      seenDepth.add(m);
      track('scroll_depth', { value: m });
    }
  }
}

window.addEventListener(
  'scroll',
  () => {
    if (scrollScheduled) return;
    scrollScheduled = true;
    requestAnimationFrame(checkScrollDepth);
  },
  { passive: true },
);
requestAnimationFrame(checkScrollDepth);

// --- Copy-to-clipboard --------------------------------------------------
document.addEventListener('copy', () => {
  const sel = window.getSelection();
  if (!sel || sel.isCollapsed) return;
  const anchorNode = sel.anchorNode;
  const startEl =
    anchorNode instanceof Element ? anchorNode : anchorNode?.parentElement ?? null;
  const wrapper = startEl?.closest<HTMLElement>('[data-track-copy]');
  if (!wrapper) return;
  track('install_command_copy', { command: wrapper.dataset.trackCopy });
});

// --- Blog post read (75% through the article) --------------------------
document.querySelectorAll<HTMLElement>('[data-track-read]').forEach((el) => {
  let fired = false;
  const slug = el.dataset.trackRead;
  const onScroll = () => {
    if (fired) return;
    const r = el.getBoundingClientRect();
    if (r.height <= 0) return;
    const scrolledIntoEl = window.innerHeight - r.top;
    if (scrolledIntoEl >= r.height * 0.75) {
      fired = true;
      track('blog_post_read', { slug });
      window.removeEventListener('scroll', onScroll);
    }
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
});

// --- Hover dwell --------------------------------------------------------
document.querySelectorAll<HTMLElement>('[data-track-hover]').forEach((el) => {
  const eventName = el.dataset.trackHover;
  if (!eventName) return;
  const threshold = Number(el.dataset.trackHoverThresholdMs) || 1500;
  let timer: number | null = null;
  let fired = false;
  el.addEventListener('mouseenter', () => {
    if (fired || timer !== null) return;
    timer = window.setTimeout(() => {
      fired = true;
      track(eventName, { target: el.dataset.trackTarget });
      timer = null;
    }, threshold);
  });
  el.addEventListener('mouseleave', () => {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
  });
});

// --- Engagement: page active time ---------------------------------------
let activeStart = performance.now();
let activeAccumulated = 0;
let pageActive = !document.hidden;

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (pageActive) activeAccumulated += performance.now() - activeStart;
    pageActive = false;
  } else {
    activeStart = performance.now();
    pageActive = true;
  }
});

// --- Friction: Web Vitals (LCP, CLS, TTFB) -----------------------------
let latestLCP = 0;
let cls = 0;

if ('PerformanceObserver' in window) {
  try {
    const lcpObs = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        latestLCP = entry.startTime;
      }
    });
    lcpObs.observe({ type: 'largest-contentful-paint', buffered: true });
    // Stop observing once the user interacts - LCP after that isn't meaningful
    const stop = () => lcpObs.disconnect();
    addEventListener('keydown', stop, { once: true, capture: true });
    addEventListener('click', stop, { once: true, capture: true });
  } catch {}

  try {
    const clsObs = new PerformanceObserver((list) => {
      for (const entry of list.getEntries() as PerformanceEntry[]) {
        const e = entry as unknown as { value: number; hadRecentInput: boolean };
        if (!e.hadRecentInput) cls += e.value;
      }
    });
    clsObs.observe({ type: 'layout-shift', buffered: true });
  } catch {}
}

try {
  const nav = performance.getEntriesByType('navigation')[0] as
    | PerformanceNavigationTiming
    | undefined;
  if (nav && nav.responseStart > 0) {
    track('web_vital', { name: 'TTFB', value: Math.round(nav.responseStart) });
  }
} catch {}

// --- Pagehide flush: page_active_time, LCP, CLS, residual section_dwell ---
window.addEventListener('pagehide', () => {
  if (pageActive) activeAccumulated += performance.now() - activeStart;
  pageActive = false;

  if (activeAccumulated > 1000) {
    track('page_active_time', { duration_ms: Math.round(activeAccumulated) });
  }
  if (latestLCP > 0) {
    track('web_vital', { name: 'LCP', value: Math.round(latestLCP) });
  }
  // CLS is x1000 to keep an integer (GA4 metrics work better as ints)
  track('web_vital', { name: 'CLS', value: Math.round(cls * 1000) });

  // Flush any sections still in viewport
  const now = performance.now();
  for (const [name, enterAt] of sectionEnterAt) {
    const dur = Math.round(now - enterAt);
    if (dur > 250) track('section_dwell', { target: name, duration_ms: dur });
  }
});

export {};
