import puppeteer, { type BrowserWorker } from '@cloudflare/puppeteer';
import type { PublishPayload } from './template';

const PILOT_LOGO_URL = 'https://raw.githubusercontent.com/TeoSlayer/pilotprotocol/main/docs/media/pilot.png';

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Generate the HTML for a 1200x630 OG banner image.
 * Pixel-matched to the existing Pilot Protocol blog banner style:
 * - Dark background (#1a1a1a)
 * - Thin green top accent line
 * - Filled green pill with white text (top-left, category name)
 * - Bold white title, vertically centered
 * - Date in gray (bottom-left)
 * - Pilot Protocol logo + name (bottom-right)
 * - Optional right-side SVG decoration (subtle, low opacity)
 */
export function renderBannerHTML(post: PublishPayload, decorationSvg?: string): string {
  const title = escapeHtml(post.title);
  const category = escapeHtml(post.category.toUpperCase());
  const date = escapeHtml(post.date_full);
  const decoration = decorationSvg || '';

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    width: 1200px;
    height: 630px;
    background: #1a1a1a;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    overflow: hidden;
    position: relative;
  }
  .accent {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: #22c55e;
  }
  .content {
    padding: 0 64px;
    height: 100%;
    display: flex;
    flex-direction: column;
    position: relative;
    z-index: 1;
  }
  .pill {
    display: inline-block;
    background: rgba(34, 197, 94, 0.15);
    border: 1.5px solid rgba(34, 197, 94, 0.4);
    color: #22c55e;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 1.5px;
    padding: 7px 20px;
    border-radius: 20px;
    margin-top: 48px;
    align-self: flex-start;
  }
  .title-area {
    flex: 1;
    display: flex;
    align-items: center;
  }
  .title {
    color: #ffffff;
    font-size: 48px;
    font-weight: 900;
    line-height: 1.18;
    max-width: 780px;
    letter-spacing: -0.5px;
  }
  .footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 40px;
  }
  .date {
    color: #71717a;
    font-size: 16px;
    font-weight: 400;
  }
  .brand {
    color: #71717a;
    font-size: 16px;
    font-weight: 400;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .brand img {
    width: 28px;
    height: 28px;
    border-radius: 50%;
  }
  .decoration {
    position: absolute;
    right: 40px;
    top: 50%;
    transform: translateY(-50%);
    opacity: 0.12;
    z-index: 0;
  }
</style>
</head>
<body>
  <div class="accent"></div>${decoration ? `\n  <div class="decoration">${decoration}</div>` : ''}
  <div class="content">
    <div class="pill">${category}</div>
    <div class="title-area">
      <div class="title">${title}</div>
    </div>
    <div class="footer">
      <div class="date">${date}</div>
      <div class="brand">
        <img src="${PILOT_LOGO_URL}" alt="Pilot Protocol">
        Pilot Protocol
      </div>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Call Gemini to generate a thematic SVG decoration for the banner.
 * Returns undefined on failure (banner renders clean without decoration).
 */
export async function generateDecoration(
  post: PublishPayload,
  geminiApiKey: string,
): Promise<string | undefined> {
  const prompt = `Generate a minimal, abstract SVG illustration (no text, no labels) for a blog post banner about: "${post.title}" (category: ${post.category}). Requirements:
- Single color only: use stroke="#22c55e" and/or fill="#22c55e"
- Transparent background
- Simple: 5-12 elements max (lines, circles, paths, rects)
- Abstract/geometric, not literal
- ViewBox: "0 0 400 400"
- Return ONLY the raw <svg>...</svg> markup, nothing else`;

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${geminiApiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { maxOutputTokens: 1000 },
        }),
      },
    );

    if (res.ok) {
      const data = (await res.json()) as {
        candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      };
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
      if (text && text.includes('<svg') && text.includes('</svg>')) {
        const start = text.indexOf('<svg');
        const end = text.indexOf('</svg>') + 6;
        return text.slice(start, end);
      }
    } else {
      console.error('Gemini API error:', res.status, await res.text());
    }
  } catch (err) {
    console.error('Gemini decoration generation failed:', err);
  }

  return undefined;
}

/**
 * Render banner HTML to a PNG screenshot using Cloudflare Browser Rendering.
 * Returns base64-encoded image data.
 */
export async function renderBannerImage(
  browserBinding: BrowserWorker,
  html: string,
): Promise<string> {
  const browser = await puppeteer.launch(browserBinding);
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1200, height: 630 });
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const screenshot = await page.screenshot({ type: 'png' }) as Buffer;
    const bytes = new Uint8Array(screenshot);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } finally {
    await browser.close();
  }
}
