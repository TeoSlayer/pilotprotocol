const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const logoBase64 = fs.readFileSync(path.join(__dirname, '../../docs/media/pilot.png')).toString('base64');
const logoDataUri = `data:image/png;base64,${logoBase64}`;

const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;width:1200px;height:630px;overflow:hidden;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">

  <!-- Green accent bar top -->
  <div style="position:absolute;top:0;left:0;right:0;height:4px;background:#22c55e;"></div>

  <!-- Dot grid -->
  <div style="position:absolute;inset:0;background-image:radial-gradient(circle,rgba(255,255,255,0.03) 1px,transparent 1px);background-size:24px 24px;"></div>

  <!-- Layout: two columns -->
  <div style="position:relative;display:flex;height:100%;box-sizing:border-box;">

    <!-- Left column: title + badges -->
    <div style="flex:1;padding:48px 48px 100px 64px;display:flex;flex-direction:column;">

      <!-- Category badge -->
      <div style="display:inline-block;border:1.5px solid #22c55e;color:#22c55e;padding:6px 18px;border-radius:20px;font-size:15px;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;width:fit-content;margin-bottom:40px;">Standards</div>

      <!-- Title -->
      <h1 style="color:#ffffff;font-size:46px;font-weight:800;line-height:1.15;margin:0 0 36px 0;letter-spacing:-0.01em;">Pilot Protocol<br>IETF Internet-Drafts<br>Published</h1>

      <!-- Draft ID badge -->
      <div style="display:inline-block;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.25);color:#22c55e;padding:10px 22px;border-radius:8px;font-size:17px;font-weight:700;font-family:'SF Mono',Menlo,Consolas,monospace;width:fit-content;margin-bottom:28px;">draft-teodor-pilot-protocol-00</div>

      <!-- Subtitle -->
      <p style="color:#6b7280;font-size:15px;margin:0;line-height:1.6;max-width:400px;">Problem statement + full wire specification.<br>Submitted to the IETF independent stream.</p>

    </div>

    <!-- Right column: IETF draft excerpt -->
    <div style="width:520px;padding:40px 48px 40px 0;display:flex;align-items:center;">
      <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:28px 28px;width:100%;font-family:'SF Mono',Menlo,Consolas,monospace;font-size:13px;line-height:1.85;overflow:hidden;">
        <div style="color:#6b7280;margin-bottom:4px;">Internet Engineering Task Force</div>
        <div style="color:#6b7280;">Internet-Draft</div>
        <div style="color:#6b7280;margin-bottom:16px;">Category: <span style="color:#22c55e;">Experimental</span></div>
        <div style="color:#ffffff;font-weight:700;font-size:14px;margin-bottom:16px;">Pilot Protocol Specification</div>
        <div style="color:#6b7280;margin-bottom:12px;">Abstract</div>
        <div style="color:#9ca3af;font-size:12px;line-height:1.7;">This document specifies <span style="color:#60a5fa;">Pilot Protocol</span>,
an overlay network protocol that provides
autonomous AI agents with <span style="color:#c084fc;">48-bit virtual
addresses</span>, <span style="color:#22c55e;">encrypted UDP tunnels</span>,
<span style="color:#fbbf24;">NAT traversal</span>, port-based service
multiplexing, and a <span style="color:#f472b6;">bilateral trust
model</span> below the application layer.</div>
      </div>
    </div>

  </div>

  <!-- Footer: full width, pinned to bottom -->
  <div style="position:absolute;bottom:0;left:0;right:0;padding:0 64px 56px 64px;display:flex;justify-content:space-between;align-items:flex-end;">
    <span style="color:#6b7280;font-size:15px;font-weight:500;">March 15, 2026</span>
    <div style="display:flex;align-items:center;gap:10px;">
      <img src="${logoDataUri}" style="width:28px;height:28px;border-radius:6px;" />
      <span style="color:#9ca3af;font-size:15px;font-weight:600;">Pilot Protocol</span>
    </div>
  </div>
</body>
</html>`;

async function main() {
  const outDir = path.join(__dirname, 'banners');
  fs.mkdirSync(outDir, { recursive: true });

  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  await page.setViewport({ width: 1200, height: 630 });

  await page.setContent(html, { waitUntil: 'domcontentloaded' });
  const outPath = path.join(outDir, 'ietf-internet-draft-pilot-protocol.png');
  await page.screenshot({ path: outPath, type: 'png' });
  console.log('Generated: ietf-internet-draft-pilot-protocol.png');

  await browser.close();
}

main().catch(err => { console.error(err); process.exit(1); });
