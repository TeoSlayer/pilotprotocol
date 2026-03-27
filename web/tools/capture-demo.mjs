import puppeteer from 'puppeteer';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const framesDir = path.join(__dirname, 'frames');
const htmlPath = path.join(__dirname, 'demo-animation.html');
const outputPath = path.join(__dirname, '..', 'public', 'demo', 'pilot-demo.mp4');

const FPS = 24;
const FRAME_MS = 1000 / FPS;

// Clean up frames dir
if (fs.existsSync(framesDir)) {
  fs.rmSync(framesDir, { recursive: true });
}
fs.mkdirSync(framesDir, { recursive: true });

async function main() {
  console.log('Launching browser...');
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080, deviceScaleFactor: 1 });

  console.log('Loading animation page...');
  await page.goto(`file://${htmlPath}`, { waitUntil: 'load' });

  // Get total duration from the page
  const totalDuration = await page.evaluate(() => window._totalDuration);
  const totalFrames = Math.ceil(totalDuration / FRAME_MS) + FPS * 2; // +2s hold at end
  console.log(`Total duration: ${totalDuration}ms, Frames to capture: ${totalFrames}`);

  // Capture frames
  for (let i = 0; i < totalFrames; i++) {
    const ms = i * FRAME_MS;
    await page.evaluate((t) => window.advanceTo(t), ms);

    const frameNum = String(i + 1).padStart(5, '0');
    await page.screenshot({
      path: path.join(framesDir, `frame_${frameNum}.png`),
      type: 'png',
    });

    if ((i + 1) % (FPS * 5) === 0) {
      console.log(`  Captured ${i + 1}/${totalFrames} frames (${Math.round(ms / 1000)}s)`);
    }
  }

  console.log(`Captured ${totalFrames} frames.`);
  await browser.close();

  // Compile with ffmpeg
  console.log('Compiling video with ffmpeg...');
  const ffmpegCmd = [
    'ffmpeg', '-y',
    '-framerate', String(FPS),
    '-i', path.join(framesDir, 'frame_%05d.png'),
    '-c:v', 'libx264',
    '-preset', 'slow',
    '-crf', '22',
    '-pix_fmt', 'yuv420p',
    '-movflags', '+faststart',
    outputPath,
  ].join(' ');

  console.log(`  ${ffmpegCmd}`);
  execSync(ffmpegCmd, { stdio: 'inherit' });

  // Clean up frames
  fs.rmSync(framesDir, { recursive: true });

  const stats = fs.statSync(outputPath);
  console.log(`\nDone! Output: ${outputPath} (${(stats.size / 1024).toFixed(0)} KB)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
