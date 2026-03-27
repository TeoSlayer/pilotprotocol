import { verifySignature } from './auth';
import { validatePayload, generateAstroFile, generateBlogPostEntry, insertIntoBlogPosts } from './template';
import { fileExists, getFileContent, createCommit, type GitHubFile } from './github';
import { renderBannerHTML, generateDecoration, renderBannerImage } from './banner';
import type { BrowserWorker } from '@cloudflare/puppeteer';

export interface Env {
  PUBLISH_SECRET: string;
  GITHUB_TOKEN: string;
  GITHUB_OWNER: string;
  GITHUB_REPO: string;
  GEMINI_API_KEY?: string;
  BROWSER?: BrowserWorker;
}

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 MB

function json(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function handlePublish(request: Request, env: Env): Promise<Response> {
  // 1. Read raw body with size limit
  const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (contentLength > MAX_BODY_SIZE) {
    return json({ error: 'Payload too large' }, 413);
  }
  const rawBody = await request.text();
  if (rawBody.length > MAX_BODY_SIZE) {
    return json({ error: 'Payload too large' }, 413);
  }

  // 2. Verify HMAC signature + timestamp
  const signature = request.headers.get('X-Publish-Signature');
  const timestamp = request.headers.get('X-Publish-Timestamp');
  const auth = await verifySignature(rawBody, signature, timestamp, env.PUBLISH_SECRET);
  if (!auth.valid) {
    return json({ error: auth.error || 'Unauthorized' }, 401);
  }

  // 3. Parse JSON
  let data: unknown;
  try {
    data = JSON.parse(rawBody);
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }

  // 4. Validate payload
  const validation = validatePayload(data);
  if (!validation.valid) {
    return json({ error: validation.error }, 400);
  }
  const post = validation.payload;

  const ghEnv = {
    GITHUB_TOKEN: env.GITHUB_TOKEN,
    GITHUB_OWNER: env.GITHUB_OWNER,
    GITHUB_REPO: env.GITHUB_REPO,
  };

  // 5. Check slug doesn't already exist (idempotency)
  const astroPath = `web/src/pages/blog/${post.slug}.astro`;
  const exists = await fileExists(ghEnv, astroPath);
  if (exists) {
    return json({ error: `Post with slug "${post.slug}" already exists` }, 409);
  }

  // 6. Determine banner format and generate banner
  let bannerExt = 'webp';
  const bannerFiles: GitHubFile[] = [];

  if (post.banner_base64) {
    bannerFiles.push({
      path: `web/public/blog/banners/${post.slug}.webp`,
      content: post.banner_base64,
      encoding: 'base64',
    });
  } else if (env.BROWSER) {
    // Auto-generate banner via HTML template + Cloudflare Browser Rendering
    bannerExt = 'png';
    const decoration = env.GEMINI_API_KEY
      ? await generateDecoration(post, env.GEMINI_API_KEY)
      : undefined;
    const bannerHtml = renderBannerHTML(post, decoration);
    const bannerBase64 = await renderBannerImage(env.BROWSER, bannerHtml);
    bannerFiles.push({
      path: `web/public/blog/banners/${post.slug}.png`,
      content: bannerBase64,
      encoding: 'base64',
    });
  }

  // 7. Generate .astro file
  const astroContent = generateAstroFile(post, bannerExt);

  // 8. Fetch current blogPosts.ts and insert new entry
  const blogPostsPath = 'web/src/data/blogPosts.ts';
  const currentBlogPosts = await getFileContent(ghEnv, blogPostsPath);
  const entry = generateBlogPostEntry(post, bannerExt);
  const updatedBlogPosts = insertIntoBlogPosts(currentBlogPosts, entry);

  // 9. Build file list for atomic commit
  const files: GitHubFile[] = [
    { path: astroPath, content: astroContent, encoding: 'utf-8' },
    { path: blogPostsPath, content: updatedBlogPosts, encoding: 'utf-8' },
    ...bannerFiles,
  ];

  // 10. Create atomic commit
  const result = await createCommit(ghEnv, files, `Add blog post: ${post.title}`);

  // 11. Return success
  return json(
    {
      commit_url: result.commitUrl,
      post_url: `https://pilotprotocol.network/blog/${post.slug}`,
      sha: result.sha,
    },
    201,
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/api/publish' && request.method === 'POST') {
        return await handlePublish(request, env);
      }

      // Banner preview — renders the HTML template directly (useful for testing)
      if (path === '/api/preview-banner' && request.method === 'POST') {
        return await handlePreviewBanner(request, env);
      }

      // Health check
      if (path === '/health' && request.method === 'GET') {
        return json({ status: 'ok' }, 200);
      }

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      console.error('Unhandled error:', err);
      const message = err instanceof Error ? err.message : 'Internal server error';
      // Distinguish GitHub API errors
      if (message.includes('Failed to')) {
        return json({ error: message }, 502);
      }
      return json({ error: 'Internal server error' }, 500);
    }
  },
};

/**
 * Preview endpoint: returns the banner HTML for visual testing.
 * POST /api/preview-banner — requires HMAC auth (same as publish).
 */
async function handlePreviewBanner(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.text();

  // Require auth — same HMAC verification as publish
  const signature = request.headers.get('X-Publish-Signature');
  const timestamp = request.headers.get('X-Publish-Timestamp');
  const auth = await verifySignature(rawBody, signature, timestamp, env.PUBLISH_SECRET);
  if (!auth.valid) {
    return json({ error: auth.error || 'Unauthorized' }, 401);
  }

  let data: unknown;
  try {
    data = JSON.parse(rawBody);
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }

  const validation = validatePayload(data);
  if (!validation.valid) {
    return json({ error: validation.error }, 400);
  }

  const post = validation.payload;
  const decoration = env.GEMINI_API_KEY
    ? await generateDecoration(post, env.GEMINI_API_KEY)
    : undefined;
  const html = renderBannerHTML(post, decoration);

  return new Response(html, {
    headers: { 'Content-Type': 'text/html' },
  });
}
