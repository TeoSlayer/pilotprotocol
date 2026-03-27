import { blogPosts } from '../data/blogPosts';
import { docsNav } from '../data/docsNav';

const site = 'https://pilotprotocol.network';

function url(loc: string, lastmod: string, priority: number, changefreq = 'monthly') {
  return `  <url><loc>${site}${loc}</loc><lastmod>${lastmod}</lastmod><changefreq>${changefreq}</changefreq><priority>${priority}</priority></url>`;
}

function blogDate(date: string, year?: number): string {
  const y = year || new Date().getFullYear();
  const d = new Date(`${date}, ${y}`);
  return d.toISOString().split('T')[0];
}

export async function GET() {
  const today = new Date().toISOString().split('T')[0];

  const urls: string[] = [];

  // Static pages
  urls.push(url('/', today, 1.0, 'weekly'));
  urls.push(url('/playground', '2026-03-23', 0.7));
  urls.push(url('/blog/', today, 0.9, 'weekly'));
  urls.push(url('/llms.txt', '2026-02-28', 0.5));

  // Doc pages
  for (const nav of docsNav) {
    const isIndex = nav.href === '/docs/' || nav.href === '/docs/getting-started';
    const isReference = nav.slug === 'error-codes' || nav.slug === 'troubleshooting' || nav.slug === 'diagnostics' || nav.slug === 'configuration';
    const priority = isIndex ? 0.9 : isReference ? 0.6 : 0.8;
    urls.push(url(nav.href, today, priority));
  }

  // Research pages
  urls.push(url('/research/ietf/draft-teodor-pilot-problem-statement-00.html', '2026-03-14', 0.7));
  urls.push(url('/research/ietf/draft-teodor-pilot-protocol-00.html', '2026-03-14', 0.7));

  // Blog posts
  for (const post of blogPosts) {
    urls.push(url(`/blog/${post.slug}`, blogDate(post.date, post.year), 0.8));
  }

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join('\n')}
</urlset>
`;

  return new Response(xml, {
    headers: { 'Content-Type': 'application/xml' },
  });
}
