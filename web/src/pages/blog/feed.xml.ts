import { blogPosts } from '../../data/blogPosts';

export async function GET() {
  const site = 'https://pilotprotocol.network';
  const items = blogPosts.map(post => `    <item>
      <title><![CDATA[${post.title}]]></title>
      <link>${site}/blog/${post.slug}</link>
      <guid isPermaLink="true">${site}/blog/${post.slug}</guid>
      <description><![CDATA[${post.description}]]></description>
      <pubDate>${new Date(post.date + ', ' + (post.year || new Date().getFullYear())).toUTCString()}</pubDate>
      <category>${post.category}</category>
    </item>`).join('\n');

  const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Pilot Protocol Blog</title>
    <link>${site}/blog/</link>
    <description>Technical articles on AI agent networking, P2P infrastructure, NAT traversal, trust models, and building with Pilot Protocol.</description>
    <language>en</language>
    <atom:link href="${site}/blog/feed.xml" rel="self" type="application/rss+xml"/>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
${items}
  </channel>
</rss>`;

  return new Response(rss, {
    headers: { 'Content-Type': 'application/xml' },
  });
}
