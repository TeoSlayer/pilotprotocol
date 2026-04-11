export interface PublishPayload {
  slug: string;
  title: string;
  description: string;
  date: string;           // e.g. "Mar 26"
  date_full: string;      // e.g. "March 26, 2026"
  category: string;
  tags: string[];
  body_html: string;
  banner_base64?: string; // base64-encoded webp (optional)
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$/;

export function validatePayload(data: unknown): { valid: true; payload: PublishPayload } | { valid: false; error: string } {
  if (typeof data !== 'object' || data === null) {
    return { valid: false, error: 'Payload must be a JSON object' };
  }

  const obj = data as Record<string, unknown>;

  // Required string fields
  for (const field of ['slug', 'title', 'description', 'date', 'date_full', 'category', 'body_html'] as const) {
    if (typeof obj[field] !== 'string' || (obj[field] as string).trim() === '') {
      return { valid: false, error: `Missing or empty required field: ${field}` };
    }
  }

  // Slug format
  if (!SLUG_RE.test(obj.slug as string)) {
    return { valid: false, error: 'Slug must be 3-100 chars, lowercase alphanumeric + hyphens' };
  }

  // Tags must be non-empty array of strings
  if (!Array.isArray(obj.tags) || obj.tags.length === 0) {
    return { valid: false, error: 'Tags must be a non-empty array' };
  }
  for (const tag of obj.tags) {
    if (typeof tag !== 'string' || tag.trim() === '') {
      return { valid: false, error: 'Each tag must be a non-empty string' };
    }
  }

  // Optional banner_base64
  if (obj.banner_base64 !== undefined) {
    if (typeof obj.banner_base64 !== 'string' || obj.banner_base64.length === 0) {
      return { valid: false, error: 'banner_base64 must be a non-empty string if provided' };
    }
  }

  return {
    valid: true,
    payload: {
      slug: (obj.slug as string).trim(),
      title: (obj.title as string).trim(),
      description: (obj.description as string).trim(),
      date: (obj.date as string).trim(),
      date_full: (obj.date_full as string).trim(),
      category: (obj.category as string).trim(),
      tags: (obj.tags as string[]).map((t) => t.trim()),
      body_html: (obj.body_html as string),
      banner_base64: obj.banner_base64 as string | undefined,
    },
  };
}

/**
 * Escape backticks and template literal expressions in HTML
 * so it can be safely placed inside a JS template literal.
 */
function escapeTemplateLiteral(html: string): string {
  return html.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
}

function escapeDoubleQuotes(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Generate the .astro file content for a blog post.
 * @param bannerExt - file extension for the banner image (default: 'webp')
 */
export function generateAstroFile(post: PublishPayload, bannerExt = 'webp'): string {
  const escaped = escapeTemplateLiteral(post.body_html);
  const banner = `/blog/banners/${post.slug}.${bannerExt}`;

  return `---
import BlogLayout from "../../layouts/BlogLayout.astro";

const bodyContent = \`${escaped}\`;
---
<BlogLayout
  title="${escapeDoubleQuotes(post.title)}"
  description="${escapeDoubleQuotes(post.description)}"
  date="${escapeDoubleQuotes(post.date_full)}"
  tags={${JSON.stringify(post.tags)}}
  canonicalPath="/blog/${post.slug}"
  bannerImage="${banner}"
>
  <Fragment set:html={bodyContent} />
</BlogLayout>
`;
}

/**
 * Generate the TypeScript object literal to prepend into the blogPosts array.
 */
/**
 * @param bannerExt - file extension for the banner image (default: 'webp')
 */
export function generateBlogPostEntry(post: PublishPayload, bannerExt = 'webp'): string {
  return `  {
    slug: "${escapeDoubleQuotes(post.slug)}",
    title: "${escapeDoubleQuotes(post.title)}",
    description: "${escapeDoubleQuotes(post.description)}",
    date: "${escapeDoubleQuotes(post.date)}",
    category: "${escapeDoubleQuotes(post.category)}",
    tags: ${JSON.stringify(post.tags)},
    banner: "banners/${post.slug}.${bannerExt}",
  },`;
}

/**
 * Insert a new blog post entry at the top of the blogPosts array.
 * Finds the first `[` in the array declaration and inserts after it.
 */
export function insertIntoBlogPosts(existing: string, entry: string): string {
  const marker = 'export const blogPosts: BlogPost[] = [';
  const idx = existing.indexOf(marker);
  if (idx === -1) {
    throw new Error('Could not find blogPosts array in blogPosts.ts');
  }
  const insertAt = idx + marker.length;
  return existing.slice(0, insertAt) + '\n' + entry + '\n' + existing.slice(insertAt);
}
