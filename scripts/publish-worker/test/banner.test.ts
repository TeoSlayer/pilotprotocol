import { describe, it, expect } from 'vitest';
import { renderBannerHTML } from '../src/banner';
import type { PublishPayload } from '../src/template';

const post: PublishPayload = {
  slug: 'test-banner-post',
  title: 'Test Banner Generation',
  description: 'Testing the auto-generated banner.',
  date: 'Mar 27',
  date_full: 'March 27, 2026',
  category: 'Tutorial',
  tags: ['test', 'demo'],
  body_html: '<p>Hello</p>',
};

describe('renderBannerHTML', () => {
  it('returns valid HTML document', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
  });

  it('sets 1200x630 viewport dimensions', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('width: 1200px');
    expect(html).toContain('height: 630px');
  });

  it('includes the post title', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('Test Banner Generation');
  });

  it('includes the category as uppercase filled pill', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('TUTORIAL');
    // Pill should have filled background, not just border
    expect(html).toContain('rgba(34, 197, 94, 0.15)');
  });

  it('includes the full date', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('March 27, 2026');
  });

  it('includes Pilot Protocol branding with logo', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('Pilot Protocol');
    expect(html).toContain('pilot.png');
  });

  it('has dark background', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('#1a1a1a');
  });

  it('has green accent line', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('#22c55e');
  });

  it('renders clean without decoration by default', () => {
    const html = renderBannerHTML(post);
    expect(html).not.toContain('class="decoration"');
  });

  it('includes decoration div when SVG is provided', () => {
    const svg = '<svg width="100" height="100"><circle cx="50" cy="50" r="40" stroke="#22c55e"/></svg>';
    const html = renderBannerHTML(post, svg);
    expect(html).toContain('class="decoration"');
    expect(html).toContain('r="40"');
  });

  it('escapes HTML in title', () => {
    const xssPost = { ...post, title: 'Post <script>alert("xss")</script>' };
    const html = renderBannerHTML(xssPost);
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('escapes HTML in category', () => {
    const xssPost = { ...post, category: '<b>bad</b>' };
    const html = renderBannerHTML(xssPost);
    expect(html).not.toContain('<b>bad</b>');
  });

  it('loads Inter font', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('fonts.googleapis.com');
    expect(html).toContain('Inter');
  });

  it('uses title-area for vertical centering', () => {
    const html = renderBannerHTML(post);
    expect(html).toContain('title-area');
    expect(html).toContain('align-items: center');
  });
});
