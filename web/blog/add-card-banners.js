const fs = require('fs');
const path = require('path');

const indexPath = path.join(__dirname, 'index.html');
let html = fs.readFileSync(indexPath, 'utf-8');

// For each blog-card, add the banner img and wrap text in card-body
html = html.replace(
  /<a class="blog-card" href="([^"]+)\.html">\s*\n\s*<h3>/g,
  (match, slug) => {
    return `<a class="blog-card" href="${slug}.html">\n    <img src="banners/${slug}.png" alt="" loading="lazy">\n    <div class="card-body">\n    <h3>`;
  }
);

// Close the card-body div before closing the anchor
html = html.replace(
  /<\/div>\s*\n\s*<\/a>/g,
  '</div>\n    </div>\n  </a>'
);

fs.writeFileSync(indexPath, html);
console.log('Done! Added banner images and card-body wrappers to all blog cards.');
