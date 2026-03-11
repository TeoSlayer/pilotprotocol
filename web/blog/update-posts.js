const fs = require('fs');
const path = require('path');

// 37 posts, distributed over Feb 9–28 (2 per day, last 2 days get 1)
const posts = [
  { file: 'claude-agent-teams-over-pilot', date: 'February 9, 2026', iso: '2026-02-09', short: 'Feb 9' },
  { file: 'mcp-plus-pilot-tools-and-network', date: 'February 9, 2026', iso: '2026-02-09', short: 'Feb 9' },
  { file: 'polo-score-reputation-without-blockchain', date: 'February 10, 2026', iso: '2026-02-10', short: 'Feb 10' },
  { file: 'contributing-codebase-tour', date: 'February 10, 2026', iso: '2026-02-10', short: 'Feb 10' },
  { file: 'pilot-vs-tcp-grpc-nats-comparison', date: 'February 11, 2026', iso: '2026-02-11', short: 'Feb 11' },
  { file: 'private-agent-network-company', date: 'February 11, 2026', iso: '2026-02-11', short: 'Feb 11' },
  { file: 'zero-dependency-encryption-x25519-aes-gcm', date: 'February 12, 2026', iso: '2026-02-12', short: 'Feb 12' },
  { file: 'ten-thousand-agents-three-vms', date: 'February 12, 2026', iso: '2026-02-12', short: 'Feb 12' },
  { file: 'a2a-agent-cards-over-pilot-tunnels', date: 'February 13, 2026', iso: '2026-02-13', short: 'Feb 13' },
  { file: 'nat-traversal-ai-agents-deep-dive', date: 'February 13, 2026', iso: '2026-02-13', short: 'Feb 13' },
  { file: 'decentralized-task-marketplace-agents', date: 'February 14, 2026', iso: '2026-02-14', short: 'Feb 14' },
  { file: 'peer-to-peer-file-transfer-agents', date: 'February 14, 2026', iso: '2026-02-14', short: 'Feb 14' },
  { file: 'http-services-over-encrypted-overlay', date: 'February 15, 2026', iso: '2026-02-15', short: 'Feb 15' },
  { file: 'replace-message-broker-twelve-lines-go', date: 'February 15, 2026', iso: '2026-02-15', short: 'Feb 15' },
  { file: 'build-agent-swarm-self-organizes', date: 'February 16, 2026', iso: '2026-02-16', short: 'Feb 16' },
  { file: 'benchmarking-http-vs-udp-overlay', date: 'February 16, 2026', iso: '2026-02-16', short: 'Feb 16' },
  { file: 'trust-model-agents-invisible-by-default', date: 'February 17, 2026', iso: '2026-02-17', short: 'Feb 17' },
  { file: 'why-ai-agents-need-network-stack', date: 'February 17, 2026', iso: '2026-02-17', short: 'Feb 17' },
  { file: 'build-multi-agent-network-five-minutes', date: 'February 18, 2026', iso: '2026-02-18', short: 'Feb 18' },
  { file: 'how-pilot-protocol-works', date: 'February 19, 2026', iso: '2026-02-19', short: 'Feb 19' },
  { file: 'connect-agents-across-aws-gcp-azure-without-vpn', date: 'February 19, 2026', iso: '2026-02-19', short: 'Feb 19' },
  { file: 'hipaa-compliant-agent-communication', date: 'February 20, 2026', iso: '2026-02-20', short: 'Feb 20' },
  { file: 'cross-company-agent-collaboration-without-shared-infrastructure', date: 'February 20, 2026', iso: '2026-02-20', short: 'Feb 20' },
  { file: 'replace-webhooks-with-persistent-agent-tunnels', date: 'February 21, 2026', iso: '2026-02-21', short: 'Feb 21' },
  { file: 'run-agent-network-without-cloud-dependency', date: 'February 21, 2026', iso: '2026-02-21', short: 'Feb 21' },
  { file: 'connect-ai-agents-behind-nat-without-vpn', date: 'February 22, 2026', iso: '2026-02-22', short: 'Feb 22' },
  { file: 'how-ai-agents-discover-each-other', date: 'February 22, 2026', iso: '2026-02-22', short: 'Feb 22' },
  { file: 'secure-ai-agent-communication-zero-trust', date: 'February 23, 2026', iso: '2026-02-23', short: 'Feb 23' },
  { file: 'secure-research-collaboration-share-models-not-data', date: 'February 23, 2026', iso: '2026-02-23', short: 'Feb 23' },
  { file: 'distributed-monitoring-without-prometheus', date: 'February 24, 2026', iso: '2026-02-24', short: 'Feb 24' },
  { file: 'build-ai-agent-marketplace-discovery-reputation', date: 'February 24, 2026', iso: '2026-02-24', short: 'Feb 24' },
  { file: 'smart-home-without-cloud-local-device-communication', date: 'February 25, 2026', iso: '2026-02-25', short: 'Feb 25' },
  { file: 'lightweight-swarm-communication-drones-robots', date: 'February 25, 2026', iso: '2026-02-25', short: 'Feb 25' },
  { file: 'move-beyond-rest-persistent-connections-for-agents', date: 'February 26, 2026', iso: '2026-02-26', short: 'Feb 26' },
  { file: 'distributed-rag-without-central-knowledge-base', date: 'February 27, 2026', iso: '2026-02-27', short: 'Feb 27' },
  { file: 'chain-ai-models-across-machines', date: 'February 28, 2026', iso: '2026-02-28', short: 'Feb 28' },
  { file: 'federated-learning-p2p-communication', date: 'February 28, 2026', iso: '2026-02-28', short: 'Feb 28' },
];

const blogDir = __dirname;

let updated = 0;
for (const post of posts) {
  const filePath = path.join(blogDir, `${post.file}.html`);
  let html = fs.readFileSync(filePath, 'utf-8');

  // 1. Update article-meta date — match any "Month Day, 2026" pattern
  html = html.replace(
    /(<div class="article-meta">\s*<span>)((?:January|February|March|April) \d{1,2}, 2026)(<\/span>)/,
    `$1${post.date}$3`
  );

  // 2. Update datePublished in JSON-LD — match any ISO date
  html = html.replace(
    /"datePublished":\s*"2026-\d{2}-\d{2}"/,
    `"datePublished": "${post.iso}"`
  );

  fs.writeFileSync(filePath, html);
  updated++;
  console.log(`Updated: ${post.file} → ${post.date} (${post.iso})`);
}

console.log(`\nDone! ${updated} posts updated.`);

// Export for use by other scripts
module.exports = { posts };
