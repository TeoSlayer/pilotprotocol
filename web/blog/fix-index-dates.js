const fs = require('fs');
const path = require('path');

const dateMap = {
  'federated-learning-p2p-communication': 'Feb 28',
  'chain-ai-models-across-machines': 'Feb 28',
  'distributed-rag-without-central-knowledge-base': 'Feb 27',
  'move-beyond-rest-persistent-connections-for-agents': 'Feb 26',
  'lightweight-swarm-communication-drones-robots': 'Feb 25',
  'smart-home-without-cloud-local-device-communication': 'Feb 25',
  'build-ai-agent-marketplace-discovery-reputation': 'Feb 24',
  'distributed-monitoring-without-prometheus': 'Feb 24',
  'secure-research-collaboration-share-models-not-data': 'Feb 23',
  'secure-ai-agent-communication-zero-trust': 'Feb 23',
  'how-ai-agents-discover-each-other': 'Feb 22',
  'connect-ai-agents-behind-nat-without-vpn': 'Feb 22',
  'run-agent-network-without-cloud-dependency': 'Feb 21',
  'replace-webhooks-with-persistent-agent-tunnels': 'Feb 21',
  'cross-company-agent-collaboration-without-shared-infrastructure': 'Feb 20',
  'hipaa-compliant-agent-communication': 'Feb 20',
  'connect-agents-across-aws-gcp-azure-without-vpn': 'Feb 19',
  'how-pilot-protocol-works': 'Feb 19',
  'build-multi-agent-network-five-minutes': 'Feb 18',
  'why-ai-agents-need-network-stack': 'Feb 17',
  'trust-model-agents-invisible-by-default': 'Feb 17',
  'benchmarking-http-vs-udp-overlay': 'Feb 16',
  'build-agent-swarm-self-organizes': 'Feb 16',
  'replace-message-broker-twelve-lines-go': 'Feb 15',
  'http-services-over-encrypted-overlay': 'Feb 15',
  'peer-to-peer-file-transfer-agents': 'Feb 14',
  'decentralized-task-marketplace-agents': 'Feb 14',
  'nat-traversal-ai-agents-deep-dive': 'Feb 13',
  'a2a-agent-cards-over-pilot-tunnels': 'Feb 13',
  'ten-thousand-agents-three-vms': 'Feb 12',
  'zero-dependency-encryption-x25519-aes-gcm': 'Feb 12',
  'private-agent-network-company': 'Feb 11',
  'pilot-vs-tcp-grpc-nats-comparison': 'Feb 11',
  'contributing-codebase-tour': 'Feb 10',
  'polo-score-reputation-without-blockchain': 'Feb 10',
  'mcp-plus-pilot-tools-and-network': 'Feb 9',
  'claude-agent-teams-over-pilot': 'Feb 9',
};

const indexPath = path.join(__dirname, 'index.html');
let html = fs.readFileSync(indexPath, 'utf-8');

for (const [slug, newDate] of Object.entries(dateMap)) {
  // Match: href="slug.html" ... <span class="date">OLD DATE</span>
  const re = new RegExp(
    `(href="${slug}\\.html"[\\s\\S]*?<span class="date">)((?:Feb|Mar) \\d{1,2})(</span>)`,
  );
  html = html.replace(re, `$1${newDate}$3`);
}

fs.writeFileSync(indexPath, html);
console.log('Done! Index dates fixed.');
