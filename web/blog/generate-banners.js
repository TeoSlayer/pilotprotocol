const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const posts = [
  { file: 'claude-agent-teams-over-pilot', title: 'Building Claude Code Agent Teams Over Pilot Protocol', category: 'Integration', date: 'February 9, 2026' },
  { file: 'mcp-plus-pilot-tools-and-network', title: 'MCP + Pilot: Give Your Agent Tools AND a Network', category: 'Integration', date: 'February 9, 2026' },
  { file: 'polo-score-reputation-without-blockchain', title: 'The Polo Score: Designing a Reputation System Without Blockchain', category: 'Design', date: 'February 10, 2026' },
  { file: 'contributing-codebase-tour', title: 'Contributing to Pilot Protocol: A Tour of the Codebase', category: 'Community', date: 'February 10, 2026' },
  { file: 'pilot-vs-tcp-grpc-nats-comparison', title: 'Pilot Protocol vs. Raw TCP vs. gRPC vs. NATS', category: 'Comparison', date: 'February 11, 2026' },
  { file: 'private-agent-network-company', title: 'Building a Private Agent Network for Your Company', category: 'Guide', date: 'February 11, 2026' },
  { file: 'zero-dependency-encryption-x25519-aes-gcm', title: 'Zero-Dependency Agent Encryption: X25519 + AES-256-GCM', category: 'Cryptography', date: 'February 12, 2026' },
  { file: 'a2a-agent-cards-over-pilot-tunnels', title: 'Building A2A Agent Cards Over Pilot Protocol Tunnels', category: 'Integration', date: 'February 13, 2026' },
  { file: 'nat-traversal-ai-agents-deep-dive', title: 'NAT Traversal for AI Agents: A Deep Dive', category: 'Deep Dive', date: 'February 13, 2026' },
  { file: 'decentralized-task-marketplace-agents', title: 'Build a Decentralized Task Marketplace for AI Agents', category: 'Tutorial', date: 'February 14, 2026' },
  { file: 'peer-to-peer-file-transfer-agents', title: 'Peer-to-Peer File Transfer Between AI Agents', category: 'Tutorial', date: 'February 14, 2026' },
  { file: 'http-services-over-encrypted-overlay', title: 'Run HTTP Services Over an Encrypted Agent Overlay', category: 'Tutorial', date: 'February 15, 2026' },
  { file: 'replace-message-broker-twelve-lines-go', title: 'Replace Your Agent Message Broker with 12 Lines of Go', category: 'Tutorial', date: 'February 15, 2026' },
  { file: 'build-agent-swarm-self-organizes', title: 'Build an Agent Swarm That Self-Organizes via Reputation', category: 'Tutorial', date: 'February 16, 2026' },
  { file: 'benchmarking-http-vs-udp-overlay', title: 'Benchmarking Agent Communication: HTTP vs. UDP Overlay', category: 'Benchmark', date: 'February 16, 2026' },
  { file: 'trust-model-agents-invisible-by-default', title: 'The Pilot Trust Model: Why Agents Should Be Invisible by Default', category: 'Security', date: 'February 17, 2026' },
  { file: 'why-ai-agents-need-network-stack', title: 'Why AI Agents Need Their Own Network Stack', category: 'Analysis', date: 'February 17, 2026' },
  { file: 'build-multi-agent-network-five-minutes', title: 'Build a Multi-Agent Network in 5 Minutes', category: 'Tutorial', date: 'February 18, 2026' },
  { file: 'how-pilot-protocol-works', title: 'How Pilot Protocol Works', category: 'Architecture', date: 'February 19, 2026' },
  { file: 'connect-agents-across-aws-gcp-azure-without-vpn', title: 'Connect Agents Across AWS, GCP, and Azure Without a VPN', category: 'Guide', date: 'February 19, 2026' },
  { file: 'hipaa-compliant-agent-communication', title: 'HIPAA-Compliant Agent Communication for Healthcare AI', category: 'Compliance', date: 'February 20, 2026' },
  { file: 'cross-company-agent-collaboration-without-shared-infrastructure', title: 'Cross-Company Agent Collaboration Without Shared Infrastructure', category: 'Architecture', date: 'February 20, 2026' },
  { file: 'replace-webhooks-with-persistent-agent-tunnels', title: 'Replace Webhooks With Persistent Agent Tunnels', category: 'Architecture', date: 'February 21, 2026' },
  { file: 'run-agent-network-without-cloud-dependency', title: 'Run Your Agent Network Without Cloud Dependency', category: 'Guide', date: 'February 21, 2026' },
  { file: 'connect-ai-agents-behind-nat-without-vpn', title: 'Connect AI Agents Behind NAT Without a VPN', category: 'Guide', date: 'February 22, 2026' },
  { file: 'how-ai-agents-discover-each-other', title: 'How AI Agents Discover Each Other on a Live Network', category: 'Guide', date: 'February 22, 2026' },
  { file: 'secure-ai-agent-communication-zero-trust', title: 'How to Secure AI Agent Communication With Zero Trust', category: 'Security', date: 'February 23, 2026' },
  { file: 'secure-research-collaboration-share-models-not-data', title: 'Secure Research Collaboration: Share Models, Not Data', category: 'Research', date: 'February 23, 2026' },
  { file: 'distributed-monitoring-without-prometheus', title: 'Distributed Monitoring Without Prometheus or Grafana', category: 'Operations', date: 'February 24, 2026' },
  { file: 'build-ai-agent-marketplace-discovery-reputation', title: 'Build an AI Agent Marketplace With Discovery and Reputation', category: 'Architecture', date: 'February 24, 2026' },
  { file: 'smart-home-without-cloud-local-device-communication', title: 'Smart Home Without Cloud: Local-First Device Communication', category: 'Guide', date: 'February 25, 2026' },
  { file: 'lightweight-swarm-communication-drones-robots', title: 'Lightweight Swarm Communication for Drones and Robots', category: 'Robotics', date: 'February 25, 2026' },
  { file: 'move-beyond-rest-persistent-connections-for-agents', title: 'Move Beyond REST: Persistent Connections for Agents', category: 'Architecture', date: 'February 26, 2026' },
  { file: 'distributed-rag-without-central-knowledge-base', title: 'Distributed RAG Without a Central Knowledge Base', category: 'AI/ML', date: 'February 27, 2026' },
  { file: 'chain-ai-models-across-machines', title: 'Chain AI Models Across Machines With Persistent Tunnels', category: 'AI/ML', date: 'February 28, 2026' },
  { file: 'federated-learning-p2p-communication', title: 'P2P Communication for Federated Learning Nodes', category: 'AI/ML', date: 'February 28, 2026' },
  { file: 'build-openclaw-agent-self-organizes-pilot', title: 'Build an OpenClaw Agent That Self-Organizes Into Pilot', category: 'Tutorial', date: 'March 1, 2026' },
  { file: 'building-custom-pilot-skills-openclaw', title: 'Building Custom Pilot Skills for OpenClaw', category: 'Development', date: 'March 1, 2026' },
  { file: 'clawhub-to-live-network-openclaw-discovery', title: 'From ClawHub to Live Network: OpenClaw Discovery', category: 'Tutorial', date: 'March 2, 2026' },
  { file: 'emergent-trust-networks-agents-choose-peers', title: 'Emergent Trust Networks: Agents Choose Peers', category: 'Networks', date: 'March 2, 2026' },
  { file: 'how-626-agents-autonomously-adopted-pilot', title: 'How 626 Agents Autonomously Adopted Pilot Protocol', category: 'Case Study', date: 'March 3, 2026' },
  { file: 'multi-agent-pipelines-openclaw-encrypted-tunnels', title: 'Multi-Agent Pipelines With OpenClaw and Encrypted Tunnels', category: 'Tutorial', date: 'March 3, 2026' },
  { file: 'openclaw-agents-behind-nat-zero-config', title: 'OpenClaw Agents Behind NAT: Zero Config', category: 'Networking', date: 'March 4, 2026' },
  { file: 'openclaw-meets-pilot-agent-networking-one-command', title: 'OpenClaw Meets Pilot: Agent Networking in One Command', category: 'Integration', date: 'March 4, 2026' },
  { file: 'openclaw-task-delegation-polo-reputation', title: 'OpenClaw Task Delegation with Polo Reputation', category: 'Tutorial', date: 'March 5, 2026' },
  { file: 'preferential-attachment-ai-networks-trust-graph', title: 'Preferential Attachment in AI Networks: The Trust Graph', category: 'Research', date: 'March 5, 2026' },
  { file: 'scaling-openclaw-fleets-thousands-agents', title: 'Scaling OpenClaw Fleets to Thousands of Agents', category: 'Operations', date: 'March 6, 2026' },
  { file: 'sociology-of-machines-626-agents', title: 'Sociology of Machines: 626 Agents', category: 'Research', date: 'March 6, 2026' },
  { file: 'why-autonomous-agents-need-private-discovery', title: 'Why Autonomous Agents Need Private Discovery', category: 'Security', date: 'March 7, 2026' },
  { file: 'python-sdk-pilot-protocol', title: 'Announcing the Pilot Protocol Python SDK', category: 'Integration', date: 'March 13, 2026' },
  { file: 'ietf-internet-draft-pilot-protocol', title: 'Pilot Protocol IETF Internet-Drafts Published', category: 'Standards', date: 'March 15, 2026' },
  { file: 'enterprise-private-networks-roadmap', title: 'Enterprise Private Networks: The Roadmap', category: 'Security', date: 'March 21, 2026' },
  { file: 'enterprise-identity-integration-pilot-protocol', title: 'Enterprise Identity Integration: Entra ID, SPIFFE, OPA, and Beyond', category: 'Enterprise', date: 'March 21, 2026' },
];

const logoBase64 = fs.readFileSync(path.join(__dirname, '../../docs/media/pilot.png')).toString('base64');
const logoDataUri = `data:image/png;base64,${logoBase64}`;

function generateHTML(post) {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;width:1200px;height:630px;overflow:hidden;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="position:absolute;top:0;left:0;right:0;height:4px;background:#22c55e;"></div>
  <div style="position:absolute;inset:0;background-image:radial-gradient(circle,rgba(255,255,255,0.03) 1px,transparent 1px);background-size:24px 24px;"></div>
  <div style="position:relative;padding:56px 64px;height:100%;box-sizing:border-box;display:flex;flex-direction:column;">
    <div style="display:inline-block;border:1.5px solid #22c55e;color:#22c55e;padding:6px 18px;border-radius:20px;font-size:15px;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:32px;width:fit-content;">${post.category}</div>
    <div style="flex:1;display:flex;align-items:center;">
      <h1 style="color:#ffffff;font-size:42px;font-weight:700;line-height:1.25;margin:0;max-width:900px;">${post.title}</h1>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:flex-end;">
      <span style="color:#6b7280;font-size:16px;font-weight:500;">${post.date}</span>
      <div style="display:flex;align-items:center;gap:10px;">
        <img src="${logoDataUri}" style="width:28px;height:28px;border-radius:6px;" />
        <span style="color:#9ca3af;font-size:16px;font-weight:600;">Pilot Protocol</span>
      </div>
    </div>
  </div>
</body>
</html>`;
}

async function main() {
  const outDir = path.join(__dirname, 'banners');
  fs.mkdirSync(outDir, { recursive: true });

  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  await page.setViewport({ width: 1200, height: 630 });

  for (const post of posts) {
    const html = generateHTML(post);
    await page.setContent(html, { waitUntil: 'domcontentloaded' });
    const outPath = path.join(outDir, `${post.file}.png`);
    await page.screenshot({ path: outPath, type: 'png' });
    console.log(`Generated: ${post.file}.png`);
  }

  await browser.close();
  console.log(`\nDone! ${posts.length} banners generated in ${outDir}`);
}

main().catch(err => { console.error(err); process.exit(1); });
