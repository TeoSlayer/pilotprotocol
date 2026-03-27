export interface GitHubFile {
  path: string;
  content: string;
  encoding: 'utf-8' | 'base64';
}

interface GitHubEnv {
  GITHUB_TOKEN: string;
  GITHUB_OWNER: string;
  GITHUB_REPO: string;
}

const API = 'https://api.github.com';

async function ghFetch(env: GitHubEnv, path: string, init?: RequestInit): Promise<Response> {
  const url = `${API}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'pilot-publish-worker',
      ...init?.headers,
    },
  });
  return res;
}

/**
 * Check if a file exists in the repo.
 */
export async function fileExists(env: GitHubEnv, filePath: string): Promise<boolean> {
  const res = await ghFetch(env, `/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${filePath}`);
  return res.status === 200;
}

/**
 * Fetch a file's content (UTF-8 text) from the repo.
 */
export async function getFileContent(env: GitHubEnv, filePath: string): Promise<string> {
  const res = await ghFetch(env, `/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${filePath}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch ${filePath}: ${res.status} ${res.statusText}`);
  }
  const data = (await res.json()) as { content: string; encoding: string };
  if (data.encoding !== 'base64') {
    throw new Error(`Unexpected encoding for ${filePath}: ${data.encoding}`);
  }
  return atob(data.content.replace(/\n/g, ''));
}

/**
 * Create an atomic commit with multiple files using the Git Data API.
 *
 * 1. Get current HEAD SHA
 * 2. Get base tree SHA
 * 3. Create blobs for each file
 * 4. Create new tree
 * 5. Create commit
 * 6. Update ref
 */
export async function createCommit(
  env: GitHubEnv,
  files: GitHubFile[],
  message: string,
): Promise<{ commitUrl: string; sha: string }> {
  const repo = `${env.GITHUB_OWNER}/${env.GITHUB_REPO}`;

  // 1. Get current HEAD
  const refRes = await ghFetch(env, `/repos/${repo}/git/ref/heads/main`);
  if (!refRes.ok) {
    throw new Error(`Failed to get HEAD ref: ${refRes.status}`);
  }
  const refData = (await refRes.json()) as { object: { sha: string } };
  const headSha = refData.object.sha;

  // 2. Get base tree
  const commitRes = await ghFetch(env, `/repos/${repo}/git/commits/${headSha}`);
  if (!commitRes.ok) {
    throw new Error(`Failed to get commit: ${commitRes.status}`);
  }
  const commitData = (await commitRes.json()) as { tree: { sha: string } };
  const baseTreeSha = commitData.tree.sha;

  // 3. Create blobs for each file
  const treeItems: Array<{ path: string; mode: string; type: string; sha: string }> = [];
  for (const file of files) {
    const blobRes = await ghFetch(env, `/repos/${repo}/git/blobs`, {
      method: 'POST',
      body: JSON.stringify({
        content: file.content,
        encoding: file.encoding,
      }),
    });
    if (!blobRes.ok) {
      throw new Error(`Failed to create blob for ${file.path}: ${blobRes.status}`);
    }
    const blobData = (await blobRes.json()) as { sha: string };
    treeItems.push({
      path: file.path,
      mode: '100644',
      type: 'blob',
      sha: blobData.sha,
    });
  }

  // 4. Create new tree
  const treeRes = await ghFetch(env, `/repos/${repo}/git/trees`, {
    method: 'POST',
    body: JSON.stringify({
      base_tree: baseTreeSha,
      tree: treeItems,
    }),
  });
  if (!treeRes.ok) {
    throw new Error(`Failed to create tree: ${treeRes.status}`);
  }
  const treeData = (await treeRes.json()) as { sha: string };

  // 5. Create commit
  const newCommitRes = await ghFetch(env, `/repos/${repo}/git/commits`, {
    method: 'POST',
    body: JSON.stringify({
      message,
      tree: treeData.sha,
      parents: [headSha],
    }),
  });
  if (!newCommitRes.ok) {
    throw new Error(`Failed to create commit: ${newCommitRes.status}`);
  }
  const newCommit = (await newCommitRes.json()) as { sha: string; html_url: string };

  // 6. Update HEAD ref
  const updateRes = await ghFetch(env, `/repos/${repo}/git/refs/heads/main`, {
    method: 'PATCH',
    body: JSON.stringify({ sha: newCommit.sha }),
  });
  if (!updateRes.ok) {
    throw new Error(`Failed to update ref: ${updateRes.status}`);
  }

  return { commitUrl: newCommit.html_url, sha: newCommit.sha };
}
