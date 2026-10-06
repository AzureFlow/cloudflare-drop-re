import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { unzipSync } from "fflate";

const API_BASE = "https://api.cloudflare.com/client/v4";
const UPLOAD_CONCURRENCY = 4;
const REQUEST_TIMEOUT_MS = 30_000;
const UPLOAD_TIMEOUT_MS = 300_000;
const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";

const MIME_TYPES = {
  html: "text/html",
  htm: "text/html",
  css: "text/css",
  js: "application/javascript",
  mjs: "application/javascript",
  json: "application/json",
  xml: "application/xml",
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  avif: "image/avif",
  ico: "image/x-icon",
  woff: "font/woff",
  woff2: "font/woff2",
  ttf: "font/ttf",
  otf: "font/otf",
  eot: "application/vnd.ms-fontobject",
  txt: "text/plain",
  md: "text/markdown",
  pdf: "application/pdf",
  wasm: "application/wasm",
  mp4: "video/mp4",
  webm: "video/webm",
  mp3: "audio/mpeg",
  ogg: "audio/ogg",
  map: "application/json",
};

const inputPath = process.argv[2];
if (!inputPath) {
  console.error("Usage: node src/app.js <directory | file | .zip>");
  process.exit(1);
}

try {
  const challengeResponse = await fetchChallenge();
  const { challengeToken, seed, k: checkpointCount, g: checkpointGap } = challengeResponse;

  console.time("checkpoints");
  const checkpoints = computeCheckpoints(
    base64ToBytes(seed),
    checkpointCount,
    checkpointGap,
    () => {},
  );
  console.timeEnd("checkpoints");

  const previews = await submitChallenge(challengeToken, checkpoints);
  console.log(`Provisioned temp account ${previews.account.id}`);

  /** @type {DropCredentials} */
  const credentials = {
    accountId: previews.account.id,
    apiToken: previews.account.apiToken,
    claimToken: previews.claim.token,
    claimUrl: previews.claim.url,
    expiresAt: previews.account.expiresAt,
  };
  const scriptName = `drop-${crypto.randomUUID().slice(0, 12)}`;

  const { manifest, hashedFiles } = await buildManifest(inputPath);
  console.log(
    `Deploying ${Object.keys(manifest).length} files (${hashedFiles.size} unique assets) as ${scriptName}`,
  );

  const session = await createUploadSession(credentials, scriptName, manifest);
  let completionJwt = session.jwt;
  if (session.buckets?.length) {
    completionJwt = await uploadBuckets(credentials, session, hashedFiles);
  }

  await finalizeAssets(credentials, scriptName, completionJwt, manifest, hashedFiles);

  const { subdomain } = await deployScript(credentials, scriptName, completionJwt);
  console.log(`\nLive at:   https://${scriptName}.${subdomain}.workers.dev`);
  console.log(`Expires:   ${credentials.expiresAt}`);
  console.log(`Claim URL: ${credentials.claimUrl}`);
} catch (err) {
  console.error(err);
  process.exit(1);
}

/**
 * @param {string} base64
 * @returns {Uint8Array}
 */
function base64ToBytes(base64) {
  return Buffer.from(base64, "base64");
}

/**
 * Converts a list of Uint8Arrays to a base64 string.
 * @param {Array<Uint8Array>} byteArrays
 * @returns {string}
 */
function bytesListToBase64(byteArrays) {
  const concatenated = new Uint8Array(byteArrays.length * 32);
  byteArrays.forEach((bytes, index) => concatenated.set(bytes, index * 32));
  return Buffer.from(concatenated).toString("base64");
}

/**
 * Computes a list of checkpoints based on a seed and parameters.
 * @param {Uint8Array} seed
 * @param {number} checkpointCount
 * @param {number} checkpointGap
 * @param {function(number)} [onProgress]
 * @returns {Array<Uint8Array>}
 */
function computeCheckpoints(seed, checkpointCount, checkpointGap, onProgress) {
  let checkpoints = Array(checkpointCount + 1);
  let current = sha256(seed);
  checkpoints[0] = current;
  for (let i = 0; i < checkpointCount; i++) {
    for (let j = 0; j < checkpointGap; j++) {
      current = sha256(current);
    }

    checkpoints[i + 1] = current;
    if (!(i & 15)) {
      if (onProgress) {
        onProgress(i);
      }
    }
  }

  return checkpoints;
}

/**
 * Computes the SHA-256 hash of the given data.
 *
 * crypto.hash() is the one-shot API added in Node v21.7. For millions of
 * tiny 32-byte inputs it skips creating/disposing a Hash object per call,
 * which is the dominant cost vs the actual SHA-256 math.
 *
 * Note: worker threads cannot speed this up — the chain is inherently
 * sequential (each input is the previous output), so there is nothing to
 * parallelize.
 *
 * @param {crypto.BinaryLike} data The data to be hashed.
 * @returns {Uint8Array} The hash of the data.
 */
function sha256(data) {
  return crypto.hash("sha256", data, "buffer");
}

/**
 * @returns {Promise<ChallengeResponse>}
 */
async function fetchChallenge() {
  const challengeResp = await fetch(
    "https://api.cloudflare.com/client/v4/provisioning/previews/challenge",
    {
      method: "POST",
      body: JSON.stringify({}),
      headers: {
        accept: "*/*",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json",
        origin: "https://www.cloudflare.com",
        priority: "u=1, i",
        referer: "https://www.cloudflare.com/",
        "sec-ch-ua": '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
      },
    },
  );

  /** @type {CFResponse<ChallengeResponse>} */
  const challengeContent = await challengeResp.json();

  return challengeContent.result;
}

/**
 * @param {string} challengeToken
 * @param {Uint8Array[]} checkpoints
 * @returns {Promise<PreviewsResponse>}
 */
async function submitChallenge(challengeToken, checkpoints) {
  const submitResp = await fetch("https://api.cloudflare.com/client/v4/provisioning/previews", {
    method: "POST",
    body: JSON.stringify({
      client: "web",
      source: "drop",
      termsOfService: "https://www.cloudflare.com/terms/",
      privacyPolicy: "https://www.cloudflare.com/privacypolicy/",
      acceptTermsOfService: "yes",
      challengeToken: challengeToken,
      solution: {
        checkpoints: bytesListToBase64(checkpoints),
      },
    }),
    headers: {
      accept: "*/*",
      "accept-language": "en-US,en;q=0.9",
      "content-type": "application/json",
      origin: "https://www.cloudflare.com",
      priority: "u=1, i",
      referer: "https://www.cloudflare.com/",
      "sec-ch-ua": '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
      "sec-fetch-dest": "empty",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "same-site",
      "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
    },
  });

  /** @type {CFResponse<PreviewsResponse>} */
  const submitContent = await submitResp.json();

  return submitContent.result;
}

/**
 * Reads the input path (directory, single file, or .zip) into upload entries.
 * Routes mirror the web client: zip entries keep their in-archive path, a
 * directory is served from its root, and a lone file maps to /<name>.
 *
 * @param {string} inputPath
 * @returns {Promise<Array<{ route: string, name: string, bytes: Uint8Array }>>}
 */
async function collectEntries(inputPath) {
  const stat = await fs.promises.stat(inputPath);

  if (stat.isFile()) {
    const bytes = new Uint8Array(await fs.promises.readFile(inputPath));

    if (inputPath.toLowerCase().endsWith(".zip")) {
      const unzipped = unzipSync(bytes);
      /** @type {Array<{ route: string, name: string, bytes: Uint8Array }>} */
      const entries = [];
      for (const [zipPath, data] of Object.entries(unzipped)) {
        if (zipPath.endsWith("/")) {
          continue;
        }

        entries.push({
          route: `/${zipPath}`,
          name: zipPath.split("/").pop() ?? zipPath,
          bytes: data,
        });
      }

      if (entries.length === 0) {
        throw new Error("zip archive contains no files");
      }

      return entries;
    }

    const name = path.basename(inputPath);
    return [
      {
        route: `/${name}`,
        name,
        bytes,
      },
    ];
  }

  /** @type {Array<{ route: string, name: string, bytes: Uint8Array }>} */
  const entries = [];
  await collectDirectory(path.resolve(inputPath), "", entries);
  if (entries.length === 0) {
    throw new Error(`directory is empty: ${inputPath}`);
  }

  return entries;
}

/**
 * @param {string} absDir
 * @param {string} relDir
 * @param {Array<{ route: string, name: string, bytes: Uint8Array }>} entries
 */
async function collectDirectory(absDir, relDir, entries) {
  for (const entry of await fs.promises.readdir(absDir, { withFileTypes: true })) {
    const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await collectDirectory(path.join(absDir, entry.name), rel, entries);
    } else if (entry.isFile()) {
      const bytes = new Uint8Array(await fs.promises.readFile(path.join(absDir, entry.name)));
      entries.push({ route: `/${rel}`, name: entry.name, bytes });
    }
  }
}

/**
 * Builds the assets manifest and content-addressed payloads.
 *
 * The hash is sha256(base64(bytes) + extension) truncated to 32 hex chars,
 * matching the web client; files are uploaded as base64 payloads (hence the
 * base64=true flag on the upload endpoints).
 *
 * @param {string} inputPath
 * @returns {Promise<{ manifest: Record<string, { hash: string, size: number }>, hashedFiles: Map<string, { base64: string, mime: string }> }>}
 */
async function buildManifest(inputPath) {
  const entries = await collectEntries(inputPath);
  /** @type {Record<string, { hash: string, size: number }>} */
  const manifest = {};
  /** @type {Map<string, { base64: string, mime: string }>} */
  const hashedFiles = new Map();

  for (const { route, name, bytes } of entries) {
    const base64 = Buffer.from(bytes).toString("base64");
    const ext = extensionOf(name);
    const hash = crypto.hash("sha256", base64 + ext, "hex").slice(0, 32);
    manifest[route] = { hash, size: bytes.length };
    if (!hashedFiles.has(hash)) {
      hashedFiles.set(hash, {
        base64,
        mime: MIME_TYPES[ext.toLowerCase()] ?? "application/octet-stream",
      });
    }
  }

  return {
    manifest,
    hashedFiles,
  };
}

/**
 * Returns the extension after the last dot, or "" if none (mirrors the web client).
 * @param {string} name
 */
function extensionOf(name) {
  const i = name.lastIndexOf(".");
  return i === -1 ? "" : name.slice(i + 1);
}

/**
 * Minimal fetch wrapper for the Cloudflare API with a timeout.
 * @param {string} pathname
 * @param {RequestInit & { timeoutMs?: number }} [init]
 * @returns {Promise<Response>}
 */
async function cfFetch(pathname, init = {}) {
  const { timeoutMs = REQUEST_TIMEOUT_MS, headers, ...rest } = init;
  const resp = await fetch(`${API_BASE}${pathname}`, {
    ...rest,
    headers: {
      accept: "*/*",
      "user-agent": USER_AGENT,
      ...headers,
    },
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => "Unknown error");
    throw new Error(`CF API ${rest.method ?? "GET"} ${pathname} failed (${resp.status}): ${body}`);
  }

  return resp;
}

/**
 * Worker metadata shared by the finalize and deploy calls.
 * @param {string} completionJwt
 */
function buildScriptMetadata(completionJwt) {
  return {
    compatibility_date: "2025-05-19",
    assets: {
      jwt: completionJwt,
      config: {
        not_found_handling: "single-page-application",
      },
    },
    bindings: [
      {
        name: "ASSETS",
        type: "assets",
      },
    ],
  };
}

/**
 * Opens an asset upload session; the API returns the content buckets that
 * still need uploading plus a session JWT.
 *
 * @param {DropCredentials} credentials
 * @param {string} scriptName
 * @param {Record<string, { hash: string, size: number }>} manifest
 * @returns {Promise<UploadSession>}
 */
async function createUploadSession(credentials, scriptName, manifest) {
  const resp = await cfFetch(
    `/accounts/${credentials.accountId}/workers/scripts/${scriptName}/assets-upload-session`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credentials.apiToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ manifest }),
    },
  );
  return (await resp.json()).result;
}

/**
 * Uploads each bucket of base64-encoded files; every response carries a new
 * completion JWT and the last one wins, exactly like the web client.
 *
 * @param {DropCredentials} credentials
 * @param {UploadSession} session
 * @param {Map<string, { base64: string, mime: string }>} hashedFiles
 * @returns {Promise<string>}
 */
async function uploadBuckets(credentials, session, hashedFiles) {
  let nextBucket = 0;
  let completed = 0;
  let completionJwt = null;

  async function uploadWorker() {
    while (true) {
      const bucket = session.buckets[nextBucket++];
      if (!bucket) {
        return;
      }

      const form = new FormData();
      for (const hash of bucket) {
        const file = hashedFiles.get(hash);
        if (file) {
          form.set(hash, new Blob([file.base64], { type: file.mime }), hash);
        }
      }

      const resp = await cfFetch(
        `/accounts/${credentials.accountId}/workers/assets/upload?base64=true`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${session.jwt}` },
          body: form,
          timeoutMs: UPLOAD_TIMEOUT_MS,
        },
      );
      const jwt = (await resp.json()).result?.jwt ?? null;
      if (jwt) {
        completionJwt = jwt;
      }

      completed++;
      console.log(`Uploaded assets bucket ${completed}/${session.buckets.length}`);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(UPLOAD_CONCURRENCY, session.buckets.length) }, () =>
      uploadWorker(),
    ),
  );

  if (!completionJwt) {
    throw new Error("Asset upload completed without a completion token");
  }

  return completionJwt;
}

/**
 * Attaches manifest + files to the provisioned script, authenticated with the claim token.
 *
 * @param {DropCredentials} credentials
 * @param {string} scriptName
 * @param {string} completionJwt
 * @param {Record<string, { hash: string, size: number }>} manifest
 * @param {Map<string, { base64: string, mime: string }>} hashedFiles
 */
async function finalizeAssets(credentials, scriptName, completionJwt, manifest, hashedFiles) {
  const form = new FormData();
  form.set("metadata", JSON.stringify(buildScriptMetadata(completionJwt)));
  form.set("manifest", JSON.stringify(manifest));
  for (const [hash, file] of hashedFiles) {
    form.set(hash, new Blob([file.base64], { type: file.mime }), hash);
  }

  await cfFetch(
    `/provisioning/previews/accounts/${credentials.accountId}/scripts/${scriptName}/assets?base64=true`,
    {
      method: "POST",
      headers: { "X-Claim-Token": credentials.claimToken },
      body: form,
      timeoutMs: UPLOAD_TIMEOUT_MS,
    },
  );
}

/**
 * Creates the Worker script, enables its subdomain, and returns the subdomain.
 *
 * @param {DropCredentials} credentials
 * @param {string} scriptName
 * @param {string} completionJwt
 * @returns {Promise<{ subdomain: string }>}
 */
async function deployScript(credentials, scriptName, completionJwt) {
  const form = new FormData();
  form.set("metadata", JSON.stringify(buildScriptMetadata(completionJwt)));

  await cfFetch(`/accounts/${credentials.accountId}/workers/scripts/${scriptName}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${credentials.apiToken}` },
    body: form,
    timeoutMs: UPLOAD_TIMEOUT_MS,
  });

  await cfFetch(`/accounts/${credentials.accountId}/workers/scripts/${scriptName}/subdomain`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${credentials.apiToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ enabled: true }),
  });

  const resp = await cfFetch(`/accounts/${credentials.accountId}/workers/subdomain`, {
    headers: { Authorization: `Bearer ${credentials.apiToken}` },
  });

  return {
    subdomain: (await resp.json()).result?.subdomain ?? "",
  };
}

/**
 * @typedef {object} UploadSession
 * @property {string[][]} buckets
 * @property {string} jwt
 */

/**
 * @typedef {object} DropCredentials
 * @property {string} accountId
 * @property {string} apiToken
 * @property {string} claimToken
 * @property {string} claimUrl
 * @property {string} expiresAt
 */

/**
 * @template T
 * @typedef {object} CFResponse
 * @property {boolean} success
 * @property {T} result
 * @property {Array} errors
 * @property {Array} messages
 */

/**
 * @typedef {object} ChallengeResponse
 * @property {string} challengeToken
 * @property {string} seed
 * @property {number} k
 * @property {number} g
 * @property {number} s
 * @property {number} expiresAt
 */

/**
 * @typedef {object} PreviewsResponse
 * @property {object} account
 * @property {string} account.id
 * @property {string} account.name
 * @property {string} account.type
 * @property {string} account.apiToken
 * @property {string} account.tokenId
 * @property {string} account.expiresAt
 * @property {object} claim
 * @property {string} claim.token
 * @property {string} claim.url
 * @property {string} claim.expiresAt
 */
