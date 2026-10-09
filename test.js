'use strict';
// Automated test suite verifying all 14 required security, authentication,
// and authorization scenarios. Built with node:test and node:assert (zero npm dependencies).

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');

const TEST_PORT = 3999;
const TEST_DIR = path.join(__dirname, 'data', 'test_sandbox');
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

const HOST_EMAIL = 'sjohnpaul638@gmail.com';
const HOST_PASSWORD = 'Admin1234!';

let serverProcess = null;

// Helper: send HTTP request with optional cookie and JSON body
function req(method, urlPath, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, BASE_URL);
    const reqHeaders = { ...headers };
    let postData = null;
    if (body !== null) {
      postData = typeof body === 'string' ? body : JSON.stringify(body);
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }
    const r = http.request(url, { method, headers: reqHeaders }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) {}
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text,
          json
        });
      });
    });
    r.on('error', reject);
    if (postData) r.write(postData);
    r.end();
  });
}

function extractCookie(headers) {
  const sc = headers['set-cookie'];
  if (!sc) return null;
  const cookieStr = Array.isArray(sc) ? sc[0] : sc;
  const m = /^([^;]+)/.exec(cookieStr);
  return m ? m[1] : null;
}

test('Test Suite: Portfolio Authentication & Access Control', async t => {
  // Setup: start isolated server instance on TEST_PORT
  await t.test('Setup: Start isolated test server', async () => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    // Clean any prior test DB
    try { fs.rmSync(path.join(TEST_DIR, 'app.db'), { force: true }); } catch (_) {}

    serverProcess = spawn(process.execPath, ['server.js'], {
      cwd: __dirname,
      env: {
        ...process.env,
        PORT: String(TEST_PORT),
        DATA_DIR: TEST_DIR,
        OWNER_EMAIL: HOST_EMAIL,
        OWNER_PASSWORD: HOST_PASSWORD,
        NODE_ENV: 'test',
        TRUST_PROXY: '0'
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    // Wait until server starts listening
    let ready = false;
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 150));
      try {
        const res = await req('GET', '/');
        if (res.status === 200) { ready = true; break; }
      } catch (_) {}
    }
    assert.strictEqual(ready, true, 'Test server failed to start within timeout.');
  });

  // Scenario 1: Opening the root URL while signed out displays the login page
  await t.test('Scenario 1: Signed-out root URL renders login page', async () => {
    const res = await req('GET', '/');
    assert.strictEqual(res.status, 200);
    assert.match(res.text, /<form id="f"/);
    assert.match(res.text, /WELCOME/);
    assert.match(res.text, /id="go"/);
    // Unauthenticated user must NOT receive the private portfolio HTML
    assert.doesNotMatch(res.text, /<canvas id="cv"/);
  });

  // Scenario 2: Arbitrary non-empty email and password allow visitor access
  // Scenario 3: A new visitor does not have to register
  let visitorCookie = null;
  await t.test('Scenarios 2 & 3: Arbitrary unregistered visitor credentials allow instant access', async () => {
    const res = await req('POST', '/api/login', {}, {
      email: 'new.visitor99@example.com',
      password: 'ArbitraryPassword123!'
    });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.json, { role: 'visitor' });
    visitorCookie = extractCookie(res.headers);
    assert.ok(visitorCookie, 'Session cookie must be set for visitor.');

    // Opening / with the visitor cookie returns the portfolio
    const pageRes = await req('GET', '/', { Cookie: visitorCookie });
    assert.strictEqual(pageRes.status, 200);
    assert.match(pageRes.text, /<canvas id="cv"/);
    assert.match(pageRes.text, /S John Paul/);
  });

  // Scenario 4: The exact configured host credential pair grants the host role
  let hostCookie = null;
  await t.test('Scenario 4: Exact host credentials grant host role', async () => {
    const res = await req('POST', '/api/login', {}, {
      email: HOST_EMAIL,
      password: HOST_PASSWORD
    });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.json, { role: 'host' });
    hostCookie = extractCookie(res.headers);
    assert.ok(hostCookie, 'Session cookie must be set for host.');

    const meRes = await req('GET', '/api/me', { Cookie: hostCookie });
    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.json.role, 'host');
    assert.strictEqual(meRes.json.email, HOST_EMAIL);
  });

  // Scenario 5: Host sees project and certificate management controls and can manage items
  let createdProjectId = null;
  let createdCertId = null;
  await t.test('Scenario 5: Host can create projects and certificates', async () => {
    const pRes = await req('POST', '/api/projects', { Cookie: hostCookie }, {
      title: 'Automation Engine',
      cat: 'AI / Backend',
      short: 'Automated task runner',
      full: 'Full enterprise grade background runner',
      tech: 'Node.js, SQLite'
    });
    assert.strictEqual(pRes.status, 201);
    assert.strictEqual(pRes.json.ok, 1);

    const cRes = await req('POST', '/api/certs', { Cookie: hostCookie }, {
      name: 'Advanced AI Certificate',
      org: 'DeepMind',
      date: 'October 2026',
      desc: 'Certified advanced AI developer',
      tech: 'AI/ML'
    });
    assert.strictEqual(cRes.status, 201);
    assert.strictEqual(cRes.json.ok, 1);

    const contentRes = await req('GET', '/api/content', { Cookie: hostCookie });
    assert.strictEqual(contentRes.status, 200);
    const proj = contentRes.json.projects.find(x => x.title === 'Automation Engine');
    const cert = contentRes.json.certs.find(x => x.name === 'Advanced AI Certificate');
    assert.ok(proj, 'Created project must be present in content.');
    assert.ok(cert, 'Created certificate must be present in content.');
    createdProjectId = proj.id;
    createdCertId = cert.id;
  });

  // Scenario 6: Visitors see none of the Add or Remove controls
  await t.test('Scenario 6: Visitors role is visitor, frontend guards hide controls', async () => {
    const meRes = await req('GET', '/api/me', { Cookie: visitorCookie });
    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.json.role, 'visitor');

    // In private/index.html, verify that the frontend role check ONLY enables controls when role === 'host'
    const indexHtml = fs.readFileSync(path.join(__dirname, 'private', 'index.html'), 'utf8');
    assert.match(indexHtml, /OWN=\(await api\("GET","\/api\/me"\)\)\.role==="host"/);
    assert.match(indexHtml, /H\(\$\("#ap"\),OWN\?'<button class="go" data-add="projects">\+ Add project<\/button>':""\)/);
    assert.match(indexHtml, /H\(\$\("#ac"\),OWN\?'<button class="go" data-add="certs">\+ Add certificate<\/button>':""\)/);
    assert.match(indexHtml, /const ctl=\(k,id\)=>OWN\?/);
  });

  // Scenario 7: Host email combined with wrong password never grants host permissions
  await t.test('Scenario 7: Host email with wrong password enters only as visitor', async () => {
    const res = await req('POST', '/api/login', {}, {
      email: HOST_EMAIL,
      password: 'IncorrectPassword999!'
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.role, 'visitor', 'Must NEVER grant host role with wrong password.');

    const wrongHostCookie = extractCookie(res.headers);
    const meRes = await req('GET', '/api/me', { Cookie: wrongHostCookie });
    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.json.role, 'visitor');

    // Attempting a write as this session must be rejected with 403
    const writeRes = await req('POST', '/api/projects', { Cookie: wrongHostCookie }, {
      title: 'Unauthorized Project Attempt'
    });
    assert.strictEqual(writeRes.status, 403);
  });

  // Scenario 8: Visitors cannot add or delete content by calling the API directly
  await t.test('Scenario 8: Visitor write requests return 403 Forbidden', async () => {
    const postProj = await req('POST', '/api/projects', { Cookie: visitorCookie }, { title: 'Hack Project' });
    assert.strictEqual(postProj.status, 403);
    assert.strictEqual(postProj.json.error, 'Host access required.');

    const putProj = await req('PUT', `/api/projects/${createdProjectId}`, { Cookie: visitorCookie }, { title: 'Hacked Title' });
    assert.strictEqual(putProj.status, 403);

    const delProj = await req('DELETE', `/api/projects/${createdProjectId}`, { Cookie: visitorCookie });
    assert.strictEqual(delProj.status, 403);

    const postCert = await req('POST', '/api/certs', { Cookie: visitorCookie }, { name: 'Fake Cert' });
    assert.strictEqual(postCert.status, 403);

    const delCert = await req('DELETE', `/api/certs/${createdCertId}`, { Cookie: visitorCookie });
    assert.strictEqual(delCert.status, 403);
  });

  // Scenario 9: Anonymous requests cannot modify content
  await t.test('Scenario 9: Anonymous requests receive 401 Unauthorized', async () => {
    const postRes = await req('POST', '/api/projects', {}, { title: 'Anonymous Attempt' });
    assert.strictEqual(postRes.status, 401);
    assert.strictEqual(postRes.json.error, 'Sign in required.');

    const delRes = await req('DELETE', `/api/projects/${createdProjectId}`, {});
    assert.strictEqual(delRes.status, 401);

    const postCertRes = await req('POST', '/api/certs', {}, { name: 'Anonymous Cert' });
    assert.strictEqual(postCertRes.status, 401);
  });

  // Scenario 10: Host project and certificate changes persist after refresh and new login
  await t.test('Scenario 10: Content persistence across sessions', async () => {
    // Modify project as host
    const updateRes = await req('PUT', `/api/projects/${createdProjectId}`, { Cookie: hostCookie }, {
      title: 'Automation Engine Updated',
      cat: 'AI / Backend'
    });
    assert.strictEqual(updateRes.status, 200);

    // Create a new fresh visitor session
    const freshLogin = await req('POST', '/api/login', {}, {
      email: 'different.visitor@domain.com',
      password: 'PassWord123!'
    });
    const freshCookie = extractCookie(freshLogin.headers);

    // Verify the change is visible in the fresh session
    const contentRes = await req('GET', '/api/content', { Cookie: freshCookie });
    assert.strictEqual(contentRes.status, 200);
    const updatedProj = contentRes.json.projects.find(x => x.id === createdProjectId);
    assert.ok(updatedProj, 'Project must persist.');
    assert.strictEqual(updatedProj.title, 'Automation Engine Updated');
  });

  // Scenario 11: Real-time updates continue to work
  await t.test('Scenario 11: Real-time SSE updates receive update notification on content write', async () => {
    return new Promise(async (resolve, reject) => {
      const url = new URL('/api/events', BASE_URL);
      const sseReq = http.request(url, { method: 'GET', headers: { Cookie: visitorCookie } }, res => {
        assert.strictEqual(res.statusCode, 200);
        assert.strictEqual(res.headers['content-type'], 'text/event-stream');
        res.on('data', chunk => {
          const str = chunk.toString();
          if (str.includes('data: update')) {
            sseReq.destroy();
            resolve();
          }
        });
      });
      sseReq.on('error', err => {
        if (err.code !== 'ECONNRESET') reject(err);
      });
      sseReq.end();

      // Give SSE time to connect, then trigger a write from host
      await new Promise(r => setTimeout(r, 200));
      await req('PUT', `/api/projects/${createdProjectId}`, { Cookie: hostCookie }, {
        title: 'Automation Engine SSE Ping',
        cat: 'AI / Backend'
      });
    });
  });

  // Scenario 12: Logout invalidates the session and returns to login page
  await t.test('Scenario 12: Logout invalidates server-side session and cookie', async () => {
    const loRes = await req('POST', '/api/logout', { Cookie: visitorCookie });
    assert.strictEqual(loRes.status, 200);
    assert.deepStrictEqual(loRes.json, { ok: 1 });

    // Cookie header must clear the cookie
    const sc = loRes.headers['set-cookie'];
    assert.ok(sc && sc[0].includes('Max-Age=0'));

    // Trying to use previous visitorCookie must now be rejected
    const meAfterLo = await req('GET', '/api/me', { Cookie: visitorCookie });
    assert.strictEqual(meAfterLo.status, 401);

    const rootAfterLo = await req('GET', '/', { Cookie: visitorCookie });
    assert.strictEqual(rootAfterLo.status, 200);
    assert.match(rootAfterLo.text, /<form id="f"/);
    assert.doesNotMatch(rootAfterLo.text, /<canvas id="cv"/);
  });

  // Scenario 13: Existing portfolio content and responsive layouts still work
  await t.test('Scenario 13: Portfolio responsive layout and major sections are preserved', async () => {
    const indexHtml = fs.readFileSync(path.join(__dirname, 'private', 'index.html'), 'utf8');
    assert.match(indexHtml, /id="hero"/);
    assert.match(indexHtml, /id="about"/);
    assert.match(indexHtml, /id="work"/);
    assert.match(indexHtml, /id="skills"/);
    assert.match(indexHtml, /id="journey"/);
    assert.match(indexHtml, /id="education"/);
    assert.match(indexHtml, /id="certificates"/);
    assert.match(indexHtml, /id="services"/);
    assert.match(indexHtml, /id="highlights"/);
    assert.match(indexHtml, /id="contact"/);
    assert.match(indexHtml, /@media\(max-width:860px\)/);
    assert.match(indexHtml, /@media\(max-height:540px\)/);
    assert.match(indexHtml, /@media\(min-width:1921px\)/);
  });

  // Scenario 14: Application starts up and syntax is clean
  await t.test('Scenario 14: Server syntax and environment load cleanly', async () => {
    assert.ok(serverProcess && serverProcess.exitCode === null, 'Server is running healthy.');
  });

  // Teardown: terminate test server
  await t.test('Teardown: Terminate test server', async () => {
    if (serverProcess) {
      serverProcess.kill();
      await new Promise(r => serverProcess.on('exit', r));
    }
    // Clean up test data folder
    try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
  });
});
