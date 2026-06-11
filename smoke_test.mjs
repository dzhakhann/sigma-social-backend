// Smoke test for the secured API. Run after the server is up + DB migrated:
//   node smoke_test.mjs                       (tests http://localhost:3000)
//   API_BASE=https://your-render-url/api node smoke_test.mjs
//
// It verifies: auth without email, recovery phrase, JWT protection (401),
// ownership protection (403), and that the actor comes from the token.

const BASE = process.env.API_BASE || 'http://localhost:3000/api';
let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? '✅ PASS' : '❌ FAIL'}  ${name}${extra ? '  — ' + extra : ''}`);
  cond ? pass++ : fail++;
};
const j = async (res) => { try { return await res.json(); } catch { return {}; } };
const rnd = () => 'u' + Math.random().toString(36).slice(2, 8);

const post = (path, body, token) => fetch(BASE + path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
  body: JSON.stringify(body),
});

(async () => {
  console.log('Testing:', BASE, '\n');

  // 1. health
  try {
    const h = await j(await fetch(BASE + '/health'));
    ok('health endpoint up', h.success === true);
  } catch (e) {
    ok('health endpoint up', false, 'server not reachable — is it running?');
    console.log('\nStop: server unreachable at ' + BASE);
    process.exit(1);
  }

  // 2. register A (no email/phone) → token + recovery phrase
  const aName = rnd();
  const regA = await j(await post('/auth/register', { username: aName, password: 'secret123' }));
  const aToken = regA?.data?.token;
  const aId = regA?.data?.user?.id;
  const aPhrase = regA?.data?.recovery_phrase;
  ok('register A succeeds with username only', regA.success === true);
  ok('register A returns a JWT', !!aToken);
  ok('register A returns a 12-word recovery phrase',
    typeof aPhrase === 'string' && aPhrase.trim().split(/\s+/).length === 12, aPhrase);

  // 3. register B
  const bName = rnd();
  const regB = await j(await post('/auth/register', { username: bName, password: 'secret123' }));
  const bToken = regB?.data?.token;
  ok('register B succeeds', regB.success === true && !!bToken);

  // 4. login A
  const logA = await j(await post('/auth/login', { username: aName, password: 'secret123' }));
  ok('login A with password works (bcrypt)', logA.success === true && !!logA?.data?.token);

  // 5. write WITHOUT token → blocked
  const noAuth = await post('/posts', { content: 'hack' });
  ok('POST /posts without token is rejected (401)', noAuth.status === 401);

  // 6. write WITH token → actor comes from token, not body
  const made = await j(await post('/posts', { content: 'hello from A', user_id: 'SOMEONE-ELSE' }, aToken));
  ok('POST /posts with token succeeds', made.success === true);
  ok('post author = token user (body user_id ignored)', made?.data?.user_id === aId,
    `got ${made?.data?.user_id}`);

  // 7. B tries to edit A's profile → forbidden
  const cross = await post(`/users/${aId}/update`, { username: aName, bio: 'pwned' }, bToken);
  ok('B cannot update A\'s profile (403)', cross.status === 403);

  // 8. recover A with the phrase → new password
  const rec = await j(await post('/auth/recover', { username: aName, phrase: aPhrase, new_password: 'newpass456' }));
  ok('recover A with recovery phrase works', rec.success === true && !!rec?.data?.token);

  // 9. wrong phrase → blocked
  const recBad = await j(await post('/auth/recover', { username: aName, phrase: 'wrong words here', new_password: 'x123456' }));
  ok('recover with wrong phrase is rejected', recBad.success === false);

  // 10. login with new password
  const logNew = await j(await post('/auth/login', { username: aName, password: 'newpass456' }));
  ok('login A with the new password works', logNew.success === true);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
