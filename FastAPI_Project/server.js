/*
 * Mandi Mitra local server
 *
 * This intentionally uses only Node's standard library so the project can run
 * on a fresh machine without Python, MongoDB, or an npm install.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { randomBytes, pbkdf2Sync, timingSafeEqual } = require('crypto');

const PORT = Number(process.env.PORT) || 8000;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'mandi-mitra-data.json');

function emptyData() {
  return { users: [], products: [], messages: [], order_requests: [], sessions: [] };
}

function starterData() {
  const farmers = [
    { _id: id(), name: 'Lakshmi Farms', email: 'lakshmi@mandi.local', phone: '9000000001', role: 'farmer', city: 'Rangareddy', state: 'Telangana' },
    { _id: id(), name: 'Green Valley Dairy', email: 'greenvalley@mandi.local', phone: '9000000002', role: 'farmer', city: 'Medchal', state: 'Telangana' },
    { _id: id(), name: 'Sunrise Orchards', email: 'sunrise@mandi.local', phone: '9000000003', role: 'farmer', city: 'Vikarabad', state: 'Telangana' },
  ];
  const [lakshmi, dairy, orchards] = farmers;
  const product = (farmer, name, description, quantity, unit, price, ready_by) => ({
    _id: id(), farmer_id: farmer._id, farmer_name: farmer.name, name, description,
    quantity, unit, price, ready_by, status: 'active',
  });
  return {
    users: farmers,
    products: [
      product(lakshmi, 'Tomatoes', 'Fresh red tomatoes, picked this morning.', 35, 'kg', 32, '2026-09-16'),
      product(lakshmi, 'Potatoes', 'Clean, firm farm potatoes for everyday cooking.', 50, 'kg', 28, '2026-09-16'),
      product(lakshmi, 'Carrots', 'Sweet orange carrots, naturally grown.', 20, 'kg', 45, '2026-09-17'),
      product(lakshmi, 'Spinach', 'Fresh leafy spinach bunches.', 18, 'bag', 25, '2026-09-16'),
      product(orchards, 'Bananas', 'Naturally ripened yellow bananas.', 12, 'dozen', 55, '2026-09-16'),
      product(orchards, 'Mangoes', 'Seasonal sweet mangoes from the orchard.', 25, 'kg', 90, '2026-09-18'),
      product(orchards, 'Guavas', 'Juicy, vitamin-rich guavas.', 16, 'kg', 65, '2026-09-17'),
      product(dairy, 'Fresh Cow Milk', 'Pure chilled cow milk, delivered fresh daily.', 30, 'bag', 60, '2026-09-16'),
      product(dairy, 'Homemade Curd', 'Thick, fresh-set curd with no additives.', 15, 'kg', 85, '2026-09-16'),
      product(dairy, 'Paneer', 'Soft, fresh paneer made from full-cream milk.', 10, 'kg', 380, '2026-09-17'),
      product(dairy, 'Desi Ghee', 'Traditional aromatic ghee, small-batch prepared.', 8, 'kg', 720, '2026-09-17'),
    ],
    messages: [],
    sessions: [],
  };
}

function loadData() {
  try {
    const saved = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return {
      users: Array.isArray(saved.users) ? saved.users : [],
      products: Array.isArray(saved.products) ? saved.products : [],
      messages: Array.isArray(saved.messages) ? saved.messages : [],
      order_requests: Array.isArray(saved.order_requests) ? saved.order_requests : [],
      sessions: Array.isArray(saved.sessions) ? saved.sessions : [],
    };
  } catch (error) {
    return starterData();
  }
}

let data = loadData();

function saveData() {
  fs.writeFileSync(DATA_FILE, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

// Persist the first-run catalog so its listings and seller IDs stay stable
// across restarts.
if (!fs.existsSync(DATA_FILE)) saveData();

function id() {
  // 24 hexadecimal characters, matching MongoDB ObjectId-shaped IDs expected
  // by the existing frontend.
  return randomBytes(12).toString('hex');
}

function send(response, status, body, headers = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  response.end(JSON.stringify(body));
}

function notFound(response, detail = 'Not found') {
  return send(response, 404, { detail });
}

function validPhone(phone) {
  return typeof phone === 'string' && /^\d{10}$/.test(phone);
}

function validPin(pin) {
  return typeof pin === 'string' && /^\d{4,6}$/.test(pin);
}

function hashPin(pin, salt) {
  // A PIN is never saved in plain text.  The salt makes identical PINs hash
  // differently, and the work factor slows down password-guessing attempts.
  return pbkdf2Sync(pin, salt, 310000, 32, 'sha256').toString('hex');
}

function savePin(user, pin) {
  // Keep only the hash and salt in the JSON data file; remove a PIN left by
  // an older development build before writing the account back to disk.
  const salt = randomBytes(16).toString('hex');
  user.pin_salt = salt;
  user.pin_hash = hashPin(pin, salt);
  delete user.pin;
}

function publicUser(user) {
  // API responses must never expose any credential fields to the browser.
  const { pin, pin_salt, pin_hash, ...account } = user;
  return account;
}

function orderUserSnapshot(user, userId, fallbackName = '') {
  const account = user ? publicUser(user) : { _id: userId, name: fallbackName };
  const fields = ['_id', 'name', 'email', 'phone', 'role', 'address', 'street', 'village', 'city', 'district', 'state', 'postal_code', 'zip'];
  return Object.fromEntries(fields.filter(field => account[field] !== undefined && account[field] !== null)
    .map(field => [field, account[field]]));
}

const captchaStore = new Map();

function createCaptchaChallenge() {
  const first = Math.floor(Math.random() * 9) + 2;
  const second = Math.floor(Math.random() * 9) + 2;
  const answer = first + second;
  const token = randomBytes(16).toString('hex');
  captchaStore.set(token, { answer, expires_at: Date.now() + 5 * 60 * 1000 });
  return { token, question: `What is ${first} + ${second}?` };
}

function validateCaptcha(token, answer) {
  const challenge = captchaStore.get(token);
  if (!challenge || challenge.expires_at < Date.now()) {
    captchaStore.delete(token);
    return false;
  }
  const isValid = Number(answer) === Number(challenge.answer);
  if (isValid) captchaStore.delete(token);
  return isValid;
}

function createSession(user) {
  const token = randomBytes(32).toString('hex');
  data.sessions.push({
    token,
    user_id: user._id,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  });
  saveData();
  return token;
}

function requireAuth(request, response) {
  const authorization = request.headers.authorization || '';
  if (!authorization.startsWith('Bearer ')) {
    send(response, 401, { detail: 'Authentication required' });
    return null;
  }
  const token = authorization.slice(7).trim();
  const session = data.sessions.find(item => item.token === token && new Date(item.expires_at).getTime() > Date.now());
  if (!session) {
    send(response, 401, { detail: 'Authentication required or session expired' });
    return null;
  }
  const user = data.users.find(item => item._id === session.user_id);
  if (!user) {
    send(response, 401, { detail: 'Authentication required or session expired' });
    return null;
  }
  return user;
}

function validUser(user) {
  return user && typeof user.name === 'string' && typeof user.email === 'string'
    && validPhone(user.phone) && ['farmer', 'buyer'].includes(user.role)
    && typeof user.city === 'string' && typeof user.state === 'string';
}

function validProduct(product) {
  return product && typeof product.farmer_id === 'string'
    && typeof product.farmer_name === 'string' && typeof product.name === 'string'
    && typeof product.description === 'string' && Number.isFinite(product.quantity)
    && typeof product.unit === 'string' && Number.isFinite(product.price)
    && typeof product.ready_by === 'string' && ['active', 'sold'].includes(product.status);
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let raw = '';
    request.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1_000_000) request.destroy();
    });
    request.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(new Error('Request body must be valid JSON')); }
    });
    request.on('error', reject);
  });
}

function withCors(response) {
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

async function handleApi(request, response, url) {
  const { method } = request;
  const segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);

  if (method === 'OPTIONS') return response.end();
  if (method === 'GET' && url.pathname === '/api/health') {
    return send(response, 200, { message: 'Mandi Mitra API is working!' });
  }

  if (method === 'GET' && url.pathname === '/farmers') {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    return send(response, 200, data.users.map(publicUser));
  }
  if (method === 'GET' && url.pathname === '/users') {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    return send(response, 200, data.users.map(publicUser));
  }
  if (method === 'GET' && segments[0] === 'farmers' && segments[1] === 'by-phone' && segments[2]) {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const user = data.users.find(item => item.phone === segments[2]);
    return user ? send(response, 200, publicUser(user)) : notFound(response, 'Farmer not found');
  }
  if (method === 'GET' && url.pathname === '/auth/captcha') {
    return send(response, 200, createCaptchaChallenge());
  }
  if (method === 'POST' && url.pathname === '/auth/login') {
    const credentials = await readJson(request);
    if (!validPhone(credentials.phone) || !validPin(credentials.pin)) {
      return send(response, 401, { detail: 'Invalid phone number or PIN' });
    }
    if (!credentials.captcha_token || !validateCaptcha(credentials.captcha_token, credentials.captcha_answer)) {
      return send(response, 403, { detail: 'Captcha verification failed' });
    }

    // Look up the account in the same JSON store used by signup, so a restart
    // does not send locally created accounts to a different database.
    const user = data.users.find(item => item.phone === credentials.phone);
    if (!user) return send(response, 401, { detail: 'Invalid phone number or PIN' });

    if (!user.pin_hash || !user.pin_salt) {
      // Accounts created by the earlier server did not retain a PIN.  This
      // one-time local migration lets their owner set the entered PIN so the
      // account is usable again after the authentication fix.
      savePin(user, credentials.pin);
      const token = createSession(user);
      return send(response, 200, { ...publicUser(user), migrated_pin: true, token });
    }

    const expectedHash = Buffer.from(user.pin_hash, 'hex');
    const suppliedHash = Buffer.from(hashPin(credentials.pin, user.pin_salt), 'hex');
    if (expectedHash.length !== suppliedHash.length || !timingSafeEqual(expectedHash, suppliedHash)) {
      return send(response, 401, { detail: 'Invalid phone number or PIN' });
    }
    const token = createSession(user);
    return send(response, 200, { ...publicUser(user), token });
  }
  if (method === 'POST' && url.pathname === '/auth/reset-pin') {
    const credentials = await readJson(request);
    if (!validPhone(credentials.phone) || !validPin(credentials.pin)) {
      return send(response, 422, { detail: 'Enter a valid phone number and a 4-6 digit PIN' });
    }
    if (!credentials.captcha_token || !validateCaptcha(credentials.captcha_token, credentials.captcha_answer)) {
      return send(response, 403, { detail: 'Captcha verification failed' });
    }
    const user = data.users.find(item => item.phone === credentials.phone);
    if (!user) return send(response, 404, { detail: 'No account found for this phone number' });

    // This local app has no email or SMS provider, so phone ownership is the
    // recovery check and the replacement PIN is stored in the same safe form.
    savePin(user, credentials.pin);
    saveData();
    return send(response, 200, { message: 'PIN reset successfully' });
  }
  if (method === 'POST' && url.pathname === '/farmers') {
    const user = await readJson(request);
    if (!validUser(user) || !validPin(user.pin)) {
      return send(response, 422, { detail: 'Enter valid account details and a 4-6 digit PIN' });
    }
    if (!user.captcha_token || !validateCaptcha(user.captcha_token, user.captcha_answer)) {
      return send(response, 403, { detail: 'Captcha verification failed' });
    }
    if (data.users.some(item => item.phone === user.phone)) {
      return send(response, 409, { detail: 'An account with this phone already exists' });
    }
    const saved = { ...user, _id: id() };
    delete saved.captcha_token;
    delete saved.captcha_answer;
    savePin(saved, user.pin);
    data.users.push(saved);
    saveData();
    const token = createSession(saved);
    return send(response, 201, { message: 'Farmer added successfully', id: saved._id, token, user: publicUser(saved) });
  }
  if (method === 'PUT' && segments[0] === 'farmers' && segments[1]) {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const user = await readJson(request);
    const index = data.users.findIndex(item => item._id === segments[1]);
    if (index < 0) return notFound(response, 'Farmer not found');
    if (!validUser(user)) return send(response, 422, { detail: 'Invalid account details' });
    if (data.users.some((item, i) => i !== index && item.phone === user.phone)) {
      return send(response, 409, { detail: 'An account with this phone already exists' });
    }
    data.users[index] = { ...user, _id: segments[1] };
    saveData();
    return send(response, 200, { message: 'Farmer updated successfully' });
  }

  if (method === 'GET' && url.pathname === '/products') {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    return send(response, 200, data.products);
  }
  if (method === 'POST' && url.pathname === '/products') {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const product = await readJson(request);
    if (!validProduct(product)) return send(response, 422, { detail: 'Invalid product details' });
    const saved = { ...product, _id: id() };
    data.products.push(saved);
    saveData();
    return send(response, 201, { message: 'Product added successfully', id: saved._id });
  }
  if (method === 'PUT' && segments[0] === 'products' && segments[1]) {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const product = await readJson(request);
    const index = data.products.findIndex(item => item._id === segments[1]);
    if (index < 0) return notFound(response, 'Product not found');
    if (!validProduct(product)) return send(response, 422, { detail: 'Invalid product details' });
    data.products[index] = { ...product, _id: segments[1] };
    saveData();
    return send(response, 200, { message: 'Product updated successfully' });
  }
  if (method === 'DELETE' && segments[0] === 'products' && segments[1]) {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const before = data.products.length;
    data.products = data.products.filter(item => item._id !== segments[1]);
    if (data.products.length === before) return send(response, 200, { message: 'Product not found' });
    saveData();
    return send(response, 200, { message: 'Product deleted successfully' });
  }

  if (method === 'POST' && url.pathname === '/order-requests') {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const requestData = await readJson(request);
    const required = ['buyer_id', 'buyer_name', 'farmer_id', 'farmer_name', 'product_id', 'product_name', 'body'];
    if (!requestData || !required.every(key => typeof requestData[key] === 'string') || !requestData.body.trim()) {
      return send(response, 422, { detail: 'Order request cannot be empty' });
    }
    // Resolve contact details on the server too, so older browser tabs still
    // create requests that give the buyer a reliable way to reach the farmer.
    const farmer = data.users.find(user => user._id === requestData.farmer_id);
    const saved = {
      ...requestData,
      buyer_id: authUser._id,
      buyer_name: authUser.name,
      farmer_phone: requestData.farmer_phone || farmer?.phone || '',
      farmer_email: requestData.farmer_email || farmer?.email || '',
      buyer_user: orderUserSnapshot(authUser, authUser._id, requestData.buyer_name),
      farmer_user: orderUserSnapshot(farmer, requestData.farmer_id, requestData.farmer_name),
      body: requestData.body.trim(),
      status: 'pending',
      reply: '',
      _id: id(),
      created_at: new Date().toISOString(),
      replied_at: '',
    };
    data.order_requests.push(saved);
    saveData();
    return send(response, 201, { message: 'Order request sent', id: saved._id });
  }
  if (method === 'GET' && segments[0] === 'order-requests' && segments[1]) {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const userId = segments[1];
    if (authUser._id !== userId) return send(response, 403, { detail: 'You can only view your own order requests' });
    const requests = data.order_requests.filter(item => item.buyer_id === userId || item.farmer_id === userId)
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
    return send(response, 200, requests);
  }
  if (method === 'PUT' && segments[0] === 'order-requests' && segments[1]) {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const requestData = await readJson(request);
    const requestIndex = data.order_requests.findIndex(item => item._id === segments[1]);
    if (requestIndex < 0) return notFound(response, 'Order request not found');
    if (!requestData || !['accepted', 'declined'].includes(requestData.status)
      || typeof requestData.reply !== 'string' || !requestData.reply.trim()) {
      return send(response, 422, { detail: 'Choose a status and enter a reply' });
    }
    const orderRequest = data.order_requests[requestIndex];
    if (orderRequest.farmer_id !== authUser._id) {
      return send(response, 403, { detail: 'Only the requested farmer can reply' });
    }
    if (orderRequest.status !== 'pending') {
      return send(response, 409, { detail: 'This order request has already been answered' });
    }
    data.order_requests[requestIndex] = {
      ...orderRequest,
      status: requestData.status,
      reply: requestData.reply.trim(),
      replied_at: new Date().toISOString(),
    };
    // The acceptance reply is also the first item in the private chat thread.
    if (requestData.status === 'accepted') {
      data.messages.push({
        sender_id: orderRequest.farmer_id,
        sender_name: orderRequest.farmer_name,
        recipient_id: orderRequest.buyer_id,
        recipient_name: orderRequest.buyer_name,
        body: requestData.reply.trim(),
        product_id: orderRequest.product_id || '',
        order_request_id: orderRequest._id,
        _id: id(),
        created_at: new Date().toISOString(),
      });
    }
    saveData();
    return send(response, 200, {
      message: 'Order request updated',
      conversation_peer_id: orderRequest.buyer_id,
    });
  }

  if (method === 'POST' && url.pathname === '/messages') {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const message = await readJson(request);
    const required = ['sender_id', 'sender_name', 'recipient_id', 'recipient_name', 'body'];
    if (!message || !required.every(key => typeof message[key] === 'string') || !message.body.trim()) {
      return send(response, 422, { detail: 'Message cannot be empty' });
    }
    const saved = { ...message, body: message.body.trim(), product_id: message.product_id || '', _id: id(), created_at: new Date().toISOString() };
    data.messages.push(saved);
    saveData();
    return send(response, 201, { message: 'Message sent', id: saved._id });
  }
  if (method === 'GET' && segments[0] === 'messages' && segments[1]) {
    const authUser = requireAuth(request, response);
    if (!authUser) return;
    const userId = segments[1];
    const peerId = url.searchParams.get('peer_id');
    const messages = data.messages.filter(message => peerId
      ? (message.sender_id === userId && message.recipient_id === peerId)
        || (message.sender_id === peerId && message.recipient_id === userId)
      : message.sender_id === userId || message.recipient_id === userId,
    ).sort((a, b) => a.created_at.localeCompare(b.created_at));
    return send(response, 200, messages);
  }

  return notFound(response);
}

const server = http.createServer(async (request, response) => {
  withCors(response);
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  try {
    if (url.pathname === '/' && request.method === 'GET') {
      const file = path.join(ROOT, 'farmer-marketplace.html');
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return fs.createReadStream(file).pipe(response);
    }
    return await handleApi(request, response, url);
  } catch (error) {
    console.error(error);
    return send(response, 400, { detail: error.message || 'Bad request' });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Mandi Mitra is running at http://127.0.0.1:${PORT}`);
});
