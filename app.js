const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const users = new Map();
const identities = new Map();
const userCredentials = new Map();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Utility functions
const generateKeyPair = () => {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
};

const validateRequest = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  };
};

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/create-identity', validateRequest([
  body('username').trim().isString().notEmpty(),
  body('password').isString().isLength({ min: 6 })
]), async (req, res) => {
  const { username, password } = req.body;

  if (users.has(username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const did = 'did:akjgmw:' + crypto.randomBytes(16).toString('hex');
  const keypair = generateKeyPair();

  users.set(username, { password, did, keypair });
  identities.set(did, {
    owner: username,
    publicKey: keypair.publicKey,
    credentials: []
  });

  res.json({ did, message: 'Identity created successfully' });
});

app.post('/login', validateRequest([
  body('username').trim().isString(),
  body('password').isString()
]), async (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);

  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username, did: user.did }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, did: user.did });
});

app.get('/user-credentials', authenticateToken, (req, res) => {
  const identity = identities.get(req.user.did);
  if (!identity) {
    return res.status(404).json({ error: 'Identity not found' });
  }
  res.json({ credentials: identity.credentials });
});

app.post('/issue-credential', authenticateToken, validateRequest([
  body('type').trim().isString(),
  body('data').isObject()
]), async (req, res) => {
  const { type, data } = req.body;

  // Check if user already has this type of credential
  const identity = identities.get(req.user.did);
  if (identity.credentials.some(c => c.type === type)) {
    return res.status(400).json({ error: `User already has a ${type} credential` });
  }

  const credential = {
    id: crypto.randomBytes(16).toString('hex'),
    type,
    issuer: req.user.did,
    issuanceDate: new Date().toISOString(),
    data,
    proof: {
      type: 'RsaSignature2018',
      created: new Date().toISOString(),
      verificationMethod: req.user.did
    }
  };

  const user = users.get(req.user.username);
  const signature = crypto.sign(
    'sha256',
    Buffer.from(JSON.stringify(credential)),
    user.keypair.privateKey
  );

  credential.proof.signature = signature.toString('base64');
  identity.credentials.push(credential);

  res.json(credential);
});

app.post('/verify-credential', validateRequest([
  body('credentialId').trim().isString()
]), async (req, res) => {
  const { credentialId } = req.body;
  let foundCredential;

  for (let [, identity] of identities) {
    foundCredential = identity.credentials.find(c => c.id === credentialId);
    if (foundCredential) break;
  }

  if (!foundCredential) {
    return res.status(404).json({ error: 'Credential not found' });
  }

  const issuerIdentity = identities.get(foundCredential.issuer);
  const credentialWithoutSignature = {
    ...foundCredential,
    proof: { ...foundCredential.proof, signature: undefined }
  };

  const verified = crypto.verify(
    'sha256',
    Buffer.from(JSON.stringify(credentialWithoutSignature)),
    issuerIdentity.publicKey,
    Buffer.from(foundCredential.proof.signature, 'base64')
  );

  res.json({ verified, credential: foundCredential });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
