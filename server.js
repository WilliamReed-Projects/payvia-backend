require('dotenv').config();
const express = require('express');
const cors = require('cors');
const https = require('https');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./data.sqlite');
const app = express();

const allowedOrigins = new Set([
  'https://payvia.fr',
  'https://www.payvia.fr',
  'https://soldora.up.railway.app',
  'https://soldora-backend-backend.up.railway.app'
]);

app.use(cors({
  origin(origin, cb) {
    if (!origin || allowedOrigins.has(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by CORS'));
  }
}));
app.use(express.json());

// Ensure required tables exist on startup.
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT,
    prenom TEXT,
    email TEXT UNIQUE NOT NULL,
    mot_de_passe TEXT NOT NULL,
    adresse TEXT,
    code_postal TEXT,
    ville TEXT,
    pays TEXT,
    code_parrain TEXT,
    telephone TEXT,
    date_naissance TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS temoignages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    date_achat TEXT,
    montant REAL,
    produit TEXT NOT NULL,
    commentaire TEXT NOT NULL,
    note INTEGER NOT NULL,
    statut TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Temporary in-memory storage of verification codes: email -> { code, expiresAt }
const verificationCodes = new Map();

// Setup nodemailer transporter with Gmail SMTP
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (resp) => {
      let data = '';
      resp.on('data', (chunk) => {
        data += chunk;
      });
      resp.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(err);
        }
      });
    }).on('error', reject);
  });
}

function cryptoToCoinGeckoId(code) {
  const key = String(code || '').toUpperCase();
  const map = {
    BTC: 'bitcoin',
    ETH: 'ethereum',
    LTC: 'litecoin',
    TRX: 'tron',
    BNB: 'binancecoin',
    SOL: 'solana',
    USDT: 'tether',
    'USDT-ERC20': 'tether',
    'USDT-TRC20': 'tether'
  };
  return map[key] || null;
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/send-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requis' });

  db.get(`SELECT id FROM users WHERE email = ?`, [email], async (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    if (row) {
      return res.status(409).json({ error: 'Cet email est deja enregistre' });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    verificationCodes.set(email, { code, expiresAt });

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.warn('SMTP non configure, mode debug code actif.');
      return res.json({
        message: 'Code genere (email non envoye)',
        emailSent: false,
        debugCode: code
      });
    }

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Votre code de vérification',
        text: `Votre code est : ${code}. Il expire dans 10 minutes.`
      });
      console.log(`Code envoyé à ${email} : ${code}`);
      res.json({ message: 'Code de verification envoye par email', emailSent: true });
    } catch (error) {
      console.error('Erreur lors de l\'envoi du mail:', error);
      return res.json({
        message: 'Code genere (email non envoye)',
        emailSent: false,
        debugCode: code
      });
    }
  });
});

app.post('/api/verify-code', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: 'Email et code requis' });
  }

  const entry = verificationCodes.get(email);
  if (!entry) {
    return res.status(404).json({ success: false, message: 'Code non trouve ou expire' });
  }

  const isValid = entry.code === code && entry.expiresAt > Date.now();
  if (!isValid) {
    return res.status(401).json({ success: false, message: 'Code invalide ou expire' });
  }

  verificationCodes.delete(email);
  const token = jwt.sign(
    { email },
    process.env.JWT_SECRET || 'your_jwt_secret_key',
    { expiresIn: '1h' }
  );

  return res.json({ success: true, message: 'Code valide avec succes', token });
});

app.post('/api/register', (req, res) => {
  const {
    nom,
    prenom,
    email,
    mot_de_passe,
    adresse,
    code_postal,
    ville,
    pays,
    code_parrain,
    telephone,
    date_naissance
  } = req.body;

  if (!email || !mot_de_passe) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const query = `
    INSERT INTO users 
    (nom, prenom, email, mot_de_passe, adresse, code_postal, ville, pays, code_parrain, telephone, date_naissance)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(
    query,
    [
      nom,
      prenom,
      email,
      mot_de_passe,
      adresse,
      code_postal,
      ville,
      pays,
      code_parrain,
      telephone,
      date_naissance
    ],
    function (err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'User with this email already exists' });
        }
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to register user' });
      }

      return res.status(201).json({
        message: 'User registered successfully',
        userId: this.lastID
      });
    }
  );
});

app.post('/api/login', (req, res) => {
  const { email, mot_de_passe } = req.body;

  if (!email || !mot_de_passe) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const query = `SELECT * FROM users WHERE email = ?`;

  db.get(query, [email], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (mot_de_passe !== user.mot_de_passe) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '1h' }
    );

    return res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        nom: user.nom,
        prenom: user.prenom,
        email: user.email
      }
    });
  });
});

app.post('/api/temoignage', (req, res) => {
  const { nom, prenom, date_achat, montant, produit, commentaire, note } = req.body;

  if (!nom || !prenom || !produit || !commentaire || !note) {
    return res.status(400).json({ error: 'Champs temoignage manquants' });
  }

  const safeMontant = montant ? Number(montant) : null;
  const safeNote = Number(note);
  if (!Number.isInteger(safeNote) || safeNote < 1 || safeNote > 5) {
    return res.status(400).json({ error: 'Note invalide (1-5)' });
  }

  db.run(
    `INSERT INTO temoignages (nom, prenom, date_achat, montant, produit, commentaire, note, statut)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
    [nom, prenom, date_achat || null, Number.isFinite(safeMontant) ? safeMontant : null, produit, commentaire, safeNote],
    function (err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Impossible d enregistrer le temoignage' });
      }
      return res.status(201).json({ success: true, id: this.lastID });
    }
  );
});

app.get('/api/temoignages-valides', (_req, res) => {
  db.all(
    `SELECT nom, prenom, produit, commentaire, note, created_at
     FROM temoignages
     WHERE statut = 'valide'
     ORDER BY created_at DESC
     LIMIT 50`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Impossible de recuperer les temoignages' });
      }
      return res.json(rows || []);
    }
  );
});

app.get('/api/crypto-price', async (req, res) => {
  const { crypto } = req.query;
  const coinId = cryptoToCoinGeckoId(crypto);
  if (!coinId) {
    return res.status(400).json({ error: 'Crypto non supportee' });
  }

  const url = `https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(coinId)}&vs_currencies=eur`;
  try {
    const data = await httpGetJson(url);
    const price = data && data[coinId] && data[coinId].eur;
    if (!price) {
      return res.status(502).json({ error: 'Prix indisponible' });
    }
    return res.json({ crypto: String(crypto || '').toUpperCase(), price });
  } catch (err) {
    console.error('Crypto API error:', err);
    return res.status(502).json({ error: 'Prix indisponible' });
  }
});

app.post('/api/send-pending-payment-mail', async (req, res) => {
  const { email, commandeNum, total, cryptoName, cryptoCode } = req.body || {};
  if (!email || !commandeNum || !total) {
    return res.status(400).json({ error: 'Champs manquants' });
  }

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return res.status(500).json({ error: 'SMTP non configure' });
  }

  const subject = `Paiement en attente - commande ${commandeNum}`;
  const text = [
    'Votre commande est en attente de validation.',
    `Commande: ${commandeNum}`,
    `Montant: ${total} EUR`,
    `Crypto: ${cryptoName || cryptoCode || 'N/A'}`
  ].join('\n');

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject,
      text
    });
    return res.json({ success: true });
  } catch (err) {
    console.error('Mail error:', err);
    return res.status(500).json({ error: 'Envoi email impossible' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`API démarrée sur http://localhost:${PORT}`));
