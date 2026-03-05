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

// Ensure required tables exist on startup
// so a fresh Railway volume can boot without manual SQL setup.
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

const verificationCodes = new Map(); // email -> { code, expiresAt }

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
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

function verificationMailHtml(code) {
  return `
  <div style="background:#0f0f0f;padding:0;margin:0;font-family:'Segoe UI',Arial,sans-serif;color:#fff">
    <div style="max-width:420px;margin:auto;background:#191919;border-radius:14px;box-shadow:0 8px 38px #0006;overflow:hidden">
      <div style="background:linear-gradient(90deg,#2e0249 0,#57059e 70%,#0f0f0f 100%);padding:32px 0 24px 0;text-align:center">
        <span style="font-size:2.2rem;letter-spacing:0.09em;font-weight:700;color:#fff;display:block;margin-bottom:10px;">Soldora</span>
      </div>

      <div style="padding:32px 24px 24px 24px">
        <div style="font-size:15px;color:#bbb;text-align:center;margin-bottom:12px">Verification de votre adresse e-mail</div>
        <div style="font-size:15px;margin-bottom:30px;text-align:center">
          Voici votre code de verification pour securiser votre compte Soldora :
        </div>
        <div style="font-size:2.3rem;font-weight:bold;letter-spacing:0.2em;text-align:center;background:#181b1e;border-radius:14px;padding:16px 0;color:#19c7ff;margin-bottom:28px;box-shadow:0 2px 18px #57059e20">
          ${code}
        </div>

        <div style="background:#232333;border-radius:12px;padding:14px 12px 10px 12px;color:#b2b2b2;font-size:13px;line-height:1.4;margin-bottom:18px;box-shadow:0 1px 4px #0003;">
          <b>Ajoutez Soldora.fr a vos favoris</b> pour eviter toute tentative de phishing. <br>
          Ne cliquez jamais sur un lien recu par SMS ou e-mail si vous avez le moindre doute.
        </div>

        <div style="text-align:center;margin-bottom:20px;color:#adadad;font-size:13px">
          Pour plus d'informations, consultez <a href="https://soldora.fr" style="color:#19c7ff;text-decoration:underline" target="_blank">notre site officiel</a>.
        </div>

        <div style="border-top:1px solid #222;margin-top:26px;padding-top:10px;color:#707070;font-size:11px;text-align:center">
          <span>Ce code expirera dans 10 minutes. Si vous n'etes pas a l'origine de cette demande, ignorez ce mail.</span>
        </div>
      </div>

      <div style="background:#181b1e;text-align:center;padding:14px 0 12px 0;color:#888;font-size:12px;border-top:1px solid #232333;">
        © 2026 Soldora.fr • <a href="https://soldora.fr" style="color:#19c7ff;text-decoration:none;">Soldora.fr</a>
      </div>
    </div>
  </div>`;
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

async function sendCodeHandler(req, res) {
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

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      return res.status(500).json({ error: 'SMTP non configure' });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    verificationCodes.set(email, { code, expiresAt });

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Votre code de verification',
        html: verificationMailHtml(code)
      });
      console.log(`Code envoye a ${email}`);
      return res.json({ message: 'Code de verification envoye par email', emailSent: true });
    } catch (error) {
      console.error('Erreur lors de l envoi du mail:', error);
      return res.status(500).json({ error: 'Impossible d envoyer le mail' });
    }
  });
}

function verifyCodeHandler(req, res) {
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
}

function registerHandler(req, res) {
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
    [nom, prenom, email, mot_de_passe, adresse, code_postal, ville, pays, code_parrain, telephone, date_naissance],
    function onInsert(err) {
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
}

function loginHandler(req, res) {
  const { email, mot_de_passe } = req.body;

  if (!email || !mot_de_passe) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!user || mot_de_passe !== user.mot_de_passe) {
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
}

app.post(['/api/send-code', '/send-code'], sendCodeHandler);
app.post(['/api/verify-code', '/verify-code'], verifyCodeHandler);
app.post(['/api/register', '/register'], registerHandler);
app.post(['/api/login', '/signin'], loginHandler);

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
    function onInsert(err) {
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
app.listen(PORT, () => console.log(`API demarree sur http://localhost:${PORT}`));
