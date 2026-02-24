require('dotenv').config();
const express = require('express');
const cors = require('cors');  
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./data.sqlite');
const app = express();
app.use(cors());   
app.use(express.json());

// Temporary in-memory storage of verification codes
const verificationCodes = new Map(); // email -> { code, expiresAt }

// Setup nodemailer transporter with Gmail SMTP
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,  // from .env
    pass: process.env.EMAIL_PASS   // from .env
  }
});

// POST /api/send-code
app.post('/api/send-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email requis" });

  // ✅ Check if email already registered
  db.get(`SELECT id FROM users WHERE email = ?`, [email], async (err, row) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Server error" });
    }
    if (row) {
      // Email exists -> return error
      return res.status(409).json({ error: "Cet email est déjà enregistré" });
    }

    // ✅ If not registered, continue sending code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // expires in 10 min

    verificationCodes.set(email, { code, expiresAt });

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Votre code de vérification',
        text: `Votre code est : ${code}. Il expire dans 10 minutes.`
      });
      console.log(`Code envoyé à ${email} : ${code}`);
      res.json({ message: "Code de vérification envoyé par email" });
    } catch (error) {
      console.error('Erreur lors de l\'envoi du mail:', error);
      res.status(500).json({ error: "Impossible d'envoyer le mail" });
    }
  });
});

// POST /api/verify-code
app.post('/api/verify-code', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: "Email et code requis" });
  }

  const entry = verificationCodes.get(email);

  if (!entry) {
    return res.status(404).json({ success: false, message: "Code non trouvé ou expiré" });
  }

  const isValid = entry.code === code && entry.expiresAt > Date.now();

  if (!isValid) {
    return res.status(401).json({ success: false, message: "Code invalide ou expiré" });
  }

  // Code is valid — consume it
  verificationCodes.delete(email);

  // Generate JWT token
  const token = jwt.sign(
    { email }, 
    process.env.JWT_SECRET || 'your_jwt_secret_key', 
    { expiresIn: '1h' }
  );

  return res.json({ success: true, message: "Code validé avec succès", token });
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

  // Basic validation
  if (!email || !mot_de_passe) {
    return res.status(400).json({ error: "Email and password are required" });
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
          return res.status(409).json({ error: "User with this email already exists" });
        }
        console.error("Database error:", err);
        return res.status(500).json({ error: "Failed to register user" });
      }

      return res.status(201).json({
        message: "User registered successfully",
        userId: this.lastID
      });
    }
  );
});


app.post('/api/login', (req, res) => {
  const { email, mot_de_passe } = req.body;

  if (!email || !mot_de_passe) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const query = `SELECT * FROM users WHERE email = ?`;

  db.get(query, [email], (err, user) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    if (mot_de_passe !== user.mot_de_passe) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '1h' }
    );

    return res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        nom: user.nom,
        prenom: user.prenom,
        email: user.email
        // never send mot_de_passe back
      }
    });
  });
});




const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API démarrée sur http://localhost:${PORT}`));
