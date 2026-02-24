const sqlite3 = require('sqlite3').verbose();

let db = new sqlite3.Database('./data.sqlite', (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log('Connected to the database.');
});

// Delete old table if it exists
db.run(`DROP TABLE IF EXISTS users`, (err) => {
  if (err) {
    return console.error("Error dropping old table:", err.message);
  }
  console.log('Old users table deleted.');

  // Create new table
  db.run(`CREATE TABLE users (
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
  )`, (err) => {
    if (err) {
      return console.error("Error creating table:", err.message);
    }
    console.log('New users table created.');
  });
});

db.close((err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log('Database closed.');
});
