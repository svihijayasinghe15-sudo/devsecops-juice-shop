const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('/juice-shop/data/juiceshop.sqlite');

console.log('=== 1. Testing Vulnerable Concatenation ===');
const maliciousInput = "' OR 1=1--";
const vulnQuery = "SELECT email FROM Users WHERE email = '" + maliciousInput + "'";

db.all(vulnQuery, [], (err, rows) => {
  if (err) {
    console.error('Error:', err.message);
  } else {
    console.log('Vulnerable Query Result (Authentication Bypassed):', rows[0]);
  }

  console.log('\n=== 2. Testing Parameterized / Prepared Query ===');
  const safeQuery = 'SELECT email FROM Users WHERE email = ?';

  db.all(safeQuery, [maliciousInput], (err, rows) => {
    if (err) {
      console.error('Error:', err.message);
    } else {
      console.log('Safe Query Result (Attack Neutralized):', rows.length === 0 ? 'No user found (401 Unauthorized)' : rows);
    }
    db.close();
  });
});
