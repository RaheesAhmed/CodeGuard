/**
 * Example vulnerable code for testing SecurityGuard MCP
 */

// SQL Injection vulnerability
function getUserById(userId) {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.execute(query);
}

// XSS vulnerability
function displayUserComment(comment) {
  document.getElementById('comments').innerHTML = comment;
}

// Exposed secrets
const API_KEY = "sk_live_51H7xY2eZvKYlo2C8Nz9Zq3aB4cD5eF6gH7iJ8k";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const DB_PASSWORD = "MySecretPassword123!";

// Command injection
function runCommand(userInput) {
  const { exec } = require('child_process');
  exec(`ls -la ${userInput}`, (error, stdout) => {
    console.log(stdout);
  });
}

// Weak cryptography
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// Insecure random
const token = Math.random().toString(36).substring(7);

// Path traversal
function readFile(filename) {
  const fs = require('fs');
  return fs.readFileSync(`./uploads/${filename}`, 'utf8');
}

// Hardcoded credentials
const databaseConfig = {
  host: 'localhost',
  user: 'admin',
  password: 'admin123',
  database: 'production'
};

// CORS misconfiguration
app.use(cors({
  origin: '*',
  credentials: true
}));

// Missing authentication
app.get('/admin/users', (req, res) => {
  const users = db.query('SELECT * FROM users');
  res.json(users);
});

// Logging sensitive data
logger.info('User login', { 
  username: user.username, 
  password: user.password // Never log passwords!
});

// GDPR violation - collecting email without consent
app.post('/newsletter', (req, res) => {
  const email = req.body.email;
  db.emails.insert({ email });
  res.json({ success: true });
});

// PCI DSS violation - storing CVV
app.post('/payment', (req, res) => {
  const payment = {
    cardNumber: req.body.cardNumber,
    cvv: req.body.cvv, // NEVER store CVV!
    expiryDate: req.body.expiry
  };
  db.payments.insert(payment);
});