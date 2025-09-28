// auth-bcrypt.js
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 12; // You can change this if needed

/**
 * Hash a password with bcrypt
 * @param {string} password
 * @returns {Promise<string>} hashed password
 */
async function hashPassword(password) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('Password must be a non-empty string');
  }
  return bcrypt.hash(password, SALT_ROUNDS);
}
hashPassword('admin').then(hash => {
  console.log(hash);
});
/**
 * Verify password against stored hash
 * @param {string} password
 * @param {string} storedHash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(password, storedHash) {
  if (typeof password !== 'string' || typeof storedHash !== 'string') {
    throw new TypeError('Invalid arguments');
  }
  return bcrypt.compare(password, storedHash);
}

module.exports = { hashPassword, verifyPassword };
