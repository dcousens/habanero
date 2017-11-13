let crypto = require('./crypto')

function isPasscode (x) {
  return typeof x === 'string' && x.length >= 4
}

function prepare (salt, passcode) {
  if (!crypto.isBufferN(salt, 32)) throw new TypeError('Bad salt')
  if (!isPasscode(passcode)) throw new TypeError('Bad passcode')
  return crypto.hmac256(salt, passcode)
}

// XXX: near zero work-factor, assumes cryptographically random salt and pepper
function kdf (salt, pepper, passcode) {
  if (!crypto.isBufferN(salt, 32)) throw new TypeError('Bad salt')
  if (!crypto.isBufferN(pepper, 32)) throw new TypeError('Bad pepper')
  if (!isPasscode(passcode)) throw new TypeError('Bad passcode')
  let key = Buffer.concat([salt, pepper], 64)
  return crypto.hmac256(key, passcode)
}

module.exports = { prepare, kdf }
