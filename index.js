let crypto = require('./crypto')

function isPasscode (x) {
  return typeof x === 'string' && x.length >= 4
}

function prepare (seed, passcode) {
  if (!crypto.isBufferN(seed, 32)) throw new TypeError('Bad seed')
  if (!isPasscode(passcode)) throw new TypeError('Bad passcode')
  return crypto.hmac256(seed, passcode)
}

// XXX: near zero work-factor, suitable for low power devices, assumes cryptographically random seed/pepper
function kdf (seed, pepper, passcode) {
  if (!crypto.isBufferN(seed, 32)) throw new TypeError('Bad seed')
  if (!crypto.isBufferN(pepper, 32)) throw new TypeError('Bad pepper')
  if (!isPasscode(passcode)) throw new TypeError('Bad passcode')
  let key = Buffer.concat([seed, pepper], 64)
  return crypto.hmac256(key, passcode)
}

module.exports = { prepare, kdf }
