let crypto = require('./crypto')

function isPasscode (x) {
  return typeof x === 'string' && x.length >= 4
}

function prepare (seed, passcode) {
  if (!crypto.isBufferN(seed, 32)) throw new TypeError('Bad seed')
  if (!isPasscode(passcode)) throw new TypeError('Bad passcode')
  return crypto.hmac256(seed, passcode)
}

module.exports = { prepare }
