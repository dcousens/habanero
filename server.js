let crypto = require('./crypto')
let randomBytes = require('randombytes')

function deriveCommitment (e, I, P) {
  let preimage = Buffer.concat([I, P], 64)
  let K = crypto.hmac512(e, preimage)
  let verify = K.slice(0, 32)
  let pepper = K.slice(32)
  let commitment = Buffer.concat([I, verify], 64)
  return { commitment, pepper }
}

function notarize (e, P) {
  if (!crypto.isBufferN(e, 32)) throw new TypeError('Bad secret')
  if (!crypto.isBufferN(P, 32)) throw new TypeError('Bad hash')

  let I = randomBytes(32)
  return deriveCommitment(e, I, P)
}

function respond (e, _commitment, P, queryCb, banCb, callback) {
  if (!crypto.isBufferN(e, 32)) throw new TypeError('Bad secret')
  if (!crypto.isBufferN(_commitment, 64)) throw new TypeError('Bad commitment')
  if (!crypto.isBufferN(P, 32)) throw new TypeError('Bad hash')

  let I = _commitment.slice(0, 32)

  queryCb(I, (err, attempts) => {
    if (err) return callback(err)
    if (attempts > 5) return callback()

    let { commitment, pepper } = deriveCommitment(e, I, P)
    if (!commitment.equals(_commitment)) return banCb(I, callback)

    callback(null, { attempts, pepper })
  })
}

module.exports = { notarize, respond }
