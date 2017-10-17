let createHmac = require('create-hmac')

function hmac256 (key, data) {
  return createHmac('sha256', key).update(data).digest()
}

function hmac512 (key, data) {
  return createHmac('sha512', key).update(data).digest()
}

function isBufferN (x, length) {
  return Buffer.isBuffer(x) && x.length === length
}

module.exports = { hmac256, hmac512, isBufferN }
