let user = require('../')
let server = require('../server')

let ncrypto = require('crypto')
let randombytes = require('randombytes')
let tape = require('tape')

function memdb () {
  let memory = {}
  function query (hI, callback) {
    if (hI in memory) return callback(null, memory[hI])
    callback(null, 0)
  }
  function limit (hI, limit, callback) {
    if (limit === 0) {
      delete memory[hI]
    } else {
      memory[hI] = limit
    }
    callback()
  }
  function _count () { return Object.keys(memory).length }
  function _limitOf (I) {
    let hI = ncrypto.createHash('sha256').update(I).digest()
    return memory[hI]
  }
  return { query, limit, _count, _limitOf }
}

tape.test('protocol is OK', (t) => {
  let db = memdb()
  let e = randombytes(32)
  let seed = randombytes(32)

  // commitment
  let P1 = user.prepare(seed, '1234')
  let { commitment, pepper: pepper1 } = server.commit(e, P1)

  // request/respond
  let P2 = user.prepare(seed, '1234')
  server.get(e, commitment, P2, db.query, db.limit, (err, result) => {
    t.ifErr(err)
    t.ok(result)
    t.equal(db._count(), 0)

    let { attempts, pepper: pepper2 } = result
    t.equal(attempts, 0)
    t.same(pepper1, pepper2)

    t.end()
  })
})

tape.test('protocol limits attackers', (t) => {
  let db = memdb()
  let e = randombytes(32)
  let seed = randombytes(32)

  // commitment
  let P = user.prepare(seed, '1234')
  let { commitment } = server.commit(e, P)

  // request/respond
  let I = commitment.slice(0, 32)

  t.equal(db._count(), 0)
  for (let i = 0; i < 10; ++i) {
    let aP = user.prepare(seed, '001' + i)

    if (i < 5) {
      t.equal(db._limitOf(I) || 0, i, 'limit matches i')
    } else {
      t.equal(db._limitOf(I), 5, 'limit reached, matches limit')
    }

    server.get(e, commitment, aP, db.query, db.limit, (err, result) => {
      t.ifErr(err)
      t.equal(db._count(), 1)
      if (i < 5) {
        t.equal(db._limitOf(I), i + 1, 'limit incremented')
        t.same(result, {
          attempts: i + 1,
          limited: false
        })
      } else {
        t.equal(db._limitOf(I), 5, 'limit reached')
        t.same(result, { limited: true })
      }
    })
  }

  // denial of service, even with a valid commitment
  server.get(e, commitment, P, db.query, db.limit, (err, result) => {
    t.ifErr(err)
    t.equal(db._count(), 1)
    t.equal(db._limitOf(I), 5)
    t.same(result, { limited: true })
    t.end()
  })
})

tape.test('protocol limits attackers, but resets on success', (t) => {
  let db = memdb()
  let e = randombytes(32)
  let seed = randombytes(32)

  // commitment
  let P = user.prepare(seed, '1234')
  let { commitment, pepper: pepper1 } = server.commit(e, P)

  // attack
  let I = commitment.slice(0, 32)
  let aP = user.prepare(seed, '0099') // attacker
  t.equal(db._count(), 0)
  t.equal(db._limitOf(I), undefined)
  server.get(e, commitment, aP, db.query, db.limit, () => {})
  server.get(e, commitment, aP, db.query, db.limit, () => {})
  server.get(e, commitment, aP, db.query, db.limit, () => {})
  server.get(e, commitment, aP, db.query, db.limit, () => {})
  t.equal(db._count(I), 1)
  t.equal(db._limitOf(I), 4)

  // !(attempts > 5), therefore valid commitment resets
  server.get(e, commitment, P, db.query, db.limit, (err, result) => {
    t.ifErr(err)
    t.equal(db._count(), 0)
    t.equal(db._limitOf(I), undefined)
    t.same(result, {
      attempts: 4,
      pepper: pepper1
    })
    t.end()
  })
})

tape.test('commit is non deterministic', (t) => {
  let e = randombytes(32)
  let P = randombytes(32)

  let history = {}
  for (let i = 0; i < 500; ++i) {
    let { commitment, pepper } = server.commit(e, P)
    let I = commitment.slice(0, 32).toString('hex')
    let verify = commitment.slice(32).toString('hex')
    commitment = commitment.toString('hex')
    pepper = pepper.toString('hex')

    t.notOk(history[I], 'I is unique')
    t.notOk(history[verify], 'verify is unique')
    t.notOk(history[commitment], 'commitment is unique')
    t.notOk(history[pepper], 'pepper is unique')
    history[I] = true
    history[verify] = true
    history[commitment] = true
    history[pepper] = true
  }

  t.end()
})
