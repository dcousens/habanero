let user = require('../')
let server = require('../server')

let crypto = require('../crypto')
let randombytes = require('randombytes')
let tape = require('tape')

function memdb () {
  let memory = {}
  function _h (I) {
    return crypto.hmac256('mem', I).toString('hex')
  }
  function query (I, callback) {
    let Ih = _h(I)
    if (Ih in memory) return callback(null, memory[Ih])
    callback(null, 0)
  }
  function limit (I, limit, callback) {
    let Ih = _h(I)
    if (limit === 0) {
      delete memory[Ih]
    } else {
      memory[Ih] = limit
    }
    callback()
  }
  function _count () { return Object.keys(memory).length }
  function _limitOf (I) { return memory[_h(I)] }
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
      } else {
        t.equal(db._limitOf(I), 5, 'limit reached')
      }
      t.notOk(result)
    })
  }

  // denial of service, even with a valid commitment
  server.get(e, commitment, P, db.query, db.limit, (err, result) => {
    t.ifErr(err)
    t.equal(db._count(), 1)
    t.equal(db._limitOf(I), 5)
    t.notOk(result)
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

tape.test('commit is not deterministic', (t) => {
  let e = randombytes(32)
  let P = randombytes(32)
  let results = []
  for (let i = 0; i < 100; ++i) {
    results.push(server.commit(e, P))
  }

  // O(n^2)
  results.forEach((x, i) => {
    results.forEach((y, j) => {
      if (i === j) return

      t.notSame(x.commitment, y.commitment)
      t.notSame(x.pepper, y.pepper)

      // deeper introspection of I/verify values
      t.notSame(x.commitment.slice(0, 32), y.commitment.slice(0, 32))
      t.notSame(x.commitment.slice(32), y.commitment.slice(32))
    })
  })

  t.end()
})
