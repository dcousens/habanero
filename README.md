# habanero
[![build status](https://secure.travis-ci.org/dcousens/habanero.png)](http://travis-ci.org/dcousens/habanero)
[![NPM](https://img.shields.io/npm/v/habanero.svg)](https://www.npmjs.org/package/habanero)

An attempt-limiting, remote pepper provisioning protocol with a bundled Javascript implementation.


## [Protocol](PROTOCOL.md)

## Example
``` javascript
```

``` javascript
let hb = require('habanero/server')
let e = Buffer.from(process.env.HABANERO_SECRET, 'ascii')

// ...
hb.get(e, commitment, P, queryCb, limitCb, (err, result) => {
	if (err) return res.status(500).end()
	if (result.limited) return res.status(403).end() // optional (information leak)
	if (!result.pepper) return res.status(401).end()

	res.status(200).json(result)
})
```

## LICENSE [LGPLv3](LICENSE)
