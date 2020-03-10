const ecurve = require('@lmkdbd/ecurve');
const Point = ecurve.Point;
const BigInteger = require('bigi');
const assert = require('assert');

const hash = require('./hash');
const PublicKey = require('./key_public');
const keyUtils = require('./key_utils');
const createHash = require('create-hash')
const promiseAsync = require('./promise-async')
const curveInfo = require('./curve_info');

module.exports = PrivateKey;

/**
  @typedef {string} wif - https://en.bitcoin.it/wiki/Wallet_import_format
  @typedef {string} pubkey - EOSKey..
  @typedef {ecurve.Point} Point
*/

/**
  @param {BigInteger} d
*/
function PrivateKey(d, curve_name = "secp256k1") {
    if(typeof d === 'string') {
        return PrivateKey.fromString(d)
    } else if(Buffer.isBuffer(d)) {
        return PrivateKey.fromBuffer(d, curve_name)
    } else if(typeof d === 'object' && BigInteger.isBigInteger(d.d)) {
        return PrivateKey(d.d, curve_name)
    }

    if(!BigInteger.isBigInteger(d)) {
        throw new TypeError('Invalid private key')
    }

    /** @return {string} private key like PVT_K1_base58privatekey.. */
    function toString(format = "WIF") {
      var curve_info = curveInfo.getInfoByName(curve_name);
      assert(curve_info.isSupportedFormat(format), "Invalid private format type!")
      if (format === "WIF")
          return toWif()
      else {
          return `PVT_`+ curve_info.info.keyType +`_` + keyUtils.checkEncode(toBuffer(), curve_info.info.keyType)
      }
    }

    /**
        @return  {wif}
    */
    function toWif() {
        var private_key = toBuffer();
        // checksum includes the version
        private_key = Buffer.concat([new Buffer([0x80]), private_key]);
        return keyUtils.checkEncode(private_key, 'sha256x2')
    }

    let public_key;

    /**
        @return {Point}
    */
    function toPublic() {
        if (public_key) {
            // cache
            // S L O W in the browser
            return public_key
        }
        const curve = ecurve.getCurveByName(curve_name);
        const Q = curve.G.multiply(d);
        return public_key = PublicKey.fromPoint(Q, curve_name);
    }

    function toBuffer() {
        return d.toBuffer(32);
    }

    /**
      ECIES
      @arg {string|Object} pubkey wif, PublicKey object
      @return {Buffer} 64 byte shared secret
    */
    function getSharedSecret(public_key, curve_name) {
        public_key = PublicKey(public_key, curve_name)
        let KB = public_key.toUncompressed().toBuffer()
        let KBP = Point.fromAffine(
          curve_name,
          BigInteger.fromBuffer( KB.slice( 1,33 )), // x
          BigInteger.fromBuffer( KB.slice( 33,65 )) // y
        )
        let r = toBuffer()
        let P = KBP.multiply(BigInteger.fromBuffer(r))
        let S = P.affineX.toBuffer({size: 32})
        // SHA512 used in ECIES
        return hash.sha512(S)
    }

    // /** ECIES TODO unit test
    //   @arg {string|Object} pubkey wif, PublicKey object
    //   @return {Buffer} 64 byte shared secret
    // */
    // function getSharedSecret(public_key) {
    //     public_key = PublicKey(public_key).toUncompressed()
    //     var P = public_key.Q.multiply( d );
    //     var S = P.affineX.toBuffer({size: 32});
    //     // ECIES, adds an extra sha512
    //     return hash.sha512(S);
    // }

    /**
      @arg {string} name - child key name.
      @return {PrivateKey}

      @example activePrivate = masterPrivate.getChildKey('owner').getChildKey('active')
      @example activePrivate.getChildKey('mycontract').getChildKey('myperm')
    */
    function getChildKey(name) {
      // console.error('WARNING: getChildKey untested against eosd'); // no eosd impl yet
      const index = createHash('sha256').update(toBuffer()).update(name).digest()
      return PrivateKey(index)
    }

    function toHex() {
        return toBuffer().toString('hex');
    }

    function changeCurveName(name = "secp256k1"){
      curve_name = name
    }

    return {
        d,
        curve_name,
        toWif,
        toString,
        toPublic,
        toBuffer,
        getSharedSecret,
        getChildKey,
        changeCurveName,
    }
}

/** @private */
function parseKey(privateStr) {
  assert.equal(typeof privateStr, 'string', 'privateStr')
  const match = privateStr.match(/^PVT_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)

  if(match === null) {
    // legacy WIF - checksum includes the version
    const versionKey = keyUtils.checkDecode(privateStr, 'sha256x2')
    const version = versionKey.readUInt8(0);
    assert.equal(0x80, version, `Expected version ${0x80}, instead got ${version}`)
    const keyType = 'K1'
    const format = 'WIF'
    const privateKey = PrivateKey.fromBuffer(versionKey.slice(1))
    return {privateKey, format, keyType}
  }

  assert(match.length === 3, 'Expecting private key like: PVT_K1_base58privateKey..')
  const [, keyType, keyString] = match
  var curve_name = curveInfo.getInfoByType(keyType).info.name
  const privateKey = PrivateKey.fromBuffer(keyUtils.checkDecode(keyString, keyType), curve_name)
  return {privateKey, format: 'PVT', keyType}
}

PrivateKey.fromHex = function(hex) {
    return PrivateKey.fromBuffer(new Buffer(hex, 'hex'));
}

PrivateKey.fromBuffer = function(buf, curve_name = "secp256k1") {
    if (!Buffer.isBuffer(buf)) {
        throw new Error("Expecting parameter to be a Buffer type");
    }
    if(buf.length === 33 && buf[32] === 1) {
      // remove compression flag
      buf = buf.slice(0, -1)
    }
    if (32 !== buf.length) {
      throw new Error(`Expecting 32 bytes, instead got ${buf.length}`);
    }
    return PrivateKey(BigInteger.fromBuffer(buf), curve_name);
}

/**
    @arg {string} seed - any length string.  This is private, the same seed
    produces the same private key every time.

    @return {PrivateKey}
*/
PrivateKey.fromSeed = function(seed) { // generate_private_key
    if (!(typeof seed === 'string')) {
        throw new Error('seed must be of type string');
    }
    return PrivateKey.fromBuffer(hash.sha256(seed));
}

/**
  @arg {wif} key
  @return {boolean} true if key is in the Wallet Import Format
*/
PrivateKey.isWif = function(text) {
    try {
        assert(parseKey(text).format === 'WIF')
        return true
    } catch(e) {
        return false
    }
}

/**
  @arg {wif|Buffer|PrivateKey} key
  @return {boolean} true if key is convertable to a private key object.
*/
PrivateKey.isValid = function(key) {
    try {
        PrivateKey(key)
        return true
    } catch(e) {
        return false
    }
}

/** @deprecated */
PrivateKey.fromWif = function(str) {
    console.log('PrivateKey.fromWif is deprecated, please use PrivateKey.fromString');
    return PrivateKey.fromString(str)
}

/**
    @throws {AssertError|Error} parsing key
    @arg {string} privateStr Eosio or Wallet Import Format (wif) -- a secret
*/
PrivateKey.fromString = function(privateStr) {
    return parseKey(privateStr).privateKey
}

/**
  Create a new random private key.

  Call initialize() first to run some self-checking code and gather some CPU
  entropy.

  @arg {number} [cpuEntropyBits = 0] - additional CPU entropy, this already
  happens once so it should not be needed again.

  @return {Promise<PrivateKey>} - random private key
*/
PrivateKey.randomKey = function(cpuEntropyBits = 0) {
  return PrivateKey.initialize().then(() => (
    PrivateKey.fromBuffer(keyUtils.random32ByteBuffer({cpuEntropyBits}))
  ))
}

/**
  @return {Promise<PrivateKey>} for testing, does not require initialize().
*/
PrivateKey.unsafeRandomKey = function() {
  return Promise.resolve(
    PrivateKey.fromBuffer(keyUtils.random32ByteBuffer({safe: false}))
  )
}


let initialized = false, unitTested = false

/**
  Run self-checking code and gather CPU entropy.

  Initialization happens once even if called multiple times.

  @return {Promise}
*/
function initialize() {
  if(initialized) {
    return
  }

  unitTest()
  keyUtils.addEntropy(...keyUtils.cpuEntropy())
  assert(keyUtils.entropyCount() >= 128, 'insufficient entropy')

  initialized = true
}

PrivateKey.initialize = promiseAsync(initialize)

/**
  Unit test basic private and public key functionality.

  @throws {AssertError}
*/
function unitTest() {
  let curve_name = 'secp256k1'
  const pvt = PrivateKey(hash.sha256(''))

  const pvtError = 'key comparison test failed on a known private key'
  assert.equal(pvt.toWif(), '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', pvtError)
  assert.equal(pvt.toString('WIF'), '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', pvtError)
  // assert.equal(pvt.toString(), 'PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd', pvtError)

  const pub = pvt.toPublic(curve_name)
  const pubError = 'pubkey string comparison test failed on a known public key'
  assert.equal(pub.toString('WIF'), 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', pubError)
  // assert.equal(pub.toString(), 'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX', pubError)
  // assert.equal(pub.toStringLegacy(), 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', pubError)

  doesNotThrow(() => PrivateKey.fromString(pvt.toWif()), 'converting known wif from string')
  doesNotThrow(() => PrivateKey.fromString(pvt.toString('WIF')), 'converting known pvt from string')
  doesNotThrow(() => PublicKey.fromString(pub.toString('WIF')), 'converting known public key from string')
  // doesNotThrow(() => PublicKey.fromString(pub.toStringLegacy()), 'converting known public key from string')

  unitTested = true
}

/** @private */
const doesNotThrow = (cb, msg) => {
  try {
    cb()
  } catch(error) {
    error.message = `${msg} ==> ${error.message}`
    throw error
  }
}