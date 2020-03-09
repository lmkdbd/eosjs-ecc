const assert = require('assert');
const ecurve = require('ecurve');
const BigInteger = require('bigi');
const hash = require('./hash');
const keyUtils = require('./key_utils');
const curveInfo = require('./curve_info');

module.exports = PublicKey

/**
  @param {string|Buffer|PublicKey|ecurve.Point} public key
  @param {string} [pubkey_prefix = 'EOS']
*/
function PublicKey(Q, curve_name = "secp256k1", pubkey_prefix = 'EOS') {
    const curve = ecurve.getCurveByName(curve_name);
    var G = curve.G
    var n = curve.n
    if(typeof Q === 'string') {
        const publicKey = PublicKey.fromString(Q, pubkey_prefix)
        assert(publicKey != null, 'Invalid public key')
        return publicKey
    } else if(Buffer.isBuffer(Q)) {
        return PublicKey.fromBuffer(Q,curve_name)
    } else if(typeof Q === 'object' && Q.Q) {
      return PublicKey(Q.Q, curve_name)
    }

    assert.equal(typeof Q, 'object', 'Invalid public key')
    assert.equal(typeof Q.compressed, 'boolean', 'Invalid public key')

    function toBuffer(compressed = Q.compressed) {
        return Q.getEncoded(compressed);
    }

    let pubdata // cache

    // /**
    //     @todo secp224r1
    //     @return {string} PUB_K1_base58pubkey..
    // */
    // function toString() {
    //     if(pubdata) {
    //         return pubdata
    //     }
    //     pubdata = `PUB_K1_` + keyUtils.checkEncode(toBuffer(), 'K1')
    //     return pubdata;
    // }

    /** @todo rename to toStringLegacy
     * @arg {string} [pubkey_prefix = 'EOS'] - public key prefix
    */
    function toString(format = "WIF", pubkey_prefix = 'EOS') {
        var curve_info = curveInfo.getInfoByName(curve_name);
        assert(curve_info.isSupportedFormat(format), "Invalid public format type!")
        if (format === "WIF")
            return pubkey_prefix + keyUtils.checkEncode(toBuffer())
        else {
            return `PUB_`+ curve_info.info.keyType +`_` + keyUtils.checkEncode(toBuffer(), curve_info.info.keyType)
        }
    }

    function toUncompressed() {
        var buf = Q.getEncoded(false);
        var point = ecurve.Point.decodeFrom(curve, buf);
        return PublicKey.fromPoint(point, curve_name);
    }

    /** @deprecated */
    function child( offset ) {
        console.error('Deprecated warning: PublicKey.child')

        assert(Buffer.isBuffer(offset), "Buffer required: offset")
        assert.equal(offset.length, 32, "offset length")

        offset = Buffer.concat([ toBuffer(), offset ])
        offset = hash.sha256( offset )

        let c = BigInteger.fromBuffer( offset )

        if (c.compareTo(n) >= 0)
            throw new Error("Child offset went out of bounds, try again")


        let cG = G.multiply(c)
        let Qprime = Q.add(cG)

        if( curve.isInfinity(Qprime) )
            throw new Error("Child offset derived to an invalid key, try again")

        return PublicKey.fromPoint(Qprime, curve_name)
    }

    function toHex() {
        return toBuffer().toString('hex');
    }

    return {
        Q,
        curve_name,
        toString,
        // toStringLegacy,
        toUncompressed,
        toBuffer,
        child,
        toHex
    }
}

/**
  @param {string|Buffer|PublicKey|ecurve.Point} pubkey - public key
  @param {string} [pubkey_prefix = 'EOS']
*/
PublicKey.isValid = function(pubkey, curve_name, pubkey_prefix = 'EOS') {
    try {
        PublicKey(pubkey, curve_name, pubkey_prefix)
        return true
    } catch(e) {
        return false
    }
}

PublicKey.fromBinary = function(bin, curve_name) {
    return PublicKey.fromBuffer(new Buffer(bin, 'binary'),curve_name);
}

PublicKey.fromBuffer = function(buffer, curve_name) {
    const curve = ecurve.getCurveByName(curve_name);
    return PublicKey(ecurve.Point.decodeFrom(curve, buffer),curve_name);
}

PublicKey.fromPoint = function(point, curve_name) {
    return PublicKey(point, curve_name);
}

/**
    @arg {string} public_key - like PUB_K1_base58pubkey..
    @arg {string} [pubkey_prefix = 'EOS'] - public key prefix
    @return PublicKey or `null` (invalid)
*/
PublicKey.fromString = function(public_key, pubkey_prefix = 'EOS') {
    try {
        return PublicKey.fromStringOrThrow(public_key, pubkey_prefix)
    } catch (e) {
        return null;
    }
}

/**
    @arg {string} public_key - like PUB_K1_base58pubkey..
    @arg {string} [pubkey_prefix = 'EOS'] - public key prefix

    @throws {Error} if public key is invalid

    @return PublicKey
*/
PublicKey.fromStringOrThrow = function(public_key, pubkey_prefix = 'EOS') {
    assert.equal(typeof public_key, 'string', 'public_key')
    const match = public_key.match(/^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)
    if(match === null) {
      // legacy
      var prefix_match = new RegExp("^" + pubkey_prefix);
      if(prefix_match.test(public_key)) {
        public_key = public_key.substring(pubkey_prefix.length)
      }
      const curve_name = "secp256k1"
      return PublicKey.fromBuffer(keyUtils.checkDecode(public_key),curve_name)
    }
    assert(match.length === 3, 'Expecting public key like: PUB_K1_base58pubkey..')
    const [, keyType, keyString] = match
    var curve_name = curveInfo.getInfoByType(keyType).info.name
    return PublicKey.fromBuffer(keyUtils.checkDecode(keyString, keyType),curve_name)
}

PublicKey.fromHex = function(hex, curve_name) {
    return PublicKey.fromBuffer(new Buffer(hex, 'hex'), curve_name);
}

PublicKey.fromStringHex = function(hex) {
    return PublicKey.fromString(new Buffer(hex, 'hex'));
}
