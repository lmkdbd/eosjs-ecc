var assert = require('assert') // from github.com/bitcoinjs/bitcoinjs-lib from github.com/cryptocoinjs/ecdsa
var crypto = require('./hash')
var enforceType = require('./enforce_types')

var BigInteger = require('bigi')
var ECSignature = require('./ecsignature')

// https://tools.ietf.org/html/rfc6979#section-3.2
function deterministicGenerateK(curve, hash, d, checkSig, nonce) {
  
  enforceType('Buffer', hash)
  enforceType(BigInteger, d)
  
  if (nonce) {
    hash = crypto.sha256(Buffer.concat([hash, new Buffer(nonce)]))
  }

  // sanity check
  assert.equal(hash.length, 32, 'Hash must be 256 bit')

  var x = d.toBuffer(32)
  var k = new Buffer(32)
  var v = new Buffer(32)

  // Step B
  v.fill(1)

  // Step C
  k.fill(0)

  // Step D
  k = crypto.HmacSHA256(Buffer.concat([v, new Buffer([0]), x, hash]), k)

  // Step E
  v = crypto.HmacSHA256(v, k)

  // Step F
  k = crypto.HmacSHA256(Buffer.concat([v, new Buffer([1]), x, hash]), k)

  // Step G
  v = crypto.HmacSHA256(v, k)

  // Step H1/H2a, ignored as tlen === qlen (256 bit)
  // Step H2b
  v = crypto.HmacSHA256(v, k)

  var T = BigInteger.fromBuffer(v)

  // Step H3, repeat until T is within the interval [1, n - 1]
  while ((T.signum() <= 0) || (T.compareTo(curve.n) >= 0) || !checkSig(T)) {
    k = crypto.HmacSHA256(Buffer.concat([v, new Buffer([0])]), k)
    v = crypto.HmacSHA256(v, k)

    // Step H1/H2a, again, ignored as tlen === qlen (256 bit)
    // Step H2b again
    v = crypto.HmacSHA256(v, k)
    
    T = BigInteger.fromBuffer(v)
  }

  return T

}

function sm2(curve_name){
  var curve = require('@lmkdbd/ecurve').getCurveByName(curve_name);
  function sign(hash, d, nonce) {

    var e = BigInteger.fromBuffer(hash);
    var n = curve.n;
    var G = curve.G;
  
    var r, s;
  
    var k = deterministicGenerateK(curve, hash, d, function (k) {
      var Q = G.multiply(k);
  
      if (curve.isInfinity(Q)) return false;
  
      r = e.add(Q.affineX).mod(n);
  
      if (r.signum() === 0 || r.add(k).compareTo(curve.n) === 0) return false;
      
      const number_one = new BigInteger(1, 16)
      
      s = d.add(number_one).modInverse(n).multiply(k.subtract(r.multiply(d))).mod(n);
  
      if (s.signum() === 0) return false;
  
      return true;
    }, nonce);
  
    return ECSignature(r, s);
  }
  
  function verifyRaw(e, signature, Q) {
    var n = curve.n;
    var G = curve.G;
  
    var r = signature.r;
    var s = signature.s;
  
    //r and s are both integers in the interval [1, n − 1]
    if (r.signum() <= 0 || r.compareTo(n) >= 0) return false;
    if (s.signum() <= 0 || s.compareTo(n) >= 0) return false;
  
    //t = (r + s) mod n
    var t = r.add(s).mod(n);
    // t != 0
    if (t.signum() === 0) return false;
    // P = sG + tQ
    var R = G.multiplyTwo(s, Q, t);
  
    if (curve.isInfinity(R)) return false;
    //r' = (e + x) mod n
    var v = R.affineX.add(e);
    //r = r' 
    return v.equals(r);
  }

  function verify(hash, signature, Q) {
    // 1.4.2 H = Hash(M), already done by the user
    // 1.4.3 e = H
    var e = BigInteger.fromBuffer(hash);
    return verifyRaw(e, signature, Q);
  }
  
  /**
    * Recover a public key from a signature.
    */
  function recoverPubKey(e, signature, i) {
    assert.strictEqual(i & 3, i, 'Recovery param is more than two bits');
  
    var n = curve.n;
    var G = curve.G;
  
    var r = signature.r;
    var s = signature.s;
  
    assert(r.signum() > 0 && r.compareTo(n) < 0, 'Invalid r value');
    assert(s.signum() > 0 && s.compareTo(n) < 0, 'Invalid s value');
  
    // A set LSB signifies that the y-coordinate is odd
    var isYOdd = i & 1;
  
    // The more significant bit specifies whether we should use the
    // first or second candidate key.
    var isSecondKey = i >> 1;
    // Let x = r - e mod n
    var x = r.subtract(e).mod(n);
    // x = x + n
    x = isSecondKey ? x.add(n) : x;
    var R = curve.pointFromX(isYOdd, x);
  
    //Check that nR is at infinity
    var nR = R.multiply(n);
    assert(curve.isInfinity(nR), 'nR is not a valid curve point');
  
    //Compute u1 = (s + r)^ -1
    //        u2 = (s + r)^ -1 * s
    var sNeg = s.negate().mod(n);
    var u1 = s.add(r).modInverse(n);
    var u2 = u1.multiply(sNeg);
  
    var Q = R.multiplyTwo(u1,G,u2);
    curve.validate(Q);
  
    return Q;
  }

  function calcPubKeyRecoveryParam(e, signature, Q) {
    for (var i = 0; i < 4; i++) {
      var Qprime = recoverPubKey(e, signature, i)
  
      // 1.6.2 Verify Q
      if (Qprime.equals(Q)) {
        return i
      }
    }
  
    throw new Error('Unable to find valid recovery factor')
  }

  function sign_hash(data) {
    return crypto.sm3(data);
  }

  return {
    calcPubKeyRecoveryParam,
    recoverPubKey,
    sign,
    verify,
    verifyRaw,
    sign_hash,
  }
}

function ecdsa(curve_name){

  var curve = require('@lmkdbd/ecurve').getCurveByName(curve_name);

  function sign(hash, d, nonce) {

    var e = BigInteger.fromBuffer(hash);
    var n = curve.n;
    var G = curve.G;
  
    var r, s;
  
    var k = deterministicGenerateK(curve, hash, d, function (k) {
      // find canonically valid signature
      var Q = G.multiply(k);
  
      if (curve.isInfinity(Q)) return false;
      r = Q.affineX.mod(n);
      if (r.signum() === 0) return false;
  
      s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
      if (s.signum() === 0) return false;
  
      return true;
    }, nonce);
  
    var N_OVER_TWO = n.shiftRight(1);
  
    // enforce low S values, see bip62: 'low s values in signatures'
    if (s.compareTo(N_OVER_TWO) > 0) {
      s = n.subtract(s);
    }
  
    return ECSignature(r, s);
  }
  
  function verifyRaw(e, signature, Q) {
    var n = curve.n;
    var G = curve.G;
  
    var r = signature.r;
    var s = signature.s;
  
    // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1]
    if (r.signum() <= 0 || r.compareTo(n) >= 0) return false;
    if (s.signum() <= 0 || s.compareTo(n) >= 0) return false;
  
    // c = s^-1 mod n
    var c = s.modInverse(n);
  
    // 1.4.4 Compute u1 = es^−1 mod n
    //               u2 = rs^−1 mod n
    var u1 = e.multiply(c).mod(n);
    var u2 = r.multiply(c).mod(n);
  
    // 1.4.5 Compute R = (xR, yR) = u1G + u2Q
    var R = G.multiplyTwo(u1, Q, u2);
  
    // 1.4.5 (cont.) Enforce R is not at infinity
    if (curve.isInfinity(R)) return false;
  
    // 1.4.6 Convert the field element R.x to an integer
    var xR = R.affineX;
  
    // 1.4.7 Set v = xR mod n
    var v = xR.mod(n);
  
    // 1.4.8 If v = r, output "valid", and if v != r, output "invalid"
    return v.equals(r);
  }

  function verify(hash, signature, Q) {
    // 1.4.2 H = Hash(M), already done by the user
    // 1.4.3 e = H
    var e = BigInteger.fromBuffer(hash);
    return verifyRaw(e, signature, Q);
  }

  /**
  * Recover a public key from a signature.
  *
  * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
  * Key Recovery Operation".
  *
  * http://www.secg.org/download/aid-780/sec1-v2.pdf
  */
  function recoverPubKey(e, signature, i) {
    assert.strictEqual(i & 3, i, 'Recovery param is more than two bits');

    var n = curve.n;
    var G = curve.G;

    var r = signature.r;
    var s = signature.s;

    assert(r.signum() > 0 && r.compareTo(n) < 0, 'Invalid r value');
    assert(s.signum() > 0 && s.compareTo(n) < 0, 'Invalid s value');

    // A set LSB signifies that the y-coordinate is odd
    var isYOdd = i & 1;

    // The more significant bit specifies whether we should use the
    // first or second candidate key.
    var isSecondKey = i >> 1;

    // 1.1 Let x = r + jn
    var x = isSecondKey ? r.add(n) : r;
    var R = curve.pointFromX(isYOdd, x);

    // 1.4 Check that nR is at infinity
    var nR = R.multiply(n);
    assert(curve.isInfinity(nR), 'nR is not a valid curve point');

    // Compute -e from e
    var eNeg = e.negate().mod(n);

    // 1.6.1 Compute Q = r^-1 (sR -  eG)
    //               Q = r^-1 (sR + -eG)
    var rInv = r.modInverse(n);

    var Q = R.multiplyTwo(s, G, eNeg).multiply(rInv);
    curve.validate(Q);

    return Q;
  }

  function calcPubKeyRecoveryParam(e, signature, Q) {
    for (var i = 0; i < 4; i++) {
      var Qprime = recoverPubKey(e, signature, i)
  
      // 1.6.2 Verify Q
      if (Qprime.equals(Q)) {
        return i
      }
    }
  
    throw new Error('Unable to find valid recovery factor')
  }

  function sign_hash(data) {
    return crypto.sha256(data);
  }

  return {
    calcPubKeyRecoveryParam,
    recoverPubKey,
    sign,
    verify,
    verifyRaw,
    sign_hash,
  }
}

function getSignInfo(curve_name) {
  if (curve_name === "sm2")
    return sm2(curve_name)
  else return ecdsa(curve_name);
}

module.exports = {
  deterministicGenerateK: deterministicGenerateK,
  getSignInfo: getSignInfo,
}
