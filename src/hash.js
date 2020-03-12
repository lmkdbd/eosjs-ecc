const createHash = require('create-hash')
const createHmac = require('create-hmac')
var sm3Hash = require('sm3.js/lib/hash/sm3');

/** @namespace hash */

/** @arg {string|Buffer} data
    @arg {string} [resultEncoding = null] - 'hex', 'binary' or 'base64'
    @return {string|Buffer} - Buffer when resultEncoding is null, or string
*/
function sha1(data, resultEncoding) {
    return createHash('sha1').update(data).digest(resultEncoding)
}

/** @arg {string|Buffer} data
    @arg {string} [resultEncoding = null] - 'hex', 'binary' or 'base64'
    @return {string|Buffer} - Buffer when resultEncoding is null, or string
*/
function sha256(data, resultEncoding) {
    return createHash('sha256').update(data).digest(resultEncoding)
}

/** @arg {string|Buffer} data
    @arg {string} [resultEncoding = null] - 'hex', 'binary' or 'base64'
    @return {string|Buffer} - Buffer when resultEncoding is null, or string
*/
function sha512(data, resultEncoding) {
    return createHash('sha512').update(data).digest(resultEncoding)
}

function HmacSHA256(buffer, secret) {
    return createHmac('sha256', secret).update(buffer).digest()
}

function ripemd160(data) {
    return createHash('rmd160').update(data).digest()
}

// function hash160(buffer) {
//   return ripemd160(sha256(buffer))
// }
//
// function hash256(buffer) {
//   return sha256(sha256(buffer))
// }

//
// function HmacSHA512(buffer, secret) {
//   return crypto.createHmac('sha512', secret).update(buffer).digest()
// }

/** @arg {string|Buffer} data
    @arg {string} [resultEncoding = null] - 'hex', 'binary' or 'base64'
    @return {string|Buffer} - Buffer when resultEncoding is null, or string
*/
function sm3(data, resultEncoding) {
    var res = new Buffer.from(sm3Hash().update(data).digest());
    if (resultEncoding === undefined )
        return res;
    return res.toString(resultEncoding);
}

module.exports = {
    sha1: sha1,
    sha256: sha256,
    sha512: sha512,
    HmacSHA256: HmacSHA256,
    ripemd160: ripemd160,
    // hash160: hash160,
    // hash256: hash256,
    // HmacSHA512: HmacSHA512
    sm3: sm3
}
