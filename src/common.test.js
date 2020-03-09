/* eslint-env mocha */
const assert = require('assert')

const ecc = require('.')

const wif = '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'

describe('Common API', () => {
  it('unsafeRandomKey', async function() {
    const pvt = await ecc.unsafeRandomKey('secp256k1', "KTP")
    assert.equal(typeof pvt, 'string', 'pvt')
    //assert(/^5[HJK]/.test(wif))
    assert(/^PVT_K1_/.test(pvt)) // todo
  })

  it('seedPrivate', () => {
    //assert.equal(ecc.seedPrivate('','secp256k1','PUB'), wif)
    assert.equal(ecc.seedPrivate('','secp256k1','KTP'), 'PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd')
  })

  it('privateToPublic', () => {
    const pub = 'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX'
    //const pub = 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'
    assert.equal(ecc.privateToPublic(wif, 'KTP'), pub)
  })

  it('isValidPublic', () => {
    const keys = [
      [true, 'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX', 'secp256k1'],
      [true, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', 'secp256k1'],
      [false, 'MMM859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', 'secp256k1'],
      [false, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVm', 'secp256k1', 'EOS'],
      [true, 'PUB859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', 'secp256k1', 'PUB'],
      [false, 'PUB859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVm', 'secp256k1', 'PUB'],
    ]
    for(const key of keys) {
      const [valid, pubkey, curve_name, prefix] = key
      assert.equal(valid, ecc.isValidPublic(pubkey, curve_name, prefix), pubkey)
    }
  })

  it('isValidPrivate', () => {
    const keys = [
      [true, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'],
      [false, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm'],
      [true, 'PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd']
    ]
    for(const key of keys) {
      assert.equal(key[0], ecc.isValidPrivate(key[1]), key[1])
    }
  })

  it('hashs', () => {
    const hashes = [
      // ['sha1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
      ['sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      ['sm3', '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b'],
    ]
    for(const hash of hashes) {
      assert.equal(ecc[hash[0]](''), hash[1])
      assert.equal(ecc[hash[0]](Buffer.from('')), hash[1])
    }
  })

  it('signatures', () => {
    var curve_k1 = 'secp256k1';
    const pvt = ecc.seedPrivate('',curve_k1,'WIF')
    const pubkey = ecc.privateToPublic(pvt,'WIF')

    const data = 'hi'
    const dataSha256 = ecc.sha256(data)

    const sigs = [
      ecc.sign(data, pvt, curve_k1),
      ecc.signHash(dataSha256, pvt, curve_k1)
    ]

    for(const sig of sigs) {
      assert(ecc.verify(sig, data, pubkey, curve_k1), 'verify data')
      assert(ecc.verifyHash(sig, dataSha256, pubkey, curve_k1), 'verify hash')
      assert.equal(pubkey, ecc.recover(sig, data, curve_k1, 'WIF'), 'recover from data')
      assert.equal(pubkey, ecc.recoverHash(sig, dataSha256, curve_k1, 'WIF'), 'recover from hash')
    }
  })
})

describe('Common API (initialized)', () => {
  it('initialize', () => ecc.initialize())

  it('randomKey', () => {
    const cpuEntropyBits = 1
    ecc.key_utils.addEntropy(1, 2, 3)
    const pvt = ecc.unsafeRandomKey('secp256k1', "WIF").then(pvt => {
      assert.equal(typeof pvt, 'string', 'pvt')
      assert(/^5[HJK]/.test(wif))
      // assert(/^PVT_K1_/.test(pvt))
    })
  })
})
