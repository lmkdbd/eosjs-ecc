'use strict';

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

/* eslint-env mocha */
var assert = require('assert');

var ecc = require('.');

var pvt_key = {
  secp256k1: {
    wif: "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss",
    ktp: "PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd",
    pub_wif: "EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM",
    pub_ktp: "PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX",
  },
  sm2: {
    ktp: "PVT_SM2_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1azUK8D",
    pub_ktp: "PUB_SM2_8gP74otXtG6GudaKuSyBVLFP6UGYU53rdCxxAu3tor8PH8wNc7",
  }
}

var secp_name = "secp256k1"
var sm2_name = "sm2"

describe('Common API', function () {

  it('unsafeRandomKey', async function () {
    var pvt = await ecc.unsafeRandomKey(secp_name, "KTP");
    assert.equal(typeof pvt === 'undefined' ? 'undefined' : _typeof(pvt), 'string', 'pvt');
    assert(/^PVT_K1_/.test(pvt));

    pvt = await ecc.unsafeRandomKey(secp_name, "WIF");
    assert.equal(typeof pvt === 'undefined' ? 'undefined' : _typeof(pvt), 'string', 'pvt');
    assert(/^5[HJK]/.test(pvt))

    pvt = await ecc.unsafeRandomKey(sm2_name, "KTP");
    assert.equal(typeof pvt === 'undefined' ? 'undefined' : _typeof(pvt), 'string', 'pvt');
    assert(/^PVT_SM2_/.test(pvt));
  });

  it('seedPrivate', function () {
    assert.equal(ecc.seedPrivate('', secp_name, 'WIF'), pvt_key[secp_name].wif)
    assert.equal(ecc.seedPrivate('', secp_name, 'KTP'), pvt_key[secp_name].ktp);

    assert.equal(ecc.seedPrivate('', sm2_name, 'KTP'), pvt_key[sm2_name].ktp);
  });

  it('privateToPublic', function () {
    assert.equal(ecc.privateToPublic(pvt_key[secp_name].wif, 'WIF'), pvt_key[secp_name].pub_wif);
    assert.equal(ecc.privateToPublic(pvt_key[secp_name].ktp, 'KTP'), pvt_key[secp_name].pub_ktp);

    assert.equal(ecc.privateToPublic(pvt_key[sm2_name].ktp, 'KTP'), pvt_key[sm2_name].pub_ktp);
  });

  it('isValidPublic', function () {
    var keys = [
      [true, 'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX', 'secp256k1'],
      [true, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', 'secp256k1'],
      [false, 'MMM859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', 'secp256k1'],
      [false, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVm', 'secp256k1', 'EOS'],
      [true, 'PUB859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', 'secp256k1', 'PUB'],
      [false, 'PUB859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVm', 'secp256k1', 'PUB']
    ];
    var _iteratorNormalCompletion = true;
    var _didIteratorError = false;
    var _iteratorError = undefined;

    try {
      for (var _iterator = keys[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
        var key = _step.value;

        var _key = _slicedToArray(key, 4),
          valid = _key[0],
          pubkey = _key[1],
          curve_name = _key[2],
          prefix = _key[3];

        assert.equal(valid, ecc.isValidPublic(pubkey, curve_name, prefix), pubkey);
      }
    } catch (err) {
      _didIteratorError = true;
      _iteratorError = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion && _iterator.return) {
          _iterator.return();
        }
      } finally {
        if (_didIteratorError) {
          throw _iteratorError;
        }
      }
    }
  });

  it('isValidPrivate', function () {
    var keys = [
      [true, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'],
      [false, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm'],
      [true, 'PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd']
    ];
    var _iteratorNormalCompletion2 = true;
    var _didIteratorError2 = false;
    var _iteratorError2 = undefined;

    try {
      for (var _iterator2 = keys[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
        var key = _step2.value;

        assert.equal(key[0], ecc.isValidPrivate(key[1]), key[1]);
      }
    } catch (err) {
      _didIteratorError2 = true;
      _iteratorError2 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion2 && _iterator2.return) {
          _iterator2.return();
        }
      } finally {
        if (_didIteratorError2) {
          throw _iteratorError2;
        }
      }
    }
  });

  it('hashs', function () {
    var hashes = [
      // ['sha1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
      ['sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      ['sm3', '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b']
    ];
    var _iteratorNormalCompletion3 = true;
    var _didIteratorError3 = false;
    var _iteratorError3 = undefined;

    try {
      for (var _iterator3 = hashes[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
        var hash = _step3.value;

        assert.equal(ecc[hash[0]](''), hash[1]);
        assert.equal(ecc[hash[0]](Buffer.from('')), hash[1]);
      }
    } catch (err) {
      _didIteratorError3 = true;
      _iteratorError3 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion3 && _iterator3.return) {
          _iterator3.return();
        }
      } finally {
        if (_didIteratorError3) {
          throw _iteratorError3;
        }
      }
    }
  });

  function sign(curve_name, hash_function, format){
    it('signatures', function () {
      var pvt = ecc.seedPrivate('', curve_name, format);
      var pubkey = ecc.privateToPublic(pvt, format);
  
      var data = 'hi';
      var dataHash = ecc[hash_function](data);
      var sigs = [ecc.sign(data, pvt, curve_name), ecc.signHash(dataHash, pvt, curve_name)];
  
      var _iteratorNormalCompletion4 = true;
      var _didIteratorError4 = false;
      var _iteratorError4 = undefined;
  
      try {
        for (var _iterator4 = sigs[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
          var sig = _step4.value;
  
          assert(ecc.verify(sig, data, pubkey, curve_name), 'verify data');
          assert(ecc.verifyHash(sig, dataHash, pubkey, curve_name), 'verify hash');
          assert.equal(pubkey, ecc.recover(sig, data, curve_name, format), 'recover from data');
          assert.equal(pubkey, ecc.recoverHash(sig, dataHash, curve_name, format), 'recover from hash');
        }
      } catch (err) {
        _didIteratorError4 = true;
        _iteratorError4 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion4 && _iterator4.return) {
            _iterator4.return();
          }
        } finally {
          if (_didIteratorError4) {
            throw _iteratorError4;
          }
        }
      }
    });
  }

  sign("secp256k1", "sha256", "WIF");
  sign("secp256k1", "sha256", "KTP");
  sign("sm2", "sm3", "KTP");
});

describe('Common API (initialized)', function () {
  it('initialize', function () {
    return ecc.initialize();
  });

  it('randomKey', function () {
    var cpuEntropyBits = 1;
    ecc.key_utils.addEntropy(1, 2, 3);
    var pvt = ecc.unsafeRandomKey('secp256k1', "WIF").then(function (pvt) {
      assert.equal(typeof pvt === 'undefined' ? 'undefined' : _typeof(pvt), 'string', 'pvt');
      assert(/^5[HJK]/.test(pvt));
      // assert(/^PVT_K1_/.test(pvt))
    });
  });
});