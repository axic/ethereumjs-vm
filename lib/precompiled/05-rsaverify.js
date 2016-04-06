const utils = require('ethereumjs-util')
const BN = utils.BN
const error = require('../constants.js').ERROR
//const fees = require('ethereum-common/params')
const fees = {
  rsaverifyGas: { v: 200 },
  rsaverifyBitGas: { v: 1 },
}
const abi = require('ethereumjs-abi')
const NodeRSA = require('node-rsa');

module.exports = function (opts) {
  var results = {}

  console.log('RSA', 'Incoming RSA call', opts.data.length, opts.data)

  var args

  try {
    args = abi.rawDecode(null, null, [ "bytes", "bytes", "uint", "bytes", "uint" ], opts.data)
  } catch(e) {
    console.log('RSA', 'ABI decoding failed', e)
    results.exception = 0
    return results
  }

  var msgHash = args[0]
  var n = args[1]
  var e = args[2].toNumber()
  var s = args[3]
  var pt = args[4].toNumber()

  console.log('RSA', 'Verification parameters', msgHash.toString('hex'), n.toString('hex'), e, s.toString('hex'), pt)

  results.gasUsed = new BN(fees.rsaverifyGas.v)

  // calculate gas based on key length
  // var bits = (n.length * 8)
  // results.gasUsed.iadd(new BN(fees.rsaverifyBitGas.v).pown(bits))

  if (opts.gasLimit.cmp(results.gasUsed) === -1) {
    results.gasUsed = opts.gasLimit
    results.exception = 0 // 0 means VM fail (in this case because of OOG)
    results.exceptionError = error.OUT_OF_GAS
    return results
  }

  if (pt !== 1 && pt !== 2) {
    console.log('RSA', 'Invalid padding scheme')
    results.exception = 0
    return results
  }

  var valid
  try {
    var key = new NodeRSA()
    key.setOptions({
      signingScheme: (pt === 1) ? 'pkcs1-sha256' : 'pss-sha1'
    })
    key.importKey({
      n: n,
      e: e
    }, 'components-public')
    console.log('RSA', 'Key loaded', key)

    valid = key.verify(msgHash, s)
  } catch (e) {
    console.log('RSA', 'Verification exception', e)
    results.exception = 0
    return results
  }

  console.log('RSA', 'Finished', valid)

  results.return = utils.setLengthLeft(valid ? 1 : 0, 32)
  results.exception = 1

  return results
}
