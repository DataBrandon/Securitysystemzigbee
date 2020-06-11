var CryptoJS = require("crypto-js");


 const message = [30,145,15,50].toString();
//  const secret = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
//  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21,
//  0x22, 0x23, 0x24, 0x25, 0x26, 0x26, 0x27, 0x28, 0x29, 0x30];
//const secret = [0,1,2,3,4,5,6,7,8,9,16,17,18,19,20,21,22,23,24,25,32,33,34,35,36,37,38,38,39,40,41,48].toString();

// const secret = 'Jefe'
// const message = 'what do ya want for nothing?'
const secret = "VeRy sEcReT 987981";


const text = toByteArray('b82bea76ce73483951a80e5298bb8dacf6de0a3c4f0281c5cf8ceeca60477fa1')
//const text = toHexString([102,94,179,129,83,134,8,166,202,186,211,10,31,95,197,194,144,69,47,178,127,230,4,19,176,30,64,171,60,173,118,41])

function toHexString(byteArray) {
    return Array.prototype.map.call(byteArray, function(byte) {
      return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
  }
  function toByteArray(hexString) {
    var result = [];
    for (var i = 0; i < hexString.length; i += 2) {
      result.push(parseInt(hexString.substr(i, 2), 16));
    }
    return result;
  }


console.log("dit komt van jouw " + text)

console.log(message)
console.log(secret)
console.log("Dit heb ik  in mijn ritme: " + CryptoJS.HmacSHA256(message, secret).toString());