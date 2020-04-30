/** 
 * AES encrypter for SOCK'EM
 * (C) 2020 TekMonks. All rights reserved.
 */
const io = require(`${CONSTANTS.LIBDIR}/io.js`);
const crypt = require(`${CONSTANTS.LIBDIR}/crypt.js`);
const conf = require(`${CONSTANTS.CONFDIR}/aes.json`);
const key = crypt.decrypt(conf.key);

module.exports.preOut = (socket, chunk) => _isEndpointEnabled(socket) ? io.getWritableData(chunk, key) : chunk;

module.exports.preIn = function (socket, chunk, callback) {
    if (_isEndpointEnabled(socket)) io.readData(socket, chunk, key, callback); else callback(chunk);
}

function _isEndpointEnabled(socket) {
    const check = socket.remoteFamily == "IPv6" ? `[${socket.remoteAddress}]:${socket.remotePort}` :
        `${socket.remoteAddress}:${socket.remotePort}`;
    if (conf[check] || conf[socket.remoteAddress]) return true; else return false;
}