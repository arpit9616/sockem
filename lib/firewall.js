/* 
 * (C) 2020 TekMonks. All rights reserved.
 * Implements firewall functionality for the SOCKS5 server
 */

const utils = require(`${CONSTANTS.LIBDIR}/utils.js`);

let conf;

/**
 * Inits the firewall control server
 * @param {object} conf          The incoming server config file
 */
module.exports.init = function(confObj) {
    conf = confObj;
    if (!conf.ipsAllowed) conf.firewall = false;    // doesn't make sense

    conf.__ipChecks = []; 
    for (const ip of conf.ipsAllowed) conf.__ipChecks.push({ip: ip.split("/")[0], 
        mask:ip.split("/")[1]?ip.split("/")[1]:ip.indexOf(":" != -1)?128:32});
}

module.exports.isAllowed = function (socket) {
    if (!conf.firewall) return true;    // firewall is disabled

    for (const ipCheck of conf.__ipChecks) if (_checkAgainstThisIPRange(socket, ipCheck.ip, ipCheck.mask)) return true;

    return false;
}

function _checkAgainstThisIPRange(socket, ip, mask) {
    const ipAnalyzed = utils.analyzeIPAddr(ip);
    const ipAnalyzedSocket = utils.analyzeIPAddr(socket.remoteAddress);

    if (ipAnalyzedSocket.ipv6 != ipAnalyzed.ipv6) return false;    // ipv6 can't pass via ipv4 check and vice versa

    const ipAsInt = ipAnalyzedSocket.ipv6 ? _getAs128BitInt(utils.getIPAsBytes(ipAnalyzedSocket.ip)) : utils.getIPAsBytes(ipAnalyzedSocket.ip).readUInt32BE();

    const ipInConf = ipAnalyzed.ipv6 ? _getAs128BitInt(utils.getIPAsBytes(ipAnalyzed.ip)) : utils.getIPAsBytes(ipAnalyzed.ip).readUInt32BE();

    const bitsToShift = ipAnalyzed.ipv6?BigInt(128-mask):32-mask;
    return ipAsInt >> bitsToShift == ipInConf >> bitsToShift; 
}

const _getAs128BitInt = buffer => buffer.slice(0, 8).readBigUInt64BE() << BigInt(64)  || buffer.slice(8, 16).readBigUInt64BE();