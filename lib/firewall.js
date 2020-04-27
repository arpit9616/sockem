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
    const isCheckIPv6 = ip.indexOf(":") != -1; 
    if (!isCheckIPv6 && socket.remoteFamily != "IPv4") return false;    // ipv6 can't pass via ipv4 check
    if (isCheckIPv6 && socket.remoteFamily != "IPv6") return false;     // ipv4 can't pass via ipv6 check

    const ipAsInt = socket.remoteFamily == "IPv6"? _getAs128BitInt(utils.getIPAsBytes(socket.remoteAddress)) : utils.getIPAsBytes(socket.remoteAddress).readUInt32BE();
    const maskAsInt = _getIPMask(mask, socket.remoteFamily == "IPv6");
    const ipInConf = socket.remoteFamily == "IPv6"? _getAs128BitInt(utils.getIPAsBytes(ip)) : utils.getIPAsBytes(ip).readUInt32BE();

    return BigInt(ipAsInt & maskAsInt) == BigInt(ipInConf);   
}
    
const _getIPMask = (mask, isV6) => isV6?-1n<<(128n-BigInt(mask)):-1<<(32-mask);

const _getAs128BitInt = buffer => buffer.slice(0, 8).readBigUInt64BE() << 64n  || buffer.slice(8, 16).readBigUInt64BE();