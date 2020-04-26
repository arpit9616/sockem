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
    if (!conf.ipsAllowed) conf.ipsAllowed = ["0.0.0.0/32"];
    conf.__ipCheck = conf.ipsAllowed.split("/")[0];
    conf.__ipMask = conf.ipsAllowed.split("/")[1] ? conf.ipsAllowed.split("/")[1] : "32";
}

module.exports.isAllowed = function (socket) {
    if (!conf.firewall) return true;    // firewall is disabled

    const remoteAddr = socket.remoteAddress;
    return utils.getIPAsBytes(remoteAddr).readInt32BE() & __getIPMask(conf.__ipMask) == utils.getIPAsBytes(conf.__ipCheck).readInt32BE();
}

const __getIPMask = mask => -1<<(32-mask);