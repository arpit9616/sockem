/** 
 * DNS resolver for SOCK'EM
 * (C) 2020 TekMonks. All rights reserved.
 */

const dns = require(`${CONSTANTS.CONFDIR}/dns.json`);

module.exports.preConnect = (host, port) => {
    if (dns[`${host}:${port}`]) return _getHostPort(dns[`${host}:${port}`].trim(), port);
    else if (dns[`[${host}]:${port}`]) return _getHostPort(dns[`[${host}]:${port}`].trim(), port);
    else return {host, port};
}

function _getHostPort(entry, portIn) {
    let port; let host;
    const isIPV6 = entry.indexOf("[") != -1;
    if (isIPV6) {   // ipv6 possibly with port
        port = entry.lastIndexOf("]:")+2 < entry.length?entry.substring(entry.lastIndexOf("]:")+2):portIn;
        host = entry.substring(1, entry.lastIndexOf("]"));
    }

    if (entry.indexOf(":") != entry.lastIndexOf(":") && entry.indexOf("[") == -1) { // pure IPv6, no port
        port = portIn;
        host = entry;
    }

    if (entry.indexOf(":") == entry.lastIndexOf(":") && entry.indexOf(":") != -1) { // ipv4 or domain with port
        port = entry.substring(entry.lastIndexOf(":")+1);
        host = entry.substring(0, entry.lastIndexOf(":"));
    }

    if (entry.indexOf(":") == -1) { // ipv4 or domain no port
        port = portIn;
        host = entry;
    }

    return {host, port};
}