/**
 * Handles TCP SOCKS5 proxy communications.
 * 
 * (C) 2020 TekMonks. All rights seserved.
 * License: See enclosed LICENSE file.
 */

const dgram = require('dgram');
const utils = require(`${CONSTANTS.LIBDIR}/utils.js`);
const extMan = require(CONSTANTS.LIBDIR+"/extensionsmanager.js");
const _log = (message, socket) => socket?`[SOCKS5] [UDP] [${socket.remoteAddress}:${socket.remotePort}] ${message}`:`[SOCKS5] ${message}`;
let conf; 

/**
 * Inits the module.
 * @param {object} confObj The configuration object for SOCKS5 server.
 */
function initSync(confObj) {
    conf = confObj; 
    extMan.initSync();
}

/**
 * Creates a UDP Socks5 Proxy Server. This function should be called per client, and 
 * encapsulates one TCP session.
 * @param {number} port The remote server port
 * @param {string} host The remote server host
 * @param {object} socket The incoming client connection which requested this server.
 * @returns {object} conObj {server: new UDP server object}
 */
function createSOCKS5Proxy(port, host, socket) {
    return new Promise((resolve, reject) => {
        const server = dgram.createSocket(socket.address().family=="IPv4"?"udp4":"udp6");   // match family
        server.bind(0, conf.proxy_host, _ => {
            LOG.info(_log(`Created new UDP relay listening on ${conf.proxy_host}:${server.address().port}.`, socket));
            handleSocksClient(socket, server, port, host);
            resolve({server});
        }).once("error", err => {
            LOG.error(_log(`Couldn't create a new proxy server, ${err}`,socket));
            reject(err);
        });
    })
}

/**
 * This function handles an incoming SOCKS5 UDP client connection for a proxy
 * which has already been established. 
 * @param {net.Socket} tcpClient The TCP client socket which requested this relay
 * @param {dgram.Socket} server The UDP relay server to manage
 * @param {number} rport The remote port we would be talking to
 * @param {string} rhost The remote host we would be talking to
 */
function handleSocksClient(tcpClient, server, rport, rhost) {
    tcpClient.on("close", _=>server.close());  // RFC 1928 - section 6#UDP ASSOCIATE must terminate when TCP request which requested it terminates
    tcpClient.setTimeout(0);    // TCP socket establishing the UDP relay will be idle. Clear any timeouts.
    server.removeAllListeners();    // we will handle this exclusively from now on

    const rconInfo = extMan.preConnect(rhost, rport); rconInfo.address = rconInfo.host;

    let udpClient;
    server.on("message", (msg, rinfo) => {
        if (_isFromSocksClient(rinfo, {address:tcpClient.remoteAddress}) && _shouldWeRelay(msg, rport, rhost)) {
            if (!udpClient) udpClient = rinfo;
            server.send(_stripClientHeader(msg), rconInfo.port, rconInfo.address);
        } else if (_isFromRemoteServer(rinfo, rconInfo) && udpClient) server.send(_addClientHeader({address: rhost, port: rport}, msg), udpClient.port, udpClient.address);
    });

    server.on("error", err => LOG.error(_log(`Got UDP error ${err}, ignoring.`)));
}

const _isFromSocksClient = (rinfo, clientInfo) => utils.compareIPs(clientInfo.address, rinfo.address);
const _isFromRemoteServer = (rinfo, remoteInfo) => utils.compareIPs(remoteInfo.address, rinfo.address);

function _shouldWeRelay(chunk, rport, rhost) {
    let addr = chunk[3] == 0x01 ? chunk.slice(4, 8) : chunk[3] == 0x04 ? chunk.slice(4, 20) : chunk.slice(4+1, 4+1+chunk[4]);
    const port = chunk.slice(addr.length+4,addr.length+6).readInt16BE();
    if (chunk[3] == 0x03) addr = addr.toString("utf-8"); else addr = utils.getIPFromBytes(addr);
    return (rport == port && rhost == addr);
}

function _stripClientHeader(chunk) {
    const addrLen = chunk[3] == 0x01 ? 4 : chunk[3] == 0x04 ? 16 : 1+chunk[4];
    const msg = chunk.slice(4+addrLen+2);   // RSV(2)+FRAG(1)+ATYP(1)+AddrLength+PORT(2)+DATA
    return msg;
}

function _addClientHeader(destInfo, msg) {
    const addr = utils.isThisAnIP(destInfo.address)?utils.getIPAsBytes(destInfo.address):Buffer.from(destInfo.address, "utf8");
    const headeredMsg = Buffer.alloc(6+(utils.isThisAnIP(destInfo.address)?addr.length:addr.length+1)+msg.length);
    headeredMsg[0] = 0x00; headeredMsg[1] = 0x00; headeredMsg[2] = 0x00; 
    headeredMsg[3] = utils.isThisAnIP(destInfo.address) ? (addr.length == 4 ? 0x01 : 0x04) : 0x03;
    if (utils.isThisAnIP(destInfo.address) == false) {
        headeredMsg[4] = addr.length; 
        addr.copy(headeredMsg, 5);
    } else addr.copy(headeredMsg, 4);
    headeredMsg.writeUInt16BE(destInfo.port, 4+(utils.isThisAnIP(destInfo.address)?addr.length:addr.length+1), 2);
    msg.copy(headeredMsg, 6+(utils.isThisAnIP(destInfo.address)?addr.length:addr.length+1));
    return headeredMsg;
}


module.exports = {initSync, createSOCKS5Proxy, handleSocksClient}