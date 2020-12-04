/**
 * Handles TCP SOCKS5 proxy communications.
 * 
 * (C) 2020 TekMonks. All rights seserved.
 * License: See enclosed LICENSE file.
 */

const net = require("net");
const extMan = require(CONSTANTS.LIBDIR+"/extensionsmanager.js");
const _log = (message, socket) => socket?`[SOCKS5] [TCP] [${socket.remoteAddress}:${socket.remotePort}] ${message}`:`[SOCKS5] ${message}`;
let conf; 

/**
 * Inits the module.
 * @param {object} confObj The configuration object for SOCKS5 server.
 */
function initSync(confObj) {
    conf = confObj; 
    extMan.initSync
}

/**
 * Creates a new TCP proxy server, or nothing depending on options. 
 * @param {object} options Server options object
 * @param {function} clientHandler Client handler
 * @param {number} port Port to listen on
 * @param {string} host Host to listen on
 * @param {function} callback Function to call back once listening
 * @returns The new server or null if the cofig directs us to reuse main proxy port
 */
function _createTCPListener(options, clientHandler) {
    if (conf.noNewTCPServerPerClient) return null;
    else return net.createServer(options, client => clientHandler(client));
}

/**
 * Creates a TCP Socks5 Proxy Server. This function should be called per client, and 
 * encapsulates one TCP session.
 * @param {number} port The remote server port
 * @param {string} host The remote server host
 * @param {object} socket The incoming client connection which requested this server.
 * @returns {object} conObj {server: new TCP server object, could be null, remoteSocket: socket connection to remote server}
 */
function createSOCKS5Proxy(port, host, socket) {
    const remoteConnect = (server, remoteSocket, resolve, reject) => {
        const conObj = extMan.preConnect(host, port); if (conf.remoteTimeout && conf.remoteTimeout != -1) conObj.timeout = conf.remoteTimeout;
        remoteSocket = net.connect(conObj, _ => resolve({server, remoteSocket})); // resolve once remote is connected
        remoteSocket.once("data", data => handleSocksClient(socket, remoteSocket, server, null, data, false)); // remote server sent data on connect
        remoteSocket.once("error", err => {LOG.error(_log(`Couldn't connect to the remote host, ${err}`,socket)); reject(err);});
        remoteSocket.once("timeout", _ => {LOG.error(_log(`Couldn't connect to the remote host, timeout.`,socket)); reject("Timeout error");});
        remoteSocket.once("end", _ => {LOG.error(_log(`Couldn't connect to the remote host, immediate disconnect`,socket)); socket.end(); reject("Immediate Disconnect");}); // remote server sent data on connect
    }

    return new Promise((resolve, reject) => {
        let remoteSocket; 
        const server = _createTCPListener({allowHalfOpen:true}, client => handleSocksClient(client, remoteSocket, server));
        
        if (server) server.listen(0, conf.proxy_host, _ => {
            LOG.info(_log(`Created new proxy server listening on ${conf.proxy_host}:${server?server.address().port:conf.port}.`, socket));
            remoteConnect(server, remoteSocket, resolve, reject);
        }).on("error", err => {
            LOG.error(_log(`Couldn't create a new proxy server, ${err}`,socket));
            reject(err);
        }); else remoteConnect(null, remoteSocket, resolve, reject);
    })
}

/**
 * This function handles an incoming SOCKS5 TCP client connection for a proxy
 * which has already been established. 
 * @param {socket} client The incoming client socket
 * @param {*} remoteSocket The remote server connection, already established
 * @param {*} server The SOCKS5 server object
 * @param {*} clientData The incoming client data
 * @param {*} remoteData The incoming remote data
 * @param {*} closeServer Should we close the SOCKS5 server? As client didn't use it
 */
function handleSocksClient(client, remoteSocket, server, clientData, remoteData, closeServer) {
    if (conf.clientTimeout && conf.clientTimeout != -1) client.setTimeout(conf.clientTimeout);
    client.removeAllListeners(); remoteSocket.removeAllListeners(); // take over
    LOG.info(_log(`Access to ${remoteSocket?remoteSocket.remoteAddress:""}:${remoteSocket?remoteSocket.remotePort:""}`, client));
    let serverStopped = false; const checkStopServer = _ => {if (serverStopped || !server) return; serverStopped = true; server.close();}

    const handleClientData = chunk => {if (remoteSocket) remoteSocket.write(extMan.preOut(remoteSocket, chunk))}
    const clientError = err => {
        checkStopServer(); LOG.error(_log(`Socks client error, ${err}`, client));
        if (remoteSocket) remoteSocket.destroy();
    }
    client.on("data", handleClientData);
    client.on("end", _ => {checkStopServer(); if (remoteSocket) remoteSocket.end();});
    client.on("error", clientError);
    client.on("timeout", _=>clientError("timeout"));
    const remoteSocketError = err => {
        checkStopServer(); LOG.error(_log(`Socks remote server error, ${err}`, client));
        client.destroy();
    }
    const handleRemoteData = chunk => extMan.preIn(remoteSocket, chunk, chunkBack => client.write(chunkBack));
    if (remoteSocket) remoteSocket.on("data", handleRemoteData);
    if (remoteSocket) remoteSocket.on("end", _ => {checkStopServer(); client.end();});
    if (remoteSocket) remoteSocket.on("error", remoteSocketError);
    if (remoteSocket) remoteSocket.on("timeout", _=>remoteSocketError("timeout"));

    if (clientData) handleClientData(clientData); if (remoteData) handleRemoteData(remoteData); 
    if (closeServer) checkStopServer();    // bad socks5 clients, send data to original port (libcurl!)
}

module.exports = {initSync, createSOCKS5Proxy, handleSocksClient}