/* 
 * socks5.js, Socks5 server - TCP Protocol
 * 
 * (C) 2020 TekMonks. All rights reserved.
 */

const net = require("net");
const CONSTANTS = require(`${__dirname}/constants.js`);
const utils = require(`${CONSTANTS.LIBDIR}/utils.js`);
const conf = require(CONSTANTS.CONFDIR+"/socks5.json");
global.CONSTANTS = require(__dirname + "/constants.js");
const firewall = require(CONSTANTS.LIBDIR+"/firewall.js");
const _log = (message, socket) => socket?`[SOCKS5] [${socket.remoteAddress}:${socket.remotePort}] ${message}`:`[SOCKS5] ${message}`;

// support starting in stand-alone config
if (require("cluster").isMaster) bootstrap();

function bootstrap() {
    console.log(_log("Starting the SOCKS5 server..."));

    /* Init the logs */
	console.log(_log("Initializing the logs."));
    require(CONSTANTS.LIBDIR+"/log.js").initGlobalLoggerSync(`${CONSTANTS.LOGDIR}/socks5.log.ndjson`);
    LOG.overrideConsole();

    /* Init the firewall */
    firewall.init(conf);
    
    if (!conf.host) conf.host = "::";   // support IPv6 and IPv4 

    net.createServer({allowHalfOpen: true}, socket => {
        LOG.debug(_log("Connection received.", socket));
        if (firewall.isAllowed(socket)) _handle_client_socket(socket);
    }).listen(conf.port, conf.host, _ => LOG.console(_log(`Server listening on ${conf.host}:${conf.port}\n`))
    ).on("error", err => {LOG.error(_log("Server received a server socket error")); LOG.error(err);});
}

function _handle_client_socket(socket) {
    let messageNumber = 0;

    const negotiateSocksMethod = chunk => {
        const ver = chunk[0]; if (ver != 0x05) throw ("Bad SOCKS5 version byte.");
        const methods = chunk.slice(2);
        const returnMethod = [0x05,methods.includes(0x00)?0x00:0xFF];
        socket.write(Buffer.from(returnMethod));
    }

    const setupProxy = async chunk => {
        const ver = chunk[0]; if (ver != 0x05) throw ("Bad SOCKS5 version byte.");
        const cmd = chunk[1]; if (cmd != 0x01) throw ("Only CONNECT is supported.");
        let addr = chunk[3] == 0x01 ? chunk.slice(4, 8) : chunk[3] == 0x04 ? chunk.slice(4, 20) : chunk.slice(4, 4+chunk[4]);
        if (chunk[3] == 0x03) addr = addr.toString("utf-8"); else addr = utils.getIPFromBytes(addr);
        const port = chunk.slice(chunk.length-2).readInt16BE();

        try {
            const {server, remoteSocket} = await _createSOCKS5Proxy(port, addr, socket);
            const getPortAsBytes = port => {const buf = Buffer.alloc(2); buf.writeInt16BE(port); return buf.values();}
            const reply = [0x05, 0x00, 0x00, server.address().family == "IPv4" ? 0x01 : 0x04, 
                ...(utils.getIPAsBytes(server.address().address).values()), ...getPortAsBytes(server.address().port)];
            socket.write(Buffer.from(reply));   // for SOCKS5 compliant clients, timeout will cleanup the socket
            return {server, remoteSocket};
        } catch(err) {LOG.error(_log(`Error in setting up proxy: ${err}`, socket)); socket.write(Buffer.from([0x05, 0x01, 0x00]));}
    }

    let proxyObj;
    const dataHandler = async chunk => { // all SOCKS5 commands should fit in a chunk
        try {
            if (messageNumber == 0) negotiateSocksMethod(chunk);
            if (messageNumber == 1) proxyObj = await setupProxy(chunk);
            if (messageNumber > 1) if (proxyObj) {  // Bad SOCKS5 client! Most probably libcurl nonsense, should be reconnecting to our new port
                LOG.error(_log("Bad client, RFC 1928 Section 6, doesn't follow reply port. Probably LIBCURL based.", socket));
                _handleClient(socket, proxyObj.remoteSocket, proxyObj.server, chunk, true);   
            }
        } catch (err) {
            LOG.error(_log(`Client error, ${err}`, socket));
            socket.end(); socket.destroy();
        }
    }

    if (conf.timeout) socket.setTimeout(conf.timeout);
    socket.on("data", async chunk => {await dataHandler(chunk); messageNumber++});  
    socket.on("error", err => {LOG.error(_log(`Client socket issue, ${err}.`, socket)); socket.end(); socket.destroy();});
    socket.on("timeout", _=>{LOG.error(_log(`Client socket timeout.`, socket)); socket.end();})
}

function _createSOCKS5Proxy(port, host, socket) {
    return new Promise((resolve, reject) => {
        let remoteSocket; 
        const server = net.createServer({allowHalfOpen:true}, client => _handleClient(client, remoteSocket, server)
        ).listen(0, conf.proxy_host, _ => {
            LOG.info(_log(`Created new proxy server listening on ${conf.proxy_host}:${server.address().port}.`, socket));
            remoteSocket = net.connect({port, host}, _ => resolve({server, remoteSocket})); // resolve once remote is connected
        }).on("error", err => {
            LOG.error(_log(`Couldn't create a new proxy server, ${err}`,socket));
            reject(err);
        });
    })
}

function _handleClient(client, remoteSocket, server, data, closeServer) {
    client.removeAllListeners();    // take over
    LOG.info(_log(`Access to ${remoteSocket?remoteSocket.remoteAddress:""}:${remoteSocket?remoteSocket.remotePort:""}`, client));
    let serverStopped = false; const checkStopServer = _ => {if (serverStopped) return; serverStopped = true; server.close();}

    const handleClientData = chunk => {if (remoteSocket) remoteSocket.write(chunk)}
    client.on("data", chunk => handleClientData(chunk));
    client.on("end", _ => {checkStopServer(); if (remoteSocket) remoteSocket.end();});
    client.on("error", err => {
        checkStopServer(); LOG.error(_log(`Socks client error, ${err}`, client));
        if (remoteSocket) remoteSocket.destroy();
    });
    if (remoteSocket) remoteSocket.on("data", chunk => client.write(chunk));
    if (remoteSocket) remoteSocket.on("end", _ => {checkStopServer();; client.end();});
    if (remoteSocket) remoteSocket.on("error", err => {
        checkStopServer(); LOG.error(_log(`Socks remote server error, ${err}`, client));
        client.destroy();
    });

    if (data) handleClientData(data); if (closeServer) checkStopServer();    // bad socks5 clients, send data to original port (libcurl!)
}

module.exports = {bootstrap};