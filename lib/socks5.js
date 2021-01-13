/** 
 * socks5.js, Socks5 server - TCP and UDP Protocols
 * 
 * (C) 2020 TekMonks. All rights reserved.
 */

const net = require("net");
global.CONSTANTS = require(`${__dirname}/constants.js`);
const utils = require(`${CONSTANTS.LIBDIR}/utils.js`);
const conf = require(CONSTANTS.CONFDIR+"/socks5.json");
const firewall = require(CONSTANTS.LIBDIR+"/firewall.js");
const extMan = require(CONSTANTS.LIBDIR+"/extensionsmanager.js");
const socks5tcp = require(`${CONSTANTS.LIBDIR}/socks5TCP.js`);
const socks5udp = require(`${CONSTANTS.LIBDIR}/socks5UDP.js`);

const _log = (message, socket) => socket?`[SOCKS5] [${socket.remoteAddress}:${socket.remotePort}] ${message}`:`[SOCKS5] ${message}`;

// support starting in stand-alone config
if (require("cluster").isMaster) bootstrap();

function _doInit() {
    /* Init the logs */
	console.log(_log("Initializing the logs."));
    require(CONSTANTS.LIBDIR+"/log.js").initGlobalLoggerSync(`${CONSTANTS.LOGDIR}/socks5.log.ndjson`);
    LOG.overrideConsole();

    /* Init the firewall */
    firewall.init(conf);

    /* Init Extension Manager*/
    extMan.initSync();

    /* Init the TCP Server */
    socks5tcp.initSync(conf, extMan);

    /* Init the UDP Server */
    socks5udp.initSync(conf, extMan);
    
    if (!conf.host) conf.host = "::";   // support IPv6 and IPv4 
}

function bootstrap() {
    const args = process.argv.slice(2); if (args.length) {_main(args); return;}
    console.log(_log("Starting the SOCKS5 server..."));

    _doInit();

    const socksCoreServer = net.createServer({allowHalfOpen: true}, socket => {
        LOG.debug(_log("Connection received.", socket));
        if (firewall.isAllowed(socket)) _handle_initial_client_conection(socket, socksCoreServer);
        else {LOG.error(_log("Firewall block.", socket)); socket.destroy();}
    }).listen(conf.port, conf.host, _ => LOG.console(_log(`Server listening on ${conf.host}:${conf.port}\n`))
    ).on("error", err => {LOG.error(_log("Server received a server socket error")); LOG.error(err);});
}

function _handle_initial_client_conection(socket, socksCoreServer) {
    let messageNumber = 0;

    const negotiateSocksMethod = chunk => {
        const ver = chunk[0]; if (ver != 0x05) throw ("Bad SOCKS5 version byte.");
        const methods = chunk.slice(2);
        const returnMethod = [0x05,methods.includes(0x00)?0x00:0xFF];
        socket.write(Buffer.from(returnMethod));
    }

    const setupProxy = async chunk => {
        const ver = chunk[0]; if (ver != 0x05) throw ("Bad SOCKS5 version byte.");
        const cmd = chunk[1]; if (cmd != 0x01 && cmd != 0x03) throw ("Only CONNECT or UDP ASSOCIATE are supported.");
        let addr = chunk[3] == 0x01 ? chunk.slice(4, 8) : chunk[3] == 0x04 ? chunk.slice(4, 20) : chunk.slice(4+1, 4+1+chunk[4]);
        if (chunk[3] == 0x03) addr = addr.toString("utf-8"); else addr = utils.getIPFromBytes(addr);
        const port = chunk.slice(chunk.length-2).readInt16BE();

        try {
            const {server, remoteSocket} = cmd==0x001?await socks5tcp.createSOCKS5Proxy(port, addr, socket):await socks5udp.createSOCKS5Proxy(port, addr, socket);
            const getPortAsBytes = port => {const buf = Buffer.alloc(2); buf.writeUInt16BE(port); return buf.values();}
            const proxyServer = server||socksCoreServer, reply = [0x05, 0x00, 0x00, proxyServer.address().family == "IPv4" ? 0x01 : 0x04, 
                ...(utils.getIPAsBytes(proxyServer.address().address).values()), ...getPortAsBytes(proxyServer.address().port)];
            socket.write(Buffer.from(reply));   // for SOCKS5 compliant clients, timeout will cleanup the socket
            return {server, remoteSocket, isTCP:cmd==0x001};
        } catch(err) {LOG.error(_log(`Error in setting up proxy: ${err}`, socket)); if (!socket.destroyed) socket.write(Buffer.from([0x05, 0x01, 0x00]));}
    }

    let proxyObj;
    const dataHandler = async chunk => { // all SOCKS5 commands should fit in a chunk
        try {
            if (messageNumber == 0) negotiateSocksMethod(chunk);
            if (messageNumber == 1) proxyObj = await setupProxy(chunk);
            if (messageNumber > 1) if (proxyObj && proxyObj.isTCP) {  // Bad SOCKS5 client! Most probably libcurl nonsense, should be reconnecting to our new port
                LOG.debug(_log("Bad client, RFC 1928 Section 6, doesn't follow reply port. Probably LIBCURL based.", socket));
                socks5tcp.handleSocksClient(socket, proxyObj.remoteSocket, proxyObj.server, chunk, null, true);   
            }
        } catch (err) {
            LOG.error(_log(`Client error, ${err}`, socket));
            socket.end(); socket.destroy();
        }
    }

    if (conf.clientTimeout && conf.clientTimeout != -1) socket.setTimeout(conf.clientTimeout);
    socket.on("data", async chunk => {await dataHandler(chunk); messageNumber++});  
    socket.on("error", err => {LOG.error(_log(`Client socket issue, ${err}.`, socket)); socket.end(); socket.destroy();});
    socket.on("timeout", _=>{LOG.error(_log(`Client socket timeout.`, socket)); socket.end(); socket.destroy();})
}

function _main(args) {  // allows standalone proxy operation, useful for non SOCKS5 clients (e.g. Windows "net use")
    if (args.length < 2 || args.length == 2 && args[0] != "useconf" || args.length < 4 && args[0] != "useconf") {
        console.log("Usage: One of the following options");
        console.log("socks5 <listening host> <listening port> <remote host> <remote port> <optional: timeout>");
        console.log("socks5 useconf <conf_file>");
        process.exit(1);
    }

    /* Override extensions config and init */
    CONSTANTS.EXTENSIONSCONF = CONSTANTS.CONFDIR+"/extensionsCmdLine.json"; _doInit();
    
    /* The server creation function */
    const createProxyServer = (conObj, listeningHost, listeningPort) => {
        net.createServer({allowHalfOpen:true}, client => {
            const remoteSocket = net.connect(conObj, _ => socks5tcp.handleSocksClient(client, remoteSocket)); // resolve once remote is connected
            remoteSocket.once("error", err => {LOG.error(_log(`Couldn't connect to the remote host, ${err}`,client)); client.destroy();});
            remoteSocket.once("timeout", _ => {LOG.error(_log(`Couldn't connect to the remote host, timeout`,client)); client.destroy();});
            remoteSocket.once("end", _ => {LOG.error(_log(`Couldn't connect to the remote host, immediate disconnect`,client)); client.destroy();});
        }).listen(listeningPort, listeningHost, _ => LOG.console(_log(`Created new proxy server listening on ${listeningHost}:${listeningPort}\n`))
        ).on("error", err => {const errMsg = _log(`Couldn't create a new proxy server, ${err}`); LOG.console(errMsg); LOG.error(errMsg, true); process.exit(1);});
    }

    /* Create command line proxies */
    if (args[0] == "useconf") { // read conf file
        let conf; try {conf = require(args[1]);} catch (err) {log.console("Bad config file."); process.exit(1);}
        for (const proxyEntry of conf) {
            const conObj = {host: proxyEntry.remoteHost, port: proxyEntry.remotePort}; 
            if (proxyEntry.timeout) conObj.timeout = proxyEntry.timeout;
            createProxyServer(conObj, proxyEntry.host, proxyEntry.port);
        }
    } else {    // single proxy based on command line arguments
        const conObj = {host: args[2], port: args[3]}; if (args[4]) conObj.timeout = args[4];
        createProxyServer(conObj, args[0], args[1]);
    }
}

module.exports = {bootstrap};