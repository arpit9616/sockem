/* 
 * (C) 2020 TekMonks. All rights reserved.
 * Manages extensions
 */

const conf = require(CONSTANTS.EXTENSIONSCONF || CONSTANTS.CONFDIR+"/extensions.json");
const _log = (message, socket) => socket?`[SOCKS5] [${socket.remoteAddress}:${socket.remotePort}] ${message}`:`[SOCKS5] ${message}`;

let preConnects = [], preOuts = [], preIns = [];

function initSync() {
    for (const extPreConnect of conf.pre_connect)
        preConnects.push(require(`${CONSTANTS.EXTDIR}/${extPreConnect}.js`));
    for (const extPreOut of conf.pre_out)
        preOuts.push(require(`${CONSTANTS.EXTDIR}/${extPreOut}.js`));
    for (const extPreIn of conf.pre_in)
        preIns.push(require(`${CONSTANTS.EXTDIR}/${extPreIn}.js`));
}

function preConnect(host, port) {
    let retObj = {host, port};
    for (const preConnect of preConnects) retObj = preConnect.preConnect(retObj.host, retObj.port);
    return retObj;
}

function preOut(socket, chunk) {
    try {
        let chunkOut = chunk;
        for (const preOut of preOuts) chunkOut = preOut.preOut(socket, chunk);
        return chunkOut;
    } catch (err) {
        LOG.error(_log(`Error in preOut, sending back original data ${err}`, socket));
        return chunk;
    }
}

function preIn(socket, chunk, callback) {
    const fns = [];  for (const preIn of preIns) fns.push(preIn.preIn);
    const chainCall = data => {
        if (!fns.length) {callback(data); return;}
        const fn = fns.shift();
        try {fn(socket, data, chainCall)} catch (err) {
            LOG.error(_log(`Error in preIn, sending back original data ${err}`, socket));
            callback(data);
        }
    }
    chainCall(chunk);
}

module.exports = {initSync, preConnect, preOut, preIn}