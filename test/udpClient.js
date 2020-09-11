/**
 * Test UDP client which uses SOCKS5 relay.
 * Sends an initial hello on connect, echoes responses and keeps
 * sending hellos back to them in response.
 * 
 * Needs socks NPM. npm install socks.
 */
const SocksClient = require('socks').SocksClient;
let info;

const udpSocket = require('dgram').createSocket('udp4');
udpSocket.bind();

const sendUDPMsg = _ => {
    const packet = SocksClient.createUDPFrame({remoteHost: { host: '192.168.10.33', port: 4444 }, data: Buffer.from("Hello\n")});
    udpSocket.send(packet, info.remoteHost.port, info.remoteHost.host);
}

udpSocket.on('message', (msg, rinfo) => {
    console.log(`\n\nReceived new packet, rinfo is: ${JSON.stringify(rinfo)}`);
    const parsedMsg = SocksClient.parseUDPFrame(msg);
    console.log(`Parsed frame follows\n${JSON.stringify(parsedMsg)}`);
    console.log(`Decoded data is: ${parsedMsg.data.toString('utf8')}`);
    sendUDPMsg();
});

const associateOptions = { proxy: {host: '192.168.10.33', port: 1080, type: 5}, command: 'associate', 
    destination: {host: '192.168.10.33', port: 4444}, timeout: 600000 };
const client = new SocksClient(associateOptions);
client.on('established', socksinfo => {
    console.log(`Got connected to the UDP SOCKS5 Proxy\nInfo is: ${JSON.stringify(socksinfo)}`);
    info = socksinfo; sendUDPMsg();
});
client.connect();