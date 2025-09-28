// broker.js
// Aedes MQTT broker module
const aedes = require('aedes')();
const net = require('net');
const WebSocket = require('ws');
const websocketStream = require('websocket-stream');

function attachWebSocket(server, path = '/mqtt') {
  const wss = new WebSocket.Server({ server, path });
  wss.on('connection', (ws) => {
    const stream = websocketStream(ws);
    aedes.handle(stream);
  });
  console.log(`Aedes broker attached to WebSocket path: ${path}`);
}

function attachTCP(port = 1883) {
  const tcpServer = net.createServer(aedes.handle);
  tcpServer.listen(port, () => {
    console.log(`Aedes TCP broker listening on ${port}`);
  });
  return tcpServer;
}

function getBroker() {
  return aedes;
}

function closeBroker(cb) {
  aedes.close(cb);
}

module.exports = { attachWebSocket, attachTCP, getBroker, closeBroker };
