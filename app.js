// install first: npm install socket.io-client
const { io } = require("socket.io-client");
const mqtt = require('mqtt');
require("dotenv").config();

// Constants
const SERVER_KEY = process.env.SERVER_KEY || "super";
const client = mqtt.connect('mqtt://localhost:1885', {
  clientId: 'plc',
  username: 'super', // optional
  password: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbXMzOSI6NjI4NzgsInFhMnR5IjpmYWxzZSwibjBkeXMiOiJ6bDJwOW5lNiIsImpmcGM5IjpmYWxzZSwiaWF0IjoxNzU1OTE1MDY3fQ.90f-AU3cltPwDCf3ZXs8zv-aMHhajI_uhsXQO5c16U8'
});
// connect to your server
const socket = io("http://localhost:3000", {
  auth: {
    serverKey: SERVER_KEY  // only agents know this
  }
});

socket.on("connect", () => {
  console.log("Connected to server");
  // emit registreServer when connected
  socket.emit("registre_server", SERVER_KEY);
});
client.on('connect', () => {
  console.log(`Connected to MQTT broker`);
});
// listen for setConsigne event
socket.on("set_status", (data) => {
  console.log("Received setConsigne:", data);
  console.log(data.uploadID)
  socket.emit("set_status_ack", {uploadID:data.uploadID,approve:true})
  // if you want to reply with ack:
  // socket.emit("consigneAck", { status: "ok", received: data });
});

socket.on("set_parameter", (data) => {
  console.log("Received setParameter:", data);
  console.log(data.uploadID)
  socket.emit("set_parameter_ack", {uploadID:data.uploadID,approve:true})
  // if you want to reply with ack:
  // socket.emit("consigneAck", { status: "ok", received: data });
});

socket.on("set_consigne", (data) => {
  console.log("Received setConsigne:", data);
  console.log(data.uploadID ,data.data.value)
  socket.emit("set_consigne_ack", {uploadID:data.uploadID,approve:true})
  // if you want to reply with ack:
  // socket.emit("consigneAck", { status: "ok", received: data });
});
socket.on("set_consigneperlevel", (data) => {
  console.log("Received setConsigne pere level:", data);
  console.log(data.uploadID)
  socket.emit("set_consigneperlevel_ack", {uploadID:data.uploadID,approve:true})
  // if you want to reply with ack:
  // socket.emit("consigneAck", { status: "ok", received: data });
});
socket.on('"set_actionStatus', (data) => {
  console.log("Received actionStatus:", data);
  console.log(data.uploadID)
  socket.emit("set_actionStatus", {uploadID:data.uploadID,approve:true})
  // if you want to reply with ack:
  // socket.emit("consigneAck", { status: "ok", received: data });
});
socket.on("disconnect", () => {
  console.log("Disconnected");
});
