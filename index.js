const fs = require('fs');
const WebSocket = require('ws');
const { publicEncrypt, constants, randomBytes, createCipheriv, createDecipheriv } = require('crypto');

let EventEmitter = require('events').EventEmitter

function symDecrypt(aesKey, encrypted, iv){
  let decipher = createDecipheriv('aes-256-cbc', aesKey, Buffer.from(iv, 'base64'));
  let decrypted = decipher.update(encrypted, 'base64')
  decrypted += decipher.final('utf8');
  return decrypted;
}

function symEncrypt(aesKey, data){
  let aesIV = randomBytes(16);
  let cipher = createCipheriv('aes-256-cbc', aesKey, aesIV);
  let encryptedData = cipher.update(data, "utf8", "base64");
  encryptedData += cipher.final("base64");
  return {iv: aesIV.toString('base64'), encrypted: encryptedData};
}

function PSMSClient(host, port, publicKey, passphrase){
  let aesKey = randomBytes(32);
  let client = new EventEmitter();
  let ws = null;

  let self = this;
  this.handleEvent = (name, data) => {
    if(name == "RECEIVED_SMS"){
      client.emit('onNewMessage', data);
    }else if(name == "MESSAGES"){
      client.emit('onStoredMessages', data);
    }
  };

  client.open = (callback) => {
    ws = new WebSocket("ws://" + host + ":" + port);
    ws.on('open', () => {
      const handshakeDetails = {
        "aesKey": aesKey.toString('base64'),
        "passphrase": passphrase
      };
      const stringified = JSON.stringify(handshakeDetails);

      const encryptedData = publicEncrypt({
        key: publicKey,
        padding: constants.RSA_PKCS1_PADDING
      }, Buffer.from(stringified));
      ws.send(encryptedData);

      callback();

      ws.on('message', (data) => {
        const parsed = JSON.parse(data);
        const decrypted = symDecrypt(aesKey, parsed.encrypted, parsed.iv);
        let parsedDecrypted = JSON.parse(decrypted);

        self.handleEvent(parsedDecrypted.name, parsedDecrypted.data);
      });
    });
  };
  client.requestStoredMessages = (limit=0) => {
    let obj = {
      name: "GET_MESSAGES",
      data: {
        limit
      }
    };
    let encryptedStringified = JSON.stringify(symEncrypt(aesKey, JSON.stringify(obj)));
    ws.send(encryptedStringified);
  };
  client.sendSMS = (phoneNumber, content) => {
    let obj = {
      name: "SEND_SMS",
      data: {
        phoneNumber,
        content
      }
    };
    let encryptedStringified = JSON.stringify(symEncrypt(aesKey, JSON.stringify(obj)));
    ws.send(encryptedStringified);
  };

  return client;
}

module.exports = PSMSClient;
