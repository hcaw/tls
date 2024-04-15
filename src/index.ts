import net from 'node:net';
import crypto from 'node:crypto';
import { createX25519KeyPair } from './crypto';

const serverHost = 'google.com';
const serverPort = 443;

// async function go() {
// 	const keyPair = await createX25519KeyPair();
// 	console.log(keyPair.privateKey);
// 	console.log(keyPair.publicKey);
// }

const hexString =
  '16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeeae329adf9121383851ed21a28e3b75e965d0d2cd166254';

const clientHello = Buffer.from(hexString, 'hex');

const socket = net.createConnection(serverPort, serverHost, () => {
  console.log('Connected to server');
  // Send the ClientHello message to the server
  socket.write(clientHello);
});

socket.on('data', (data) => {
  console.log('Received data from server:', data.toString('hex'));
  // Handle server's response here
  parseServerResponse(data);
});

socket.on('error', (error) => {
  console.error('Socket error:', error);
});

socket.on('close', () => {
  console.log('Connection closed');
});

function parseServerResponse(data: Buffer) {
  // Check if the first byte indicates a ServerHello message
  if (data[0] === 0x16 && data[1] === 0x03) {
    // ServerHello message found
    const serverHello = data.slice(0, 36); // Assuming ServerHello message is 36 bytes
    console.log('ServerHello message:', serverHello.toString('hex'));

    // Extract SSL/TLS version, cipher suite, and other parameters from ServerHello message
    const serverTlsVersion = serverHello.slice(3, 5); // SSL/TLS version
    const cipherSuite = serverHello.slice(9, 11); // Cipher suite
    // Parse other parameters as needed

    // Handle SSL/TLS version and cipher suite negotiation
    console.log(
      'Server selected SSL/TLS version:',
      serverTlsVersion.toString('hex'),
    );
    console.log('Server selected cipher suite:', cipherSuite.toString('hex'));

    // Implement further logic based on server's response
  } else {
    console.log('Unexpected data received from server:', data.toString('hex'));
    // Handle unexpected data
  }
}
