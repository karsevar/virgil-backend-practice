const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const {VirgilCrypto, VirgilAccessTokenSigner} = require('virgil-crypto');
const {JwtGenerator} = require('virgil-sdk');

const { requireAuthHeader } = require('./userValidation');
const { authenticate } = require('./authenticate');

const virgilCrypto = new VirgilCrypto();

const accessTokenSigner = new VirgilAccessTokenSigner(virgilCrypto);

console.log(process.env.APP_KEY)

const appKey = virgilCrypto.importPrivateKey(process.env.APP_KEY);

const jwtGenerator = new JwtGenerator({
    appId: process.env.APP_ID,
    apiKey: appKey,
    apiKeyId: process.env.APP_KEY_ID,
    accessTokenSigner: new VirgilAccessTokenSigner(virgilCrypto),
    millisecondsToLive: 20 * 60 * 1000
});

const keyPair = virgilCrypto.generateKeys();
const privateKeyData = virgilCrypto.exportPrivateKey(keyPair.privateKey);

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
    res.status(200).json({message: 'server is working!!!'})
})
server.post('/authenticate', authenticate);

server.get('/virgil-jwt', requireAuthHeader, (req, res) => {
    
    const virgilJwtToken = jwtGenerator.generateToken(req.user.identity);
    res.json({ virgilToken: virgilJwtToken.toString()})
    
})

server.post('/virgil-signature', (req, res) => {
    const signingKeypair = virgilCrypto.generateKeys();
    const signature = virgilCrypto.calculateSignature(req.body.email, signingKeypair.privateKey)
    // const jwt = jwtGenerator.generateToken(req.body.email);
    const verified = virgilCrypto.verifySignature(req.body.email, signature, signingKeypair.publicKey)
    res.status(200).json({jwtSigningpair: signature, verify: verified})
})

server.post('/virgil-encrypt', (req, res) => {
    const signingKeypair = virgilCrypto.generateKeys();
    const signature = virgilCrypto.encrypt(req.body.email, signingKeypair.publicKey)
    // const jwt = jwtGenerator.generateToken(req.body.email);
    const decryption = virgilCrypto.decrypt(signature, signingKeypair.privateKey)
    // const verifyDecryption = virgilCrypto.decryptThenVerify(signature, signingKeypair.privateKey, signingKeypair.publicKey)
    res.status(200).json({encryption: signature.toString('base64'), decryptedValue: decryption.toString('utf8')})
})



module.exports = server;