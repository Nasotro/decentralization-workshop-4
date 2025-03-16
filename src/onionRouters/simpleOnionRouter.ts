import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import {
  generateRsaKeyPair,
  exportPubKey,
  exportPrvKey,
  importPrvKey,
  rsaDecrypt,
  symDecrypt,
} from "../crypto";
import axios from "axios";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // Generate RSA key pair
  const { publicKey, privateKey } = await generateRsaKeyPair();
  const strPubKey = await exportPubKey(publicKey);
  const strPrvKey = await exportPrvKey(privateKey);

  // Register the node with the registry
  await axios.post(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    nodeId,
    pubKey: strPubKey,
  });

  // Implement the status route
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // Implement the /getLastReceivedEncryptedMessage route
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // Implement the /getLastReceivedDecryptedMessage route
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // Implement the /getLastMessageDestination route
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Implement the /getPrivateKey route
  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: strPrvKey });
  });

  // Implement the /message route
  onionRouter.post("/message", async (req, res) => {
    const { message } = req.body;
    lastReceivedEncryptedMessage = message;
    
    // Decrypt the outer layer
    if (strPrvKey === null) {
      res.status(500).send("Private key is not available");
      return;
    }
    console.log(`Onion router ${nodeId} received message: ${message}`);

    // const prvKey = await importPrvKey(strPrvKey);
    const rsaEncryptedSymmKey = message.slice(0, 344);
    const cipherText = message.slice(344);
    const symKey = await rsaDecrypt(rsaEncryptedSymmKey, privateKey);
    const decryptedMessage = await symDecrypt(symKey, cipherText);

    lastReceivedDecryptedMessage = decryptedMessage.slice(10);

    // Discover the next destination
    lastMessageDestination = parseInt(decryptedMessage.slice(0, 10), 10);

    
    console.log(`Onion router ${nodeId} forwarding message to ${lastMessageDestination}`);

    // Forward the message to the next node or user
    if (lastMessageDestination >= BASE_ONION_ROUTER_PORT && lastMessageDestination < BASE_ONION_ROUTER_PORT + 10) {
      await axios.post(`http://localhost:${lastMessageDestination}/message`, { message: decryptedMessage.slice(10) });
    } else {
      await axios.post(`http://localhost:${lastMessageDestination}/message`, { message: decryptedMessage.slice(10) });
    }

    res.sendStatus(200);
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
