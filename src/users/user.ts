import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import axios from "axios";
import {
  createRandomSymmetricKey,
  exportSymKey,
  rsaEncrypt,
  symEncrypt,
} from "../crypto";

type Node = {
  nodeId: number;
  pubKey: string;
};

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  // Implement the status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Implement the /getLastReceivedMessage route
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Implement the /getLastSentMessage route
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Implement the /message route
  _user.post("/message", (req, res) => {
    const { message } = req.body as SendMessageBody;
    lastReceivedMessage = message;
    res.sendStatus(200);
  });

  // Implement the /sendMessage route
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;
    lastSentMessage = message;

    // Get the node registry
    const { data } = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
    const nodes = data.nodes;

    // Create a random circuit of 3 distinct nodes
    const circuit: Node[] = [];
    while (circuit.length < 3) {
      const randomNode = nodes[Math.floor(Math.random() * nodes.length)];
      if (!circuit.includes(randomNode)) {
        circuit.push(randomNode);
      }
    }

    // Create each layer of encryption
    let encryptedMessage = message;
    for (let i = 0; i < circuit.length; i++) {
      const symmetricKey = await createRandomSymmetricKey();
      const strSymKey = await exportSymKey(symmetricKey);
      const encryptedSymKey = await rsaEncrypt(strSymKey, circuit[i].pubKey);
      encryptedMessage = await symEncrypt(symmetricKey, encryptedMessage);
      encryptedMessage = encryptedSymKey + encryptedMessage;
    }

    // Forward the encrypted message to the entry node
    await axios.post(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
      message: encryptedMessage,
    });

    res.sendStatus(200);
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
