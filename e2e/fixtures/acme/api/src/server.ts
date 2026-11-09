import { createServer } from "node:http";
import { createOrder, type Item } from "./orders.js";

/** POST /orders {customerId, items, currency} -> 201 Order | 400 {error} */
export const server = createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/orders") {
    res.writeHead(404).end();
    return;
  }
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    try {
      const { customerId, items, currency } = JSON.parse(body) as { customerId: string; items: Item[]; currency: string };
      const order = createOrder(customerId, items, { currency });
      res.writeHead(201, { "content-type": "application/json" }).end(JSON.stringify(order));
    } catch (e) {
      res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: (e as Error).message }));
    }
  });
});
