import { createOrder, type Order } from "@acme/api";
import type { Cart } from "./cart.js";

/** Turns the cart into an order. */
export function checkout(cart: Cart): Order {
  if (cart.items.length === 0) throw new Error("cart is empty");
  return createOrder(cart.customerId, cart.items, { currency: cart.currency });
}
