import type { Item } from "@acme/api";

export interface Cart {
  customerId: string;
  currency: string;
  items: Item[];
}

export function addItem(cart: Cart, item: Item): Cart {
  return { ...cart, items: [...cart.items, item] };
}
