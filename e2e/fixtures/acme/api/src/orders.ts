/** Orders domain logic. Amounts are integer cents. */

export interface Item {
  sku: string;
  quantity: number;
  unitPriceCents: number;
}

export interface CreateOrderOptions {
  /** ISO 4217 code, e.g. "EUR". Required since 2.0. */
  currency: string;
  idempotencyKey?: string;
}

export interface Order {
  id: string;
  customerId: string;
  items: Item[];
  currency: string;
  totalCents: number;
  status: "open" | "cancelled";
}

let nextId = 1;

export function orderTotalCents(items: Item[]): number {
  return items.reduce((sum, item) => sum + item.quantity * item.unitPriceCents, 0);
}

export function createOrder(customerId: string, items: Item[], opts: CreateOrderOptions): Order {
  if (!customerId) throw new Error("customerId is required");
  if (items.length === 0) throw new Error("an order needs at least one item");
  if (!opts || !/^[A-Z]{3}$/.test(opts.currency)) throw new Error("currency is required");
  return {
    id: `ord_${nextId++}`,
    customerId,
    items,
    currency: opts.currency,
    totalCents: orderTotalCents(items),
    status: "open",
  };
}

export function cancelOrder(order: Order): Order {
  if (order.status === "cancelled") return order;
  return { ...order, status: "cancelled" };
}
