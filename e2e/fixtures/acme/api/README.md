# acme/api (e2e fixture)

Orders service used by the xrepo-review end-to-end test.

## Breaking change in 2.0

`createOrder` takes a third, required argument: `opts: { currency: string }`. Orders without a
currency are rejected (`currency is required`). Consumers must pass the cart currency.
