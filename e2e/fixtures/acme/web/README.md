# acme/web (e2e fixture)

Storefront that creates orders through `@acme/api` (`createOrder`). Used by the xrepo-review
end-to-end test: the e2e pull request changes `src/checkout.ts` so that it calls `createOrder`
with the pre-2.0 signature, which the reviewer must catch by reading `/repos/acme/api`.
