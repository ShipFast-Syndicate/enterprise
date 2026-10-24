// Only the slice of the workerd-provided `cloudflare:workers` module these
// tests read: the bindings `vitest.config.ts` declares for the workerd project.
declare module "cloudflare:workers" {
  export const env: { IDP_CERT: string };
}
