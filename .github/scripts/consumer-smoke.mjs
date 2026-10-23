// Runs inside a scratch consumer project that installed the packed tarball
// (CI) or the published version (post-release smoke). Imports every public
// entry point through the package name, exactly as a consumer would.
import { Window } from "happy-dom";

const server = await import("@alphabros/enterprise/server");
const schema = await import("@alphabros/enterprise/schema");
const client = await import("@alphabros/enterprise/client");

// The portal registers custom elements on import, so it needs a DOM.
const window = new Window();
// Expose the window's DOM globals the way a browser would, without
// overriding Node's own (fetch, URL, crypto, ...).
for (const key of Object.getOwnPropertyNames(window))
  if (!(key in globalThis)) globalThis[key] = window[key];
globalThis.window = window;
const portal = await import("@alphabros/enterprise/portal");

for (const [name, module] of Object.entries({ server, schema, client, portal })) {
  if (Object.keys(module).length === 0) throw new Error(`${name} exports nothing`);
  console.log(`${name}: ${Object.keys(module).length} exports`);
}
if (typeof server.enterprisePreset !== "function")
  throw new Error("server.enterprisePreset missing");
if (!window.customElements.get("ab-members"))
  throw new Error("portal did not register <ab-members>");
console.log("Consumer import smoke OK");
