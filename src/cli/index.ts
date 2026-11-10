#!/usr/bin/env node
// Alpha Bros enterprise layer — CLI entry point (ab-enterprise bin). The
// `#!/usr/bin/env node` line above is part of this source file (esbuild
// preserves an entry point's hashbang verbatim) rather than a tsup `banner`,
// see `./main.ts`, where the commands live (so a test can call `main()` in
// process); this file only runs it.
import { main } from "./main";

export { insertStatementBreakpoints } from "./main";

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  },
);
