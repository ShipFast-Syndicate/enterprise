// @ts-check
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "sql/**", "coverage/**", "node_modules/**"],
  },
  tseslint.configs.recommended,
);
