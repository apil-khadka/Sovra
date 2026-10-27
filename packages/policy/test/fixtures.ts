import { readFileSync } from "node:fs";

/** Load a canonical JSON fixture shared by the executable test suite. */
export function loadFixture<T>(name: string): T {
  const url = new URL(`../../../tests/fixtures/${name}`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as T;
}
