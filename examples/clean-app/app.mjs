/** A deliberately small, dependency-free source fixture for the Guardian-Unit demo. */
export function greeting(name) {
  const safeName = String(name ?? "friend").replace(/[<>&"']/g, "");
  return Object.freeze({ message: `Hello, ${safeName || "friend"}!` });
}
