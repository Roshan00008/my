// Resolution hook: the worker source uses bundler-style extensionless
// relative imports, which Node's type-stripping loader doesn't resolve.
// Append ".ts" when the bare specifier misses.
export async function resolve(specifier, context, next) {
  if (
    (specifier.startsWith("./") || specifier.startsWith("../")) &&
    !/\.(ts|js|mjs|json)$/.test(specifier)
  ) {
    try {
      return await next(specifier + ".ts", context);
    } catch {
      // fall through to default resolution
    }
  }
  return next(specifier, context);
}
