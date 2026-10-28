import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { API_HOST } from "./host.js";

/**
 * server.ts is never imported here, because importing it loads .env and starts
 * listening. Its source is parsed into a syntax tree instead, so strings and
 * comments (such as the `//` in a URL) cannot be mistaken for each other.
 */
function parse(file: string): ts.SourceFile {
  const text = readFileSync(new URL(file, import.meta.url), "utf8");
  return ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function nodesOf<T extends ts.Node>(root: ts.Node, guard: (node: ts.Node) => node is T): T[] {
  const found: T[] = [];
  const visit = (node: ts.Node): void => {
    if (guard(node)) found.push(node);
    ts.forEachChild(node, visit);
  };
  visit(root);
  return found;
}

/** Every piece of literal string text in a file, including the fixed parts of template strings. */
function literalTexts(root: ts.Node): string[] {
  return nodesOf(root, (n): n is ts.Node => ts.isStringLiteralLike(n) || ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n))
    .map((n) => (n as ts.LiteralLikeNode).text);
}

const isCallTo = (name: string) => (n: ts.Node): n is ts.CallExpression =>
  ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === name;

describe("Phase J: the API listens on IPv4 loopback only", () => {
  it("the host constant is exactly 127.0.0.1", () => {
    expect(API_HOST).toBe("127.0.0.1");
  });

  it("a server started with the constant listens on loopback, not a wildcard address", async () => {
    const server = createApp().listen(0, API_HOST);
    try {
      // A bind failure rejects here with its own error instead of timing out.
      await new Promise<void>((resolve, reject) => {
        server.once("listening", () => resolve());
        server.once("error", reject);
      });
      const address = server.address() as AddressInfo;
      expect(address.address).toBe("127.0.0.1");
      expect(address.family).toBe("IPv4");
      expect(["::", "0.0.0.0", "::ffff:0.0.0.0", ""]).not.toContain(address.address);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("the server entry point passes the constant to its only listen call", () => {
    const source = parse("./server.ts");
    const hostImport = source.statements.filter(ts.isImportDeclaration).find((d) => (d.moduleSpecifier as ts.StringLiteral).text === "./host.js");
    const named = hostImport?.importClause?.namedBindings;
    expect(named && ts.isNamedImports(named) ? named.elements.map((e) => e.name.text) : []).toEqual(["API_HOST"]);

    const listens = nodesOf(source, isCallTo("listen"));
    expect(listens).toHaveLength(1);
    const [portArg, hostArg] = listens[0]!.arguments;
    expect(portArg && ts.isIdentifier(portArg) ? portArg.text : null).toBe("port");
    expect(hostArg && ts.isIdentifier(hostArg) ? hostArg.text : null).toBe("API_HOST");

    // No literal host anywhere in the file can replace or misdescribe the binding.
    for (const text of literalTexts(source)) {
      expect(text).not.toMatch(/localhost|0\.0\.0\.0/);
      expect(text.trim()).not.toBe("::");
    }
  });

  it("the startup log reports the address and port the server actually bound", () => {
    const source = parse("./server.ts");
    // const { address, port: boundPort } = server.address() as AddressInfo;
    const bound = nodesOf(source, ts.isVariableDeclaration).find((d) => {
      const init = d.initializer && ts.isAsExpression(d.initializer) ? d.initializer.expression : d.initializer;
      return init !== undefined && isCallTo("address")(init) && ts.isObjectBindingPattern(d.name);
    });
    expect(bound).toBeDefined();
    const names = (bound!.name as ts.ObjectBindingPattern).elements.map((e) => [
      e.propertyName && ts.isIdentifier(e.propertyName) ? e.propertyName.text : (e.name as ts.Identifier).text,
      (e.name as ts.Identifier).text,
    ]);
    expect(names).toEqual([["address", "address"], ["port", "boundPort"]]);

    const logs = nodesOf(source, isCallTo("log"));
    expect(logs).toHaveLength(1);
    const message = logs[0]!.arguments[0];
    if (!message || !ts.isTemplateExpression(message)) throw new Error("startup log is not a template string");
    expect(message.head.text).toBe("AgentShield API listening on http://");
    expect(message.templateSpans.map((span) => (ts.isIdentifier(span.expression) ? span.expression.text : null))).toEqual(["address", "boundPort"]);
    expect(message.templateSpans.map((span) => span.literal.text)).toEqual([":", " (loopback only, no authentication)"]);
  });

  it("the host module imports nothing and reads no configuration or secrets", () => {
    const source = parse("./host.ts");
    expect(source.statements).toHaveLength(1);
    const statement = source.statements[0]!;
    if (!ts.isVariableStatement(statement)) throw new Error("host.ts must hold only the constant");
    expect(statement.modifiers?.map((m) => m.kind)).toEqual([ts.SyntaxKind.ExportKeyword]);
    expect(statement.declarationList.flags & ts.NodeFlags.Const).toBeTruthy();
    const [declaration] = statement.declarationList.declarations;
    expect((declaration!.name as ts.Identifier).text).toBe("API_HOST");
    expect(declaration!.initializer && ts.isStringLiteral(declaration!.initializer) ? declaration!.initializer.text : null).toBe("127.0.0.1");
    // No imports, require calls, dynamic imports, or environment access.
    expect(nodesOf(source, (n): n is ts.Node => ts.isImportDeclaration(n) || ts.isImportEqualsDeclaration(n))).toHaveLength(0);
    expect(nodesOf(source, (n): n is ts.CallExpression => ts.isCallExpression(n))).toHaveLength(0);
    expect(nodesOf(source, (n): n is ts.PropertyAccessExpression => ts.isPropertyAccessExpression(n))).toHaveLength(0);
  });
});
