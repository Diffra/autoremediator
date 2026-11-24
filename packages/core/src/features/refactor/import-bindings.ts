/**
 * Finds how a source file imports the package being migrated: default, namespace and subpath
 * imports, with the import declarations they come from.
 */

export interface ImportBindings {
  defaultLocalName: string | undefined;
  namespaceLocalName: string | undefined;
  defaultImportDecl: any;
  subpathImportDecl: any;
  subpathName: string | undefined;
}

export function collectImportBindings(body: any[], packageName: string): ImportBindings {
  const bindings: ImportBindings = {
    defaultLocalName: undefined,
    namespaceLocalName: undefined,
    defaultImportDecl: undefined,
    subpathImportDecl: undefined,
    subpathName: undefined,
  };

  for (const statement of body) {
    if (statement.type === "ImportDeclaration" && statement.source?.value) {
      const specText = String(statement.source.value);
      if (specText === packageName) {
        recordPackageImport(bindings, statement);
      } else if (specText.startsWith(`${packageName}/`)) {
        recordSubpathImport(bindings, statement, specText.slice(packageName.length + 1));
      }
    }
  }

  return bindings;
}

function recordPackageImport(bindings: ImportBindings, statement: any): void {
  for (const spec of statement.specifiers || []) {
    if (spec.type === "ImportDefaultSpecifier") {
      bindings.defaultLocalName = spec.local?.name;
      bindings.defaultImportDecl = statement;
    } else if (spec.type === "ImportNamespaceSpecifier") {
      bindings.namespaceLocalName = spec.local?.name;
    }
  }
}

function recordSubpathImport(bindings: ImportBindings, statement: any, subpath: string): void {
  bindings.subpathImportDecl = statement;
  bindings.subpathName = subpath;
  for (const spec of statement.specifiers || []) {
    if (spec.type === "ImportDefaultSpecifier") {
      bindings.defaultLocalName = spec.local?.name;
    }
  }
}
