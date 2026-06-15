import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const restart = vscode.commands.registerCommand(
    "rastray.restartServer",
    async () => {
      await stopClient();
      await startClient(context);
    }
  );
  context.subscriptions.push(restart);

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(async (event) => {
      if (
        event.affectsConfiguration("rastray.serverPath") ||
        event.affectsConfiguration("rastray.serverArgs") ||
        event.affectsConfiguration("rastray.trace.server")
      ) {
        await stopClient();
        await startClient(context);
      }
    })
  );

  void startClient(context);
}

export async function deactivate(): Promise<void> {
  await stopClient();
}

async function startClient(context: vscode.ExtensionContext): Promise<void> {
  const config = vscode.workspace.getConfiguration("rastray");
  const serverPath = config.get<string>("serverPath", "rastray");
  const serverArgs = config.get<string[]>("serverArgs", ["lsp"]);

  const serverOptions: ServerOptions = {
    run: {
      command: serverPath,
      args: serverArgs,
      transport: TransportKind.stdio,
    },
    debug: {
      command: serverPath,
      args: serverArgs,
      transport: TransportKind.stdio,
    },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "rust" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "go" },
      { scheme: "file", language: "java" },
    ],
    outputChannelName: "rastray",
    synchronize: {
      configurationSection: "rastray",
    },
  };

  client = new LanguageClient(
    "rastray",
    "rastray",
    serverOptions,
    clientOptions
  );

  try {
    await client.start();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    void vscode.window.showErrorMessage(
      `rastray: failed to start language server (${serverPath}): ${message}. ` +
        "Install rastray from https://github.com/balangyaoejuspher/rastray and set rastray.serverPath if it is not on PATH."
    );
    client = undefined;
    return;
  }

  context.subscriptions.push({
    dispose: () => {
      void stopClient();
    },
  });
}

async function stopClient(): Promise<void> {
  if (!client) {
    return;
  }
  const local = client;
  client = undefined;
  try {
    await local.stop();
  } catch {
    // best-effort shutdown; nothing actionable
  }
}
