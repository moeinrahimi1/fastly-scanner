const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const fs = require("fs");

const { runSmartScan, fetchFastlyCidrs } = require("./scanner");

let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile(path.join(__dirname, "renderer/index.html"));
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

ipcMain.handle("fastly:fetch", async () => {
  return await fetchFastlyCidrs({ timeout: 8000 });
});

ipcMain.handle("cidr:file:open", async () => {
  const res = await dialog.showOpenDialog(win, {
    properties: ["openFile"],
    filters: [{ name: "Text", extensions: ["txt"] }]
  });
  if (res.canceled || !res.filePaths?.[0]) return null;

  const filePath = res.filePaths[0];
  const text = fs.readFileSync(filePath, "utf8");
  const cidrs = text
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);

  return { filePath, cidrs };
});

ipcMain.handle("scan:start", async (evt, config) => {
  // run scan in-process but async; send progress events to renderer
  const send = (channel, payload) => {
    if (!win || win.isDestroyed()) return;
    win.webContents.send(channel, payload);
  };

  const result = await runSmartScan(config, {
    onStage: (s) => send("scan:stage", s),
    onProgress: (p) => send("scan:progress", p),
    onValid: (v) => send("scan:valid", v),
    onLog: (l) => send("scan:log", l)
  });

  return result;
});

ipcMain.handle("scan:save", async (evt, { txt, csv }) => {
  const res = await dialog.showOpenDialog(win, {
    properties: ["openDirectory"]
  });
  if (res.canceled || !res.filePaths?.[0]) return null;

  const dir = res.filePaths[0];
  const txtPath = path.join(dir, "valid.txt");
  const csvPath = path.join(dir, "valid.csv");

  fs.writeFileSync(txtPath, txt, "utf8");
  fs.writeFileSync(csvPath, csv, "utf8");

  return { txtPath, csvPath };
});
