const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("api", {
  fetchFastly: () => ipcRenderer.invoke("fastly:fetch"),
  openCidrFile: () => ipcRenderer.invoke("cidr:file:open"),
  startScan: (config) => ipcRenderer.invoke("scan:start", config),
  saveResults: (payload) => ipcRenderer.invoke("scan:save", payload),
stopScan: () => ipcRenderer.invoke("scan:stop"),

  onStage: (cb) => ipcRenderer.on("scan:stage", (_, data) => cb(data)),
  onProgress: (cb) => ipcRenderer.on("scan:progress", (_, data) => cb(data)),
  onValid: (cb) => ipcRenderer.on("scan:valid", (_, data) => cb(data)),
  onLog: (cb) => ipcRenderer.on("scan:log", (_, data) => cb(data))
});
