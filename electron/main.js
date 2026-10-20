const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let pythonProcess = null;

function startBackend() {
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
  const projectRoot = path.join(__dirname, '..');

  pythonProcess = spawn(pythonCmd, ['src/main.py'], {
    cwd: projectRoot,
    stdio: 'inherit'
  });

  pythonProcess.on('error', (err) => {
    console.error('Không thể khởi chạy backend Python:', err);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 640,
    title: 'AI Early Web Attack Detection - SOC Desktop',
    backgroundColor: '#0f172a',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  // Tải giao diện từ backend Flask
  setTimeout(() => {
    mainWindow.loadURL('http://127.0.0.1:5000');
  }, 1500);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  startBackend();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (pythonProcess) {
    pythonProcess.kill();
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
