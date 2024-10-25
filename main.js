const { app, BrowserWindow } = require('electron');
const path = require('path');
const { exec } = require('child_process');

let mainWindow;

// Function to create the Electron window
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true
        }
    });

    // Load Django's URL in the window (assume Django is running on http://127.0.0.1:8000)
    mainWindow.loadURL('http://127.0.0.1:8000');

    mainWindow.on('closed', function () {
        mainWindow = null;
    });
}

// Start Django server
function startDjangoServer() {
    // Modify this path to point to your manage.py
    let djangoProcess = exec('python manage.py runserver', { cwd: __dirname });

    djangoProcess.stdout.on('data', (data) => {
        console.log(`Django: ${data}`);
    });

    djangoProcess.stderr.on('data', (data) => {
        console.error(`Django Error: ${data}`);
    });

    djangoProcess.on('exit', (code) => {
        console.log(`Django exited with code ${code}`);
    });
}

app.on('ready', () => {
    startDjangoServer();
    createWindow();
});

app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', function () {
    if (mainWindow === null) {
        createWindow();
    }
});
