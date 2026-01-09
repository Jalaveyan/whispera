
// Window Controls Module
// Handles Minimize, Maximize/Restore, Close functionality

async function getWindow() {
    // Try Tauri v2 Import
    try {
        const { getCurrentWindow } = await import('@tauri-apps/api/window');
        return getCurrentWindow();
    } catch (e) {
        // Fallback to global
        if (window.__TAURI__ && window.__TAURI__.window) {
            return window.__TAURI__.window.getCurrentWindow();
        }
    }
    console.warn('[WindowControls] Tauri API not found');
    return null;
}

export async function initWindowControls() {
    const btnMin = document.getElementById('btn-minimize');
    const btnMax = document.getElementById('btn-maximize');
    const btnClose = document.getElementById('btn-close');

    const appWindow = await getWindow();

    if (!appWindow) {
        console.log('[WindowControls] Running in browser mode (mocking controls)');
        return;
    }

    if (btnMin) {
        btnMin.addEventListener('click', () => appWindow.minimize());
    }

    if (btnMax) {
        btnMax.addEventListener('click', async () => {
            await appWindow.toggleMaximize();
        });
    }

    if (btnClose) {
        btnClose.addEventListener('click', () => appWindow.close());
    }

    console.log('[WindowControls] Initialized');
}
