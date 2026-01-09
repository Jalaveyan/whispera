/**
 * Whispera Client - Main Entry Point
 * This file imports all modules and initializes the application
 */

// Import all modules
import { initSettings, loadSettings, getSetting, setSetting, currentSettings } from './modules/settings_persistence.js';
import { keyConnectionManager } from './modules/key_connection.js';
import { initI18n, toggleLanguage, translations } from './modules/i18n.js';
import { initNotifications } from './modules/notifications.js';
import { initWindowControls } from './modules/window_controls.js';
import { waveAnimator } from './modules/wave_animator.js';
import { activeConnectionManager } from './modules/active_connections.js';

// Dashboard data module may have its own initialization
import './modules/dashboard_data.js';

// Export for global access if needed
window.whispera = {
    settings: { getSetting, setSetting, loadSettings, currentSettings },
    i18n: { toggleLanguage, translations },
    keyConnection: keyConnectionManager,
    waveAnimator: waveAnimator,
    activeConnections: activeConnectionManager,
};

// Initialize all modules when DOM is ready
document.addEventListener('DOMContentLoaded', async () => {
    console.log('[Whispera] Initializing application... VERSION: ' + new Date().toISOString());

    try {
        // Initialize in order of dependency
        initI18n();
        console.log('[Whispera] i18n initialized');

        // Settings module has auto-init, but call explicitly to be safe
        initSettings();
        console.log('[Whispera] Settings initialized');

        // Window controls
        await initWindowControls();
        console.log('[Whispera] Window controls initialized');

        // Notifications
        initNotifications();
        console.log('[Whispera] Notifications initialized');

        // Wave animator and active connections are auto-initialized
        // but we can call their init methods if needed

        console.log('[Whispera] ✅ All modules initialized successfully!');

    } catch (error) {
        console.error('[Whispera] ❌ Initialization error:', error);
    }
});

// Handle unhandled errors
window.addEventListener('unhandledrejection', (event) => {
    console.error('[Whispera] Unhandled promise rejection:', event.reason);
});

window.addEventListener('error', (event) => {
    console.error('[Whispera] Global error:', event.error);
});
