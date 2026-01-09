import { defineConfig } from 'vite';

// https://vitejs.dev/config/
export default defineConfig({
    // Prevent vite from obscuring rust errors
    clearScreen: false,

    // Tauri expects a fixed port
    server: {
        port: 1420,
        strictPort: true,
        watch: {
            // Tell vite to ignore watching `src-tauri`
            ignored: ['**/src-tauri/**'],
        },
    },

    // Make sure to build properly for Tauri
    build: {
        // Tauri uses dist folder for frontend
        outDir: 'dist',
        // Don't minify for easier debugging (can change to true for production)
        minify: true,
        // Clear the output directory before building
        emptyOutDir: true,
    },

    // Env prefix for Tauri
    envPrefix: ['VITE_', 'TAURI_'],
});
