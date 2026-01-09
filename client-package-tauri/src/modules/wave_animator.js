// Dynamic Wave Animation Module
// Waves respond to REAL system traffic data via Tauri

import { invoke } from '@tauri-apps/api/core';

class WaveAnimator {
    constructor() {
        this.downloadData = [];
        this.uploadData = [];
        this.memoryData = [];
        this.maxDataPoints = 50;
        this.animationFrame = null;
        this.statsInterval = null;
        this.lastBytesReceived = 0;
        this.lastBytesSent = 0;
        this.lastUpdateTime = Date.now();
    }

    init() {
        this.downloadWave = document.querySelector('.download-wave');
        this.uploadWave = document.querySelector('.upload-wave');
        this.memoryWave = document.querySelector('.memory-wave');

        // Initialize data arrays
        for (let i = 0; i < this.maxDataPoints; i++) {
            this.downloadData.push(15);
            this.uploadData.push(15);
            this.memoryData.push(15);
        }

        this.animate();
        this.startRealTrafficMonitoring();
        console.log('[WaveAnimator] Initialized with REAL traffic monitoring');
    }

    // Start monitoring real system network traffic
    startRealTrafficMonitoring() {
        if (this.statsInterval) return;

        // Poll every 500ms for smooth waves
        this.statsInterval = setInterval(async () => {
            await this.fetchRealNetworkStats();
        }, 500);

        // Initial fetch
        this.fetchRealNetworkStats();
    }

    async fetchRealNetworkStats() {
        try {
            const now = Date.now();
            const timeDelta = (now - this.lastUpdateTime) / 1000; // seconds

            // Get network stats from Tauri
            const networkResult = await invoke('get_network_stats');

            if (networkResult.success) {
                const bytesReceived = networkResult.bytes_received;
                const bytesSent = networkResult.bytes_sent;

                if (this.lastBytesReceived > 0 && timeDelta > 0) {
                    // Calculate bytes per second
                    const downloadRate = (bytesReceived - this.lastBytesReceived) / timeDelta;
                    const uploadRate = (bytesSent - this.lastBytesSent) / timeDelta;

                    // Get memory usage
                    let memoryMB = 50;
                    try {
                        const memResult = await invoke('get_memory_usage');
                        if (memResult.success) {
                            memoryMB = memResult.memory_mb;
                        }
                    } catch (e) { }

                    this.updateTraffic(
                        Math.max(0, downloadRate),
                        Math.max(0, uploadRate),
                        memoryMB
                    );
                }

                this.lastBytesReceived = bytesReceived;
                this.lastBytesSent = bytesSent;
            }

            this.lastUpdateTime = now;

        } catch (error) {
            console.error('[WaveAnimator] Failed to fetch network stats:', error);
        }
    }

    // Update traffic values and animate waves
    updateTraffic(downloadBytes, uploadBytes, memoryMB) {
        // Add new data points (normalize to 5-25 range for wave height)
        const downloadHeight = this.normalizeValue(downloadBytes, 0, 5000000, 5, 25);
        const uploadHeight = this.normalizeValue(uploadBytes, 0, 2000000, 5, 25);
        const memoryHeight = this.normalizeValue(memoryMB || 0, 0, 500, 10, 25);

        this.downloadData.push(downloadHeight);
        this.uploadData.push(uploadHeight);
        this.memoryData.push(memoryHeight);

        // Keep arrays at max length
        if (this.downloadData.length > this.maxDataPoints) this.downloadData.shift();
        if (this.uploadData.length > this.maxDataPoints) this.uploadData.shift();
        if (this.memoryData.length > this.maxDataPoints) this.memoryData.shift();

        // Update display values
        this.updateDisplayValue('download-speed', downloadBytes);
        this.updateDisplayValue('upload-speed', uploadBytes);
        const memEl = document.getElementById('memory-usage');
        if (memEl) memEl.textContent = `${memoryMB?.toFixed(1) || 0} MB`;
    }

    normalizeValue(value, min, max, outMin, outMax) {
        const clamped = Math.max(min, Math.min(max, value));
        return outMin + ((clamped - min) / (max - min)) * (outMax - outMin);
    }

    updateDisplayValue(elementId, bytes) {
        const el = document.getElementById(elementId);
        if (!el) return;

        if (bytes < 1024) {
            el.textContent = `${bytes.toFixed(0)} B/s`;
        } else if (bytes < 1024 * 1024) {
            el.textContent = `${(bytes / 1024).toFixed(1)} KB/s`;
        } else {
            el.textContent = `${(bytes / 1024 / 1024).toFixed(2)} MB/s`;
        }
    }

    generateWavePath(data) {
        if (!data || data.length < 2) return '';

        const step = 100 / (data.length - 1);
        let path = `M0,${30 - data[0]}`;

        for (let i = 1; i < data.length; i++) {
            const x = i * step;
            const y = 30 - data[i];
            const prevX = (i - 1) * step;
            const prevY = 30 - data[i - 1];

            // Smooth curve using quadratic bezier
            const cpX = (prevX + x) / 2;
            path += ` Q${cpX},${prevY} ${x},${y}`;
        }

        return path;
    }

    animate() {
        // Add slight random movement for smoother appearance
        const addNoise = (data) => {
            const lastIndex = data.length - 1;
            if (lastIndex >= 0) {
                const noise = (Math.random() - 0.5) * 1;
                data[lastIndex] = Math.max(5, Math.min(25, data[lastIndex] + noise));
            }
        };

        addNoise(this.downloadData);
        addNoise(this.uploadData);
        addNoise(this.memoryData);

        // Update SVG paths
        if (this.downloadWave) {
            this.downloadWave.setAttribute('d', this.generateWavePath(this.downloadData));
        }
        if (this.uploadWave) {
            this.uploadWave.setAttribute('d', this.generateWavePath(this.uploadData));
        }
        if (this.memoryWave) {
            this.memoryWave.setAttribute('d', this.generateWavePath(this.memoryData));
        }

        this.animationFrame = requestAnimationFrame(() => this.animate());
    }

    destroy() {
        if (this.statsInterval) {
            clearInterval(this.statsInterval);
            this.statsInterval = null;
        }
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
        }
    }
}

// Export and initialize
export const waveAnimator = new WaveAnimator();

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        waveAnimator.init();
    });
} else {
    waveAnimator.init();
}
