import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom, timeout, catchError } from 'rxjs';
import { of } from 'rxjs';

export interface SystemInfo {
    version: string;
    uptime: number;
    go_version: string;
    server_ip: string;
    public_key: string;
}

export interface SystemStats {
    total_users: number;
    active_sessions: number;
    total_upload: number;
    total_download: number;
}

@Injectable()
export class SystemService {
    private readonly logger = new Logger(SystemService.name);
    private readonly backendUrl: string;
    private readonly requestTimeout = 10000;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getSystemInfo(token: string): Promise<SystemInfo> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/system/info`, {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Failed to get system info: ${err.message}`);
                        return of({ data: { version: 'unknown', uptime: 0, go_version: '', server_ip: '', public_key: '' } });
                    }),
                ),
            );
            return response.data;
        } catch (err) {
            this.logger.error(`System info error: ${err.message}`);
            return { version: 'unknown', uptime: 0, go_version: '', server_ip: '', public_key: '' };
        }
    }

    async getStats(token: string): Promise<SystemStats> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats`, {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Failed to get stats: ${err.message}`);
                        return of({ data: { total_users: 0, active_sessions: 0, total_upload: 0, total_download: 0 } });
                    }),
                ),
            );
            return response.data;
        } catch (err) {
            this.logger.error(`Stats error: ${err.message}`);
            return { total_users: 0, active_sessions: 0, total_upload: 0, total_download: 0 };
        }
    }

    async reloadConfig(token: string): Promise<void> {
        try {
            await firstValueFrom(
                this.httpService.post(
                    `${this.backendUrl}/api/v1/config/reload`,
                    {},
                    {
                        headers: { Authorization: `Bearer ${token}` },
                        timeout: this.requestTimeout,
                    },
                ).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Failed to reload config: ${err.message}`);
                        throw err;
                    }),
                ),
            );
        } catch (err) {
            this.logger.error(`Config reload error: ${err.message}`);
            throw err;
        }
    }

    async getConfig(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/v1/config`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }),
        );
        return response.data;
    }

    async updateConfig(token: string, config: any): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/v1/config/update`, config, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }),
        );
        return response.data;
    }

    async renewCert(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/v1/config/renew-cert`, {}, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }),
        );
        return response.data;
    }

    async getBackup(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/backup`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: 30000,
            }),
        );
        return response.data;
    }

    async restoreBackup(token: string, backup: any): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/backup/restore`, backup, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: 30000,
            }),
        );
        return response.data;
    }

    async getProbeStats(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/probe/stats`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }),
        );
        return response.data;
    }

    async probeBlockIP(token: string, ip: string, reason: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/probe/block`, { ip, reason }, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }),
        );
        return response.data;
    }

    async probeUnblockIP(token: string, ip: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/probe/unblock`, { ip }, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }),
        );
        return response.data;
    }

    async getHealth(): Promise<any> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/v1/health`, {
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Health check failed: ${err.message}`);
                        return of({ data: { healthy: false, error: err.message } });
                    }),
                ),
            );
            return response.data;
        } catch (err) {
            this.logger.error(`Health check error: ${err.message}`);
            return { healthy: false, error: err.message };
        }
    }

    async getMLConfig(token: string): Promise<any> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/ml/config`, {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`ML config fetch failed: ${err.message}`);
                        return of({ data: { enabled: false, server_url: '', token_set: false } });
                    }),
                ),
            );
            return response.data;
        } catch (err) {
            this.logger.error(`ML config error: ${err.message}`);
            return { enabled: false, server_url: '', token_set: false };
        }
    }

    async rotateMLToken(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/ml/token/rotate`, {}, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }).pipe(timeout(this.requestTimeout)),
        );
        return response.data;
    }
}
