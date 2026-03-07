import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom, timeout, catchError } from 'rxjs';
import { of } from 'rxjs';

export interface TrafficStats {
    total_upload: number;
    total_download: number;
    total_traffic: number;
    active_users: number;
    user_stats: UserTrafficStats[];
    chart_data?: ChartData;
}

export interface UserTrafficStats {
    user_id: string;
    name: string;
    upload: number;
    download: number;
    total: number;
    limit: number;
    used_percent: number;
}

export interface ChartData {
    labels: string[];
    upload: number[];
    download: number[];
}

@Injectable()
export class StatsService {
    private readonly logger = new Logger(StatsService.name);
    private readonly backendUrl: string;
    private readonly requestTimeout = 10000;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getTrafficStats(token: string, period = '24h'): Promise<TrafficStats> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats/traffic`, {
                    headers: { Authorization: `Bearer ${token}` },
                    params: { period },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Failed to get traffic stats: ${err.message}`);
                        return of({ data: { total_upload: 0, total_download: 0, total_traffic: 0, active_users: 0, user_stats: [] } });
                    }),
                ),
            );
            return response.data;
        } catch (err) {
            this.logger.error(`Traffic stats error: ${err.message}`);
            return { total_upload: 0, total_download: 0, total_traffic: 0, active_users: 0, user_stats: [] };
        }
    }

    async getUserTraffic(token: string): Promise<UserTrafficStats[]> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats/users`, {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Failed to get user traffic: ${err.message}`);
                        return of({ data: { users: [] } });
                    }),
                ),
            );
            return response.data.users || [];
        } catch (err) {
            this.logger.error(`User traffic error: ${err.message}`);
            return [];
        }
    }

    async getChartData(token: string, period = '24h'): Promise<ChartData> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats/chart`, {
                    headers: { Authorization: `Bearer ${token}` },
                    params: { period },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Failed to get chart data: ${err.message}`);
                        return of({ data: { labels: [], upload: [], download: [] } });
                    }),
                ),
            );
            return response.data;
        } catch (err) {
            this.logger.error(`Chart data error: ${err.message}`);
            return { labels: [], upload: [], download: [] };
        }
    }
}
