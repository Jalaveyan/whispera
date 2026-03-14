import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface RoutingRule {
    id: string;
    type: string;
    condition: string;
    outbound: string;
    priority: number;
    enabled: boolean;
}

@Injectable()
export class RoutingService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getRules(token: string): Promise<RoutingRule[]> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/routing/rules`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data.rules || [];
    }

    async addRule(token: string, rule: Partial<RoutingRule>): Promise<RoutingRule> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/routing/rules/add`,
                rule,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async deleteRule(token: string, id: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/routing/rules/delete`,
                { id },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }
}
