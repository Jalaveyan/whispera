import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class FirewallService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getStatus(token: string) {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/firewall/status`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async addRule(token: string, body: any) {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/firewall/rules`, body, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async deleteRule(token: string, number: number) {
        const response = await firstValueFrom(
            this.httpService.delete(`${this.backendUrl}/api/firewall/rules`, {
                headers: { Authorization: `Bearer ${token}` },
                data: { number },
            }),
        );
        return response.data;
    }

    async toggle(token: string, enable: boolean) {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/firewall/toggle`, { enable }, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }
}
