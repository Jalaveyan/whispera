import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface Bridge {
    id: string;
    url: string;
    status: string;
    last_seen: string;
}

@Injectable()
export class BridgesService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getBridges(token: string): Promise<Bridge[]> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/bridge-admin`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data.bridges || response.data || [];
    }

    async addBridge(token: string, bridge: Partial<Bridge>): Promise<Bridge> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/bridge-add`,
                bridge,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async deleteBridge(token: string, id: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/bridge-delete`,
                { id },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }

    async getCloudInit(token: string): Promise<string> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/bridge-cloudinit`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async getWhiteCloudInit(query: Record<string, string>): Promise<string> {
        const params = new URLSearchParams(query).toString();
        const url = `${this.backendUrl}/api/bridge-white-cloudinit${params ? '?' + params : ''}`;
        const response = await firstValueFrom(
            this.httpService.get(url, { responseType: 'text' }),
        );
        return response.data;
    }

    async getBridgesAdmin(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/bridge-admin`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async getBridgeStats(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/bridge-stats`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async checkBridge(token: string, id: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/bridge-check`, { id }, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async getToken(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/bridge-token`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async regenerateToken(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/bridge-token-regenerate`, {}, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async addBridgeDirect(token: string, body: any): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/bridge-add`, body, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async deleteBridgeDirect(token: string, body: any): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/bridge-delete`, body, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async getBridgeMap(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/bridge-map`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async connectToBridge(token: string, bridgeId: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/bridge-connect`, { bridge_id: bridgeId }, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async scanBridges(token: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.post(`${this.backendUrl}/api/bridge-scan`, {}, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }
}
