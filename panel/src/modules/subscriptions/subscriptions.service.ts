import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface Subscription {
    id: string;
    name: string;
    token: string;
    sub_url: string;
    user_ids: number[];
    transports: string[];
    created_at: string;
    updated_at: string;
}

export interface CreateSubscriptionDto {
    name: string;
    user_ids?: number[];
    transports?: string[];
}

@Injectable()
export class SubscriptionsService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getSubscriptions(token: string, host = '', proto = 'https'): Promise<Subscription[]> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/subscriptions`, {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'X-Forwarded-Host': host,
                        'X-Forwarded-Proto': proto,
                    },
                }),
            );
            return response.data.subscriptions || response.data || [];
        } catch (e) {
            if (e.response?.status === 404) return [];
            throw e;
        }
    }

    async addSubscription(token: string, dto: CreateSubscriptionDto, host = '', proto = 'https'): Promise<Subscription> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/subscriptions/add`,
                dto,
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'X-Forwarded-Host': host,
                        'X-Forwarded-Proto': proto,
                    },
                },
            ),
        );
        return response.data.subscription;
    }

    async updateSubscription(token: string, id: string, dto: Partial<CreateSubscriptionDto>): Promise<Subscription> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/subscriptions/update`,
                { id, ...dto },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data.subscription;
    }

    async deleteSubscription(token: string, id: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/subscriptions/delete`,
                { id },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }

    // Returns the raw subscription content (base64) — for proxying to clients
    async getSubscriptionContent(token: string): Promise<string> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/sub/${token}`, {
                responseType: 'text',
            }),
        );
        return response.data;
    }
}
