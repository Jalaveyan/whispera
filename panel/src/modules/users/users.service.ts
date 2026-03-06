import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface User {
    id: number;
    username: string;
    privateKey?: string;
    publicKey?: string;
    upload: number;
    download: number;
    trafficLimit: number;
    expiryDate?: string;
    status: string;
    createdAt: string;
    obfsProfile?: string;
    marionetteProfile?: string;
    russianService?: string;
}

export interface CreateUserDto {
    username: string;
    trafficLimit?: number;
    expiryDate?: string;
    obfsProfile?: string;
    marionetteProfile?: string;
    russianService?: string;
}

@Injectable()
export class UsersService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getUsers(token: string): Promise<User[]> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/users`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data.users || response.data || [];
    }

    async createUser(token: string, dto: CreateUserDto): Promise<User> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/users/add`,
                dto,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data.user;
    }

    async updateUser(token: string, id: string, data: Partial<CreateUserDto> & { status?: string }): Promise<User> {
        const response = await firstValueFrom(
            this.httpService.put(
                `${this.backendUrl}/api/users/${id}`,
                data,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data.user;
    }

    async deleteUser(token: string, id: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/users/delete`,
                { id: parseInt(id, 10) },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }

    async getUserStats(token: string, id: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/v1/stats/users`, {
                headers: { Authorization: `Bearer ${token}` },
                params: { user_id: id },
            }),
        );
        return response.data;
    }
}
