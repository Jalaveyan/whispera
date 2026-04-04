"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BridgesService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
let BridgesService = class BridgesService {
    httpService;
    configService;
    backendUrl;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async getBridges(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/bridge-admin`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data.bridges || response.data || [];
    }
    async addBridge(token, bridge) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/bridge-add`, bridge, { headers: { Authorization: `Bearer ${token}` } }));
        return response.data;
    }
    async deleteBridge(token, id) {
        await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/bridge-delete`, { id }, { headers: { Authorization: `Bearer ${token}` } }));
    }
    async getCloudInit(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/bridge-cloudinit`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async getWhiteCloudInit(query) {
        const params = new URLSearchParams(query).toString();
        const url = `${this.backendUrl}/api/bridge-white-cloudinit${params ? '?' + params : ''}`;
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(url, { responseType: 'text' }));
        return response.data;
    }
    async getBridgesAdmin(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/bridge-admin`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async getBridgeStats(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/bridge-stats`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async checkBridge(token, id) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/bridge-check`, { id }, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async getToken(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/bridge-token`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async regenerateToken(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/bridge-token-regenerate`, {}, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async addBridgeDirect(token, body) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/bridge-add`, body, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async deleteBridgeDirect(token, body) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/bridge-delete`, body, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async getBridgeMap(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/bridge-map`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async connectToBridge(token, bridgeId) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/bridge-connect`, { bridge_id: bridgeId }, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async scanBridges(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/bridge-scan`, {}, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
};
exports.BridgesService = BridgesService;
exports.BridgesService = BridgesService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], BridgesService);
//# sourceMappingURL=bridges.service.js.map