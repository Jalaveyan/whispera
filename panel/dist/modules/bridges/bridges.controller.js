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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BridgesController = void 0;
const common_1 = require("@nestjs/common");
const bridges_service_1 = require("./bridges.service");
let BridgesController = class BridgesController {
    bridgesService;
    constructor(bridgesService) {
        this.bridgesService = bridgesService;
    }
    async getBridges(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const bridges = await this.bridgesService.getBridges(token);
            return res.json({ success: true, bridges });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch bridges' });
        }
    }
    async addBridge(auth, bridge, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.bridgesService.addBridge(token, bridge);
            return res.json({ success: true, bridge: result });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to add bridge' });
        }
    }
    async deleteBridge(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.bridgesService.deleteBridge(token, id);
            return res.json({ success: true });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to delete bridge' });
        }
    }
    async getCloudInit(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const script = await this.bridgesService.getCloudInit(token);
            return res.send(script);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).send('Failed to generate cloud-init');
        }
    }
    async getBridgesAdmin(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.getBridgesAdmin(token);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async getBridgeStats(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.getBridgeStats(token);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async checkBridge(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.checkBridge(token, id);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async getBridgeToken(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.getToken(token);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async regenerateBridgeToken(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.regenerateToken(token);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async addBridgeDirect(auth, body, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.addBridgeDirect(token, body);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async deleteBridgeDirect(auth, body, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.deleteBridgeDirect(token, body);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async getBridgeMap(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.getBridgeMap(token);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async connectToBridge(auth, bridgeId, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.connectToBridge(token, bridgeId);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async scanBridges(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.scanBridges(token);
            return res.json(data);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async getBridgeCloudinit(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const script = await this.bridgesService.getCloudInit(token);
            return res.send(script);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).send('Failed to generate cloud-init');
        }
    }
    async getWhiteBridgeCloudinit(query, res) {
        try {
            const script = await this.bridgesService.getWhiteCloudInit(query);
            res.setHeader('Content-Type', 'text/plain');
            res.setHeader('Content-Disposition', 'attachment; filename="install-white-bridge.sh"');
            return res.send(script);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).send('Failed to generate white cloud-init');
        }
    }
};
exports.BridgesController = BridgesController;
__decorate([
    (0, common_1.Get)('api/bridges'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getBridges", null);
__decorate([
    (0, common_1.Post)('api/bridges'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "addBridge", null);
__decorate([
    (0, common_1.Post)('api/bridges/delete'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "deleteBridge", null);
__decorate([
    (0, common_1.Get)('api/bridges/cloudinit'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getCloudInit", null);
__decorate([
    (0, common_1.Get)('api/bridge-admin'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getBridgesAdmin", null);
__decorate([
    (0, common_1.Get)('api/bridge-stats'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getBridgeStats", null);
__decorate([
    (0, common_1.Post)('api/bridge-check'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "checkBridge", null);
__decorate([
    (0, common_1.Get)('api/bridge-token'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getBridgeToken", null);
__decorate([
    (0, common_1.Post)('api/bridge-token-regenerate'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "regenerateBridgeToken", null);
__decorate([
    (0, common_1.Post)('api/bridge-add'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "addBridgeDirect", null);
__decorate([
    (0, common_1.Post)('api/bridge-delete'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "deleteBridgeDirect", null);
__decorate([
    (0, common_1.Get)('api/bridge-map'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getBridgeMap", null);
__decorate([
    (0, common_1.Post)('api/bridge-connect'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('bridge_id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "connectToBridge", null);
__decorate([
    (0, common_1.Post)('api/bridge-scan'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "scanBridges", null);
__decorate([
    (0, common_1.Get)('api/bridge-cloudinit'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getBridgeCloudinit", null);
__decorate([
    (0, common_1.Get)('api/bridge-white-cloudinit'),
    __param(0, (0, common_1.Query)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getWhiteBridgeCloudinit", null);
exports.BridgesController = BridgesController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [bridges_service_1.BridgesService])
], BridgesController);
//# sourceMappingURL=bridges.controller.js.map