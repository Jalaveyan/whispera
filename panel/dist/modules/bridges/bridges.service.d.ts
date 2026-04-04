import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface Bridge {
    id: string;
    url: string;
    status: string;
    last_seen: string;
}
export declare class BridgesService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getBridges(token: string): Promise<Bridge[]>;
    addBridge(token: string, bridge: Partial<Bridge>): Promise<Bridge>;
    deleteBridge(token: string, id: string): Promise<void>;
    getCloudInit(token: string): Promise<string>;
    getWhiteCloudInit(query: Record<string, string>): Promise<string>;
    getBridgesAdmin(token: string): Promise<any>;
    getBridgeStats(token: string): Promise<any>;
    checkBridge(token: string, id: string): Promise<any>;
    getToken(token: string): Promise<any>;
    regenerateToken(token: string): Promise<any>;
    addBridgeDirect(token: string, body: any): Promise<any>;
    deleteBridgeDirect(token: string, body: any): Promise<any>;
    getBridgeMap(token: string): Promise<any>;
    connectToBridge(token: string, bridgeId: string): Promise<any>;
    scanBridges(token: string): Promise<any>;
}
