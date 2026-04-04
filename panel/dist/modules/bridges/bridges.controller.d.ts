import type { Response } from 'express';
import { BridgesService, Bridge } from './bridges.service';
export declare class BridgesController {
    private readonly bridgesService;
    constructor(bridgesService: BridgesService);
    getBridges(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    addBridge(auth: string, bridge: Partial<Bridge>, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteBridge(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getCloudInit(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getBridgesAdmin(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getBridgeStats(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    checkBridge(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getBridgeToken(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    regenerateBridgeToken(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    addBridgeDirect(auth: string, body: any, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteBridgeDirect(auth: string, body: any, res: Response): Promise<Response<any, Record<string, any>>>;
    getBridgeMap(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    connectToBridge(auth: string, bridgeId: string, res: Response): Promise<Response<any, Record<string, any>>>;
    scanBridges(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getBridgeCloudinit(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getWhiteBridgeCloudinit(query: Record<string, string>, res: Response): Promise<Response<any, Record<string, any>>>;
}
