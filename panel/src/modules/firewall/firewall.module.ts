import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { FirewallController } from './firewall.controller';
import { FirewallService } from './firewall.service';

@Module({
    imports: [HttpModule],
    controllers: [FirewallController],
    providers: [FirewallService],
    exports: [FirewallService],
})
export class FirewallModule { }
