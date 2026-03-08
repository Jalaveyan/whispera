import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { join } from 'path';

import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { SessionsModule } from './modules/sessions/sessions.module';
import { SystemModule } from './modules/system/system.module';
import { DashboardModule } from './modules/dashboard/dashboard.module';
import { InboundsModule } from './modules/inbounds/inbounds.module';
import { StatsModule } from './modules/stats/stats.module';
import { RoutingModule } from './modules/routing/routing.module';
import { OutboundsModule } from './modules/outbounds/outbounds.module';
import { BridgesModule } from './modules/bridges/bridges.module';
import { SubscriptionsModule } from './modules/subscriptions/subscriptions.module';
import { AdblockModule } from './modules/adblock/adblock.module';
import { LogsModule } from './modules/logs/logs.module';
import { UploadModule } from './modules/upload/upload.module';
import { FirewallModule } from './modules/firewall/firewall.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    AuthModule,
    UsersModule,
    SessionsModule,
    SystemModule,
    DashboardModule,
    InboundsModule,
    StatsModule,
    RoutingModule,
    OutboundsModule,
    BridgesModule,
    SubscriptionsModule,
    AdblockModule,
    LogsModule,
    UploadModule,
    FirewallModule,
  ],
})
export class AppModule { }
