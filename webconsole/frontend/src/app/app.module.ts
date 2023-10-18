import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { HeaderComponent } from './components/header/header.component';
import { FooterComponent } from './components/footer/footer.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { NgChartsModule, NgChartsConfiguration } from 'ng2-charts';
import {HttpClient, HttpClientModule} from "@angular/common/http";
import {FormsModule} from "@angular/forms";
import { NetInterfaceBytesSendReceivedComponent } from './components/charts/net-interface-bytes-send-received/net-interface-bytes-send-received.component';
import { NetInterfacePacketsSendReceivedComponent } from './components/charts/net-interface-packets-send-received/net-interface-packets-send-received.component';
import { NetInterfaceThrougputComponent } from './components/charts/net-interface-througput/net-interface-througput.component';

@NgModule({
  declarations: [
    AppComponent,
    HeaderComponent,
    FooterComponent,
    DashboardComponent,

    NetInterfaceBytesSendReceivedComponent,
    NetInterfacePacketsSendReceivedComponent,
    NetInterfaceThrougputComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    NgChartsModule,
    HttpClientModule,
    FormsModule
  ],
  providers: [
    { provide: NgChartsConfiguration, useValue: { generateColors: false }}
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
