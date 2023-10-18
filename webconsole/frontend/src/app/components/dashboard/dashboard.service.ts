import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {UeStatus} from "../../models/ue-status";
import {Observable} from "rxjs";
import {ApiConfigService} from "../../services/api-config.service";
import {NetworkThrougput} from "../../models/network-througput";
import {NetworkStatus} from "../../models/network-status";

@Injectable({
  providedIn: 'root'
})
export class DashboardService {

  constructor(private http : HttpClient, private apiConfigService : ApiConfigService) { }

  getUeInfo(): Observable<UeStatus>{
    return this.http.get<UeStatus>(this.apiConfigService.UE_INFO)
  }

  getNetworkThrougput(net_interface_name: string, nm_interval: number): Observable<NetworkThrougput[]>{
    const url = `${this.apiConfigService.UE_INTERFACE}/${net_interface_name}/throughput/monitor/${nm_interval}`
    return this.http.get<NetworkThrougput[]>(url)
  }

  getNetworkStatus(net_interface_name: string, nm_interval: number): Observable<NetworkStatus[]>{
    const url = `${this.apiConfigService.UE_INTERFACE}/${net_interface_name}/network/status/${nm_interval}`
    return this.http.get<NetworkStatus[]>(url)
  }

  getNetworkThroughput(net_interface_name: string, nm_interval: number): Observable<NetworkThrougput[]>{
    const url = `${this.apiConfigService.UE_INTERFACE}/${net_interface_name}/throughput/monitor/${nm_interval}`
    return this.http.get<NetworkThrougput[]>(url)
  }

}
