import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class ApiConfigService {

  private readonly API = 'http://137.184.208.188:5001';

  UE_INFO = `${this.API}/ue/info`;
  UE_INTERFACE = `${this.API}/ue/interface`;


  constructor() { }
}
