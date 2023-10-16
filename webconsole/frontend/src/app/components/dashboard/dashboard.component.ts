import {Component, Input} from '@angular/core';
import {UeStatus} from "../../models/ue-status";
import {DashboardService} from "./dashboard.service";

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent {

  constructor(private service : DashboardService) {
  }

  ueStatus: UeStatus = {
    authenticationNasTime: 0,
    ipsecTime: 0,
    pduSessionTime: 0,
    registerTime: 0,
    securityProcedureNasTime: 0
  }

  ngOnInit(): void{
      this.getUeInfo()
  }

  getUeInfo(): void{
    this.service.getUeInfo().subscribe((value) => {
      this.ueStatus = value
    })
  }



}
