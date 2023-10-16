import {Component, ViewChild} from '@angular/core';
import {BaseChartDirective} from "ng2-charts";
import {DashboardService} from "../../dashboard/dashboard.service";
import {Chart, ChartConfiguration, ChartType} from "chart.js";
import Annotation from "chartjs-plugin-annotation";
import {NetworkStatus} from "../../../models/network-status";

@Component({
  selector: 'app-net-interface-packets-send-received',
  templateUrl: './net-interface-packets-send-received.component.html',
  styleUrls: ['./net-interface-packets-send-received.component.css']
})
export class NetInterfacePacketsSendReceivedComponent {

  @ViewChild(BaseChartDirective) chartPacketsSentReceived?: BaseChartDirective;

  constructor(private service : DashboardService) {
    Chart.register(Annotation);
  }

  public lineChartType: ChartType = 'line';

  public lineChartDataPacketsSentAndReceived: ChartConfiguration['data'] = {
    datasets: [
      {
        data: [],
        label: 'Received',
        backgroundColor: 'rgba(0, 255, 0, 0.3)',
        borderColor: 'green',
        pointBackgroundColor: 'rgba(148,159,177,1)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(148,159,177,0.8)',
        fill: 'origin',
      },
      {
        data: [],
        label: 'Sent',
        yAxisID: 'y1',
        backgroundColor: 'rgba(255,0,0,0.3)',
        borderColor: 'red',
        pointBackgroundColor: 'rgba(148,159,177,1)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(148,159,177,0.8)',
        fill: 'origin',
      },
    ],
    labels: [],
  };

  public lineChartOptions: ChartConfiguration['options'] = {
    elements: {
      line: {
        tension: 0.5,
      },
    },
    scales: {

      y: {
        position: 'left',
      },
      y1: {
        position: 'right',
        grid: {
          color: 'rgba(255,0,0,0.3)',
        },
        ticks: {
          color: 'red',
        },
      },
    },

  };




  /* ------ */
  ngOnInit(): void{
    this.getNetworkStatus(3);
    setInterval(() => {
      this.getNetworkStatus(1);
    }, 2000);
  }

  clearPacketsSentReceivedData(){
    this.lineChartDataPacketsSentAndReceived.datasets[0].data = [];
    this.lineChartDataPacketsSentAndReceived.datasets[1].data = [];
    this.lineChartDataPacketsSentAndReceived.labels = [];
  }

  getNetworkStatus(interval:number):void{
    this.service.getNetworkStatus('gretun1', interval).subscribe((values) => {
      this.updatePacketsReceived(values)
    })
  }

  updatePacketsReceived(values:NetworkStatus[]):void{
    values.forEach((status, i) => {

      this.lineChartDataPacketsSentAndReceived.datasets[0].data.push(status.packetsRecv);
      this.lineChartDataPacketsSentAndReceived.datasets[1].data.push(status.packetsSent);
      this.lineChartDataPacketsSentAndReceived?.labels?.push(
        `${this.lineChartDataPacketsSentAndReceived.labels.length + 1}`
      );


    });

    this.chartPacketsSentReceived?.update();

  }
}
