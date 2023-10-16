import {Component, ViewChild} from '@angular/core';
import {BaseChartDirective} from "ng2-charts";
import {DashboardService} from "../../dashboard/dashboard.service";
import {Chart, ChartConfiguration, ChartType} from "chart.js";
import Annotation from "chartjs-plugin-annotation";
import {NetworkStatus} from "../../../models/network-status";

@Component({
  selector: 'app-net-interface-bytes-send-received',
  templateUrl: './net-interface-bytes-send-received.component.html',
  styleUrls: ['./net-interface-bytes-send-received.component.css']
})
export class NetInterfaceBytesSendReceivedComponent {

  @ViewChild(BaseChartDirective) chartBytesSentReceived?: BaseChartDirective;

  constructor(private service : DashboardService) {
    Chart.register(Annotation);
  }

  public lineChartType: ChartType = 'line';

  public lineChartDataBytesSentAndReceived: ChartConfiguration['data'] = {
    datasets: [
      {
        data: [],
        label: 'Received',
        backgroundColor: 'rgba(148,159,177,0.2)',
        borderColor: 'rgba(148,159,177,1)',
        pointBackgroundColor: 'rgba(148,159,177,1)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(148,159,177,0.8)',
        fill: 'origin',
      },
      {
        data: [],
        label: 'Sent',
        backgroundColor: 'rgba(77,83,96,0.2)',
        borderColor: 'rgba(77,83,96,1)',
        pointBackgroundColor: 'rgba(77,83,96,1)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(77,83,96,1)',
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
      // We use this empty structure as a placeholder for dynamic theming.
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

  clearBytesSentReceivedData(){
    this.lineChartDataBytesSentAndReceived.datasets[0].data = [];
    this.lineChartDataBytesSentAndReceived.datasets[1].data = [];
    this.lineChartDataBytesSentAndReceived.labels = [];
  }

  getNetworkStatus(interval:number):void{
    this.service.getNetworkStatus('gretun1', interval).subscribe((values) => {
      this.updateBytesReceived(values)
    })
  }

  /*getNetworkThrougput():void{
    this.service.getNetworkThrougput('gretun1', 5).subscribe((values) => {
      this.updateChart(values)
    })
  }*/

  updateBytesReceived(values:NetworkStatus[]):void{
    values.forEach((status, i) => {

      this.lineChartDataBytesSentAndReceived.datasets[0].data.push(status.bytesRecv);
      this.lineChartDataBytesSentAndReceived.datasets[1].data.push(status.bytesSent);
      this.lineChartDataBytesSentAndReceived?.labels?.push(
        `${this.lineChartDataBytesSentAndReceived.labels.length + 1}`
      );


    });

    this.chartBytesSentReceived?.update();

  }
}
