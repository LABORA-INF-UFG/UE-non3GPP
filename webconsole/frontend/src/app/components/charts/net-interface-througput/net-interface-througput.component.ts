import {Component, ViewChild} from '@angular/core';
import {BaseChartDirective} from "ng2-charts";
import {DashboardService} from "../../dashboard/dashboard.service";
import {Chart, ChartConfiguration, ChartType} from "chart.js";
import Annotation from "chartjs-plugin-annotation";
import {NetworkStatus} from "../../../models/network-status";
import {NetworkThrougput} from "../../../models/network-througput";

@Component({
  selector: 'app-net-interface-througput',
  templateUrl: './net-interface-througput.component.html',
  styleUrls: ['./net-interface-througput.component.css']
})
export class NetInterfaceThrougputComponent {

  @ViewChild(BaseChartDirective) chartThrouput?: BaseChartDirective;

  constructor(private service : DashboardService) {
    Chart.register(Annotation);
  }

  public lineChartType: ChartType = 'line';

  public lineChartThrouput: ChartConfiguration['data'] = {
    datasets: [
      {
        data: [],
        label: 'In',
        backgroundColor: 'rgba(245, 187, 39, 0.8)',
        borderColor: 'yellow',
        pointBackgroundColor: 'rgba(245, 187, 39, 0.8)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(245, 187, 39, 0.8)',
        fill: 'origin',
      },
      {
        data: [],
        label: 'Out',
        yAxisID: 'y1',
        backgroundColor: 'rgba(183, 245, 39, 0.8)',
        borderColor: 'rgba(118, 245, 39, 0.8)',
        pointBackgroundColor: 'rgba(183, 245, 39, 0.8)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(183, 245, 39, 0.8)',
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

  clearChartData(){
    this.lineChartThrouput.datasets[0].data = [];
    this.lineChartThrouput.datasets[1].data = [];
    this.lineChartThrouput.labels = [];
  }

  getNetworkStatus(interval:number):void{
    this.service.getNetworkThroughput('gretun1', interval).subscribe((values) => {
      this.updateNetworkThroughput(values)
    })
  }

  updateNetworkThroughput(values:NetworkThrougput[]):void{
    values.forEach((status, i) => {

      console.log(status)

      this.lineChartThrouput.datasets[0].data.push(status.throughputIn);
      this.lineChartThrouput.datasets[1].data.push(status.throughputOut);
      this.lineChartThrouput?.labels?.push(
        `${this.lineChartThrouput.labels.length + 1}`
      );


    });

    this.chartThrouput?.update();

  }
}
