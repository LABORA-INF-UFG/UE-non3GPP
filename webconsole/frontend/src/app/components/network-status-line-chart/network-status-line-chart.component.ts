import { Component, ViewChild  } from '@angular/core';
import { Chart, ChartConfiguration, ChartEvent, ChartType } from 'chart.js';
import { BaseChartDirective } from 'ng2-charts';
import Annotation from 'chartjs-plugin-annotation';
import {DashboardService} from "../dashboard/dashboard.service";
import {NetworkThrougput} from "../../models/network-througput";
import {NetworkStatus} from "../../models/network-status";


@Component({
  selector: 'app-network-status-line-chart',
  templateUrl: './network-status-line-chart.component.html',
  styleUrls: ['./network-status-line-chart.component.css']
})
export class NetworkStatusLineChartComponent {

  private newLabel? = 'New label';

  id = 0;

  constructor(private service : DashboardService) {
    Chart.register(Annotation);
  }

  public lineChartData: ChartConfiguration['data'] = {
    datasets: [
      {
        data: [],
        label: 'Bytes Received',
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
        label: 'Bytes Sent',
        backgroundColor: 'rgba(77,83,96,0.2)',
        borderColor: 'rgba(77,83,96,1)',
        pointBackgroundColor: 'rgba(77,83,96,1)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(77,83,96,1)',
        fill: 'origin',
      },
     /* {
        data: [180, 480, 770, 90, 1000, 270, 400],
        label: 'Packets Sent',
        yAxisID: 'y1',
        backgroundColor: 'rgba(255,0,0,0.3)',
        borderColor: 'red',
        pointBackgroundColor: 'rgba(148,159,177,1)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(148,159,177,0.8)',
        fill: 'origin',
      },*/
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

   /*
    plugins: {
      legend: { display: true },
      annotation: {
        annotations: [
          {
            type: 'line',
            scaleID: 'x',
            value: 'T3',
            borderColor: 'orange',
            borderWidth: 2,
            label: {
              display: true,
              position: 'center',
              color: 'orange',
              content: 'Algo Aqui',
              font: {
                weight: 'bold',
              },
            },
          },
        ],
      },
    },*/
  };

  public lineChartType: ChartType = 'line';

  @ViewChild(BaseChartDirective) chart?: BaseChartDirective;


  public changeColor(): void {
    this.lineChartData.datasets[2].borderColor = 'green';
    this.lineChartData.datasets[2].backgroundColor = `rgba(0, 255, 0, 0.3)`;
    this.chart?.update();
  }


  /* ------ */
  ngOnInit(): void{
    this.getNetworkStatus(3);
    setInterval(() => {
      this.getNetworkStatus(1);
    }, 2000);
  }


  clearNetworkStatusLocalData(){
    this.lineChartData.datasets[0].data = [];
    this.lineChartData.datasets[1].data = [];
    this.lineChartData.labels = [];
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
      this.lineChartData.datasets[0].data.push(status.bytesRecv);
      this.lineChartData.datasets[1].data.push(status.bytesSent);

      this.lineChartData?.labels?.push(
        `${this.lineChartData.labels.length + 1}`
      );
    });
    this.chart?.update();


    //console.log(this.lineChartData.datasets[0].data)

    /*this.lineChartData.datasets.forEach((x, i) => {
      const num = Math.floor(Math.random() * (i < 2 ? 100 : 1000) + 1);
      x.data.push(num);
    });
    this.lineChartData?.labels?.push(
      `T${this.lineChartData.labels.length + 1}`
    );

    this.chart?.update();*/
  }
}
