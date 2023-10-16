import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NetworkStatusLineChartComponent } from './network-status-line-chart.component';

describe('NetworkStatusLineChartComponent', () => {
  let component: NetworkStatusLineChartComponent;
  let fixture: ComponentFixture<NetworkStatusLineChartComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [NetworkStatusLineChartComponent]
    });
    fixture = TestBed.createComponent(NetworkStatusLineChartComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
