import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NetInterfaceThrougputComponent } from './net-interface-througput.component';

describe('NetInterfaceThrougputComponent', () => {
  let component: NetInterfaceThrougputComponent;
  let fixture: ComponentFixture<NetInterfaceThrougputComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [NetInterfaceThrougputComponent]
    });
    fixture = TestBed.createComponent(NetInterfaceThrougputComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
