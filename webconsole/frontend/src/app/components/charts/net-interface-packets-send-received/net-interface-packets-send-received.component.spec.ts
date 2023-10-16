import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NetInterfacePacketsSendReceivedComponent } from './net-interface-packets-send-received.component';

describe('NetInterfacePacketsSendReceivedComponent', () => {
  let component: NetInterfacePacketsSendReceivedComponent;
  let fixture: ComponentFixture<NetInterfacePacketsSendReceivedComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [NetInterfacePacketsSendReceivedComponent]
    });
    fixture = TestBed.createComponent(NetInterfacePacketsSendReceivedComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
