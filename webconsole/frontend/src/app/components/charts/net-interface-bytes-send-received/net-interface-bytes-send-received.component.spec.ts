import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NetInterfaceBytesSendReceivedComponent } from './net-interface-bytes-send-received.component';

describe('NetInterfaceBytesSendReceivedComponent', () => {
  let component: NetInterfaceBytesSendReceivedComponent;
  let fixture: ComponentFixture<NetInterfaceBytesSendReceivedComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [NetInterfaceBytesSendReceivedComponent]
    });
    fixture = TestBed.createComponent(NetInterfaceBytesSendReceivedComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
