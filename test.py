import logging
import sys

from cip import CIP, CIP_Path,CIP_ReqConnectionManager
import plc
import binascii
from scapy import all as scapy_all
import struct

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)
#IP = '192.168.100.70'
#IP = '192.168.100.106'
IP = '192.168.100.165'
#IP = '192.168.100.116'

def test_get_attribute_all():
    # Connect to PLC
    client = plc.PLCClient('192.168.100.70')
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    
    path = CIP_Path.make(class_id=1, instance_id=1)
    pkt = CIP(service=1, path=path)
    pkt = CIP(str(pkt))
    pkt.show()
    client.send_rr_cip(pkt)
    
    # Receive the response and show it
    resppkt = client.recv_enippkt()
    #print resppkt
    resppkt.show()
    #resppkt[CIP].show()
    
def test1():
    # Connect to PLC
    client = plc.PLCClient('192.168.100.70')
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    
    #path = CIP_Path.make(class_id=1, instance_id=1)
    #pkt = CIP(serv1ce=1, path=path)
    #pkt = CIP(str(pkt))
    pkt = CIP(service=0x4c, path=CIP_Path.make_str("HOST"))
    pkt.show()
    client.send_rr_cip(pkt)
    
    # Receive the response and show it
    resppkt = client.recv_enippkt()
    print resppkt
    resppkt[CIP].show()
    
def test2():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    #ret = client.read_full_tag(1, 1, 16) #get_list_of_instances(1) #get_attribute(1,1,"2")
    ret = client.get_attribute(1,1,7)
    if ret:
       print ret



def test3():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    path = CIP_Path.make(class_id=1, instance_id=1)
    #assert str(path) == b"\x03\x20\x01\x25\x00\x01\x00"
    pkt = CIP(service=1, path=path)
    pkt = CIP(str(pkt))
    client.send_rr_cm_cip(pkt)
    #client.send_rr_cip(pkt)
    resppkt = client.recv_enippkt()

    print resppkt
    resppkt[CIP].show()





def test4():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    path = CIP_Path.make(class_id=1, instance_id=1)
    
    pkt = CIP(path=CIP_Path.make(class_id=2, instance_id=1))
    pkt = CIP(str(pkt))

    client.send_rr_mr_cip(pkt)
    resppkt = client.recv_enippkt()
    #print resppkt
    resppkt.show()
    #resppkt[CIP].show()


def test5():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    path = CIP_Path.make(class_id=1, instance_id=1)
    #assert str(path) == b"\x03\x20\x01\x25\x00\x01\x00"
    pkt = CIP(service=1, path=path)
    pkt = CIP(str(pkt))
    client.send_unit_cip(pkt)
    #resppkt = client.recv_enippkt()
    #print resppkt
    #resppkt[CIP].show()



def test6():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    #path = CIP_Path.make(class_id=1, instance_id=1)
    #assert str(path) == b"\x03\x20\x01\x25\x00\x01\x00"
    #pkt = CIP(service=1, path=path)
    #pkt = CIP(str(pkt))
    cippkt = CIP(service=0x4c, path=CIP_Path.make_str("HMI_LIT101"))
    print binascii.hexlify(str(cippkt))
    cippkt.show()
    #cippkt = CIP(service=0x4c, path=CIP_Path.make_str("SCADA"))
    client.send_unit_cip(cippkt)
    #resppkt = client.recv_enippkt()
    #print resppkt
    #resppkt[CIP].show()
 

def test7():
    '''
    test7() 
    Deny_Set_Attr_Exc_AC_B2
    '''
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    ret = client.set_attribute(0x04,0x66,0x03,'\x00')
    if ret:
       print ret

def test8():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    ret = client.get_list_of_instances(0xf6)
    if ret:
       print ret

def test9():
    print "in test9 \n"
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    ret = client.read_full_tag(0x01, 0, 8)
    if ret:
       print ret

def test10():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    client.forward_open()

def test11():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    client.forward_close()


def test12(class_id, instance, attr, value):
    '''
    SET_ATTRIBUTE_SINGLE
    test12(0x10,0x66,0x03,'\x00')
    '''
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    ret = client.set_attribute_single(class_id, instance, attr, value)
    if ret:
       print ret


def test13():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    path = CIP_Path.make(class_id=106, instance_id=26297)
    #assert str(path) == b"\x03\x20\x01\x25\x00\x01\x00"
    pkt = CIP(service=80, path=path)
    pkt = CIP(str(pkt))
    client.send_rr_cm_cip(pkt)
    #client.send_rr_cip(pkt)
    resppkt = client.recv_enippkt()

    print resppkt
    resppkt.show()
    resppkt[CIP].show()

def test14():
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    path = CIP_Path.make(class_id=178, instance_id=1)
    #assert str(path) == b"\x03\x20\x01\x25\x00\x01\x00"
    pkt = CIP(service=76, path=path)
    pkt = CIP(str(pkt))
    #client.send_unit_cip(pkt)
    client.send_rr_cm_cip(pkt)
    #resppkt = client.recv_enippkt()
    #resppkt.show()
    #print resppkt
    #resppkt[CIP].show()

def send_rr_cm_cip2(self, cippkt):
        """Encapsulate the CIP packet into a ConnectionManager packet"""
        cippkt.show()
        print "\n"
        cipcm_msg = cippkt #[cippkt]
        cippkt = CIP(path=CIP_Path.make(class_id=6, instance_id=1))
        cippkt /= CIP_ReqConnectionManager(message=cipcm_msg)
        cippkt.show()
        self.send_rr_cip(cippkt)

def test15(class_id, instance, attr, value):
        '''
        Deny_PCCC_Execution
        test15(0x74,0x01,0x01,'\x00')

        Deny_Edit_Controller_Properties
        test15(0x73,0x01,0x01,'\x00')
        '''
        client = plc.PLCClient(IP)
        if not client.connected:
            sys.exit(1)
        print("Established session {}".format(client.session_id))

        path = CIP_Path.make(class_id=class_id, instance_id=instance)
        # User CIP service 16: Set_Attribute_Single
        cippkt = CIP(service=75, path=path) / scapy_all.Raw(load=struct.pack('<HH', 1, attr) + value)
        client.send_rr_cm_cip(cippkt)
        resppkt = client.recv_enippkt()
        cippkt = resppkt[CIP]
        if cippkt.status[0].status != 0:
            print("CIP set attribute error: %r", cippkt.status[0])
            return False
        return True


def test16(class_id, instance, attr, value):
        '''
        OPC_Test_Write
        test16(0x6b,0x01,0x03,'\x00\x01')

        
        '''
        client = plc.PLCClient(IP)
        if not client.connected:
            sys.exit(1)
        print("Established session {}".format(client.session_id))

        path = CIP_Path.make(class_id=class_id, instance_id=instance)
        # User CIP service 16: Set_Attribute_Single
        cippkt = CIP(service=77, path=path) / scapy_all.Raw(load=struct.pack('<HH', 1, attr) + value)
        cippkt = CIP(str(cippkt))
        cipcm_msg = cippkt #[cippkt]
        cippkt = CIP(path=CIP_Path.make(class_id=6, instance_id=1))
        cippkt /= CIP_ReqConnectionManager(message=cipcm_msg)
        cippkt.show()
        client.send_rr_cip(cippkt)

        #client.send_rr_cm_cip(cippkt)
        resppkt = client.recv_enippkt()
        cippkt = resppkt[CIP]
        if cippkt.status[0].status != 0:
            print("CIP set attribute error: %r", cippkt.status[0])
            return False
        return True

def test17():
    '''
    like test15
    '''
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    ret = client.get_list_of_instances(0x73) #0x74
    if ret:
       print ret

def test18():
    '''
    Deny_Create_Exc_B2
    test18()
    '''
    # Connect to PLC
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    
    
    pkt = CIP(service=0x08, path=CIP_Path.make(class_id=172, instance_id=1))
    pkt.show()
    client.send_rr_cip(pkt)
    
    # Receive the response and show it
    resppkt = client.recv_enippkt()
    print resppkt
    resppkt[CIP].show()

def test19():
    '''
    Deny_Delete_Exc_B2
    test19()
    '''
    # Connect to PLC
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    
    
    pkt = CIP(service=0x09, path=CIP_Path.make(class_id=172, instance_id=1))
    pkt.show()
    client.send_rr_cip(pkt)
    
    # Receive the response and show it
    resppkt = client.recv_enippkt()
    print resppkt
    resppkt[CIP].show()

def test20(service, cip_class,cip_instance):
    '''
    Force_Enable_SFC_00 
    test20(0x4d,104,0)

    Force_Enable_IO_00
    test20(0x4d,105,0)
    
    Force_Disable_SFC_00
    test20(0x4e,104,0)

    Force_Disable_IO_00
    test20(0x4e,105,0)

    Report_Unlock
    test20(0x4c,116,1)

    Deny_Toggle_Bit_2420
    test20(0x51,106,9248)

    Deny_Edit_Timer_66B9
    test20(0x50,106,26297)
    '''
    # Connect to PLC
    client = plc.PLCClient(IP)
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))
    
    
    pkt = CIP(service=service, path=CIP_Path.make(class_id=cip_class, instance_id=cip_instance))
    pkt.show()
    client.send_rr_cip(pkt)
    
    # Receive the response and show it
    resppkt = client.recv_enippkt()
    print resppkt
    resppkt[CIP].show()

def main():
    test_get_attribute_all()
    test1()
    test2()
    test3()
    test4()
    test5()
    test6()
    test7()
    #test8()
    test9()
    test10()
    test11()

#test1()
#test2()
#test_get_attribute_all()
#main()
#test7()
#test8()
#test12()
#test6()
#test4()
#test9()
#test13()
#test14()
#test12(0x10,0x66,0x03,'\x00')
#test15(0x74,0x01,0x01,'\x00')
#test15(0x73,0x01,0x01,'\x00')
#test16(0x6b,0x01,0x03,'\x00\x01')
#test12(0x10,0x66,0x03,'\x00')
#test17()
#test20(0x4d,105,0)
#test20(0x4d,104,0)
#test20(0x4e,105,0)
#test20(0x4e,104,0)
#test20(0x4c,116,1)
#test20(0x51,106,9248)
#test20(0x50,106,26297)

def tests():
    #test12(0x10,0x66,0x03,'\x00') # SET_ATTRIBUTE_SINGLE
    #test15(0x74,0x01,0x01,'\x00') # Deny_PCCC_Execution
    #test15(0x73,0x01,0x01,'\x00') # Deny_Edit_Controller_Properties
    #test16(0x6b,0x01,0x03,'\x00\x01') # OPC_Test_Write
    #test7() # Deny_Set_Attr_Exc_AC_B2
    #test18() # Deny_Create_Exc_B2
    #test19() # Deny_Delete_Exc_B2
    #test20(0x4d,104,0) # Force_Enable_SFC_00 
    #test20(0x4d,105,0) # Force_Enable_IO_00
    #test20(0x4e,104,0) # Force_Disable_SFC_00
    #test20(0x4e,105,0) # Force_Disable_IO_00
    test20(0x4c,116,1) # Report_Unlock
    #test20(0x51,106,9248) #Deny_Toggle_Bit_2420
    #test20(0x50,106,26297) # Deny_Edit_Timer_66B9

tests()
