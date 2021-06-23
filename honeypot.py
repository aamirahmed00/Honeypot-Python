from socket import *
from datetime import date,datetime
import nmap
import os,sys

log_name = "./log/"

def main():
    
    ip_address = "0.0.0.0"
    port = 23
    
    print("The Honeypot has started")
    print("Scanning for Intruders .... ")
    
    try:
        get_socket_con = socket(AF_INET,SOCK_STREAM)
        get_socket_con.bind((ip_address, port))
        get_socket_con.listen(10)
        
        while 1:
            client_con, client_address = get_socket_con.accept()
            
            print("An Intruder was Found!")
            print("IP of Intruder - [{}]".format(client_address[0]))
            
            scan_intruder(client_address[0])
            client_con.send(b"<h1> You have been hacked! </h1>")
            data = client_con.recv(2048)
            
            print(data.decode('utf-8'))
    except error as identifier:
        print("Unspecified error [{}]".format(identifier))
    
    except KeyboardInterrupt as ky:
        print("\n The Honeypot has stopped")
        get_socket_con.close()
    
    finally:
        get_socket_con.close()
    get_socket_con.close()

def scan_intruder(intruder_ip_address):
    
    today_date = date.today()
    datetime_now = datetime.now()
    dir_name = today_date.strftime("%d_%m_%Y")
    file_log_path = os.path.join(log_name, dir_name)
    
    isExist = os.path.exists(file_log_path)

    if(not isExist):
        os.mkdir(file_log_path)
        
    file_log_name = "/"+intruder_ip_address.replace(".", "_") +" "+ datetime.strftime(datetime_now, "%d_%m_%Y")+".log"
    
    print(file_log_name)
    print(file_log_path+file_log_name)
    isFile_Exist = os.path.isfile(file_log_path+file_log_name)
    
    if not isFile_Exist:
        is_write_or_append = "w"
    
    else:
        is_write_or_append = "a"
    
    with open(file_log_path+file_log_name, is_write_or_append) as fp:
        get_port_details = get_port_info(intruder_ip_address)
        print(get_port_details[0])
        fp.write("\n")

        for disp in range(len(get_port_details) -1):
            fp.write(str(get_port_details[disp]) + "\n")
        fp.write("\n")
        fp.close()

    print("Scanning the Intruder -  {} successfully completed ".format(file_log_path+file_log_name))

def get_port_info(ip_address):
    scanner = nmap.PortScanner()
    scanner.scan(hosts = ip_address)
    ip_status = scanner[ip_address].state()

    print("Intruder scanning in-progress .... ")
    sc = {}

    for host in scanner.all_hosts():
        detail_info = []
        
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            sc = scanner[host][proto]

            for port in lport:
                a = "port: " + str(port) + " Service Name: " + sc[port]['name'] + " Product Name: " + sc[port]['product']
                detail_info.append(a)
    return detail_info

if __name__ == '__main__':
    main()
