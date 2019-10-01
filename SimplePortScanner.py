#!usr/bin/python3

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = input("Enter the IP you want to scan: ")
port = int(input("Enter the port you want to scan: "))
s.settimeout(5)

def portScanner(port):
    if s.connect_ex((host, port)):
        print ("The port is closed")
    else:
        print("The port is open")

portScanner(port)
