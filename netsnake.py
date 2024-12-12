import argparse
import requests
import folium 
from colorama import *
import socket
import time
import datetime
import nmap
import sys
from datetime import datetime



nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
nm = nmap.PortScanner(nmap_search_path=nmap_path)

init(autoreset=True)

VERSION =  "beta 0.69"

date = datetime.today()


#functions

def duration_time_func(start_time, end_time):

    duration = (end_time - start_time).total_seconds() 
    hours, remainder = divmod(duration, 3600) 
    minutes, seconds = divmod(remainder, 60) 
    print(Fore.GREEN + f"[*] Scan duration: {seconds:.1f}s")

def command_start():
    current_time = date.strftime('%M:%S')
    print(f"[*] NetSnake Started at {current_time}\n")

    

def prompt_argument1(prompt):

    try:
        response = requests.get(url=f"http://ip-api.com/json/{prompt}").json()
        #print(response)

        data = {
            '[*] IP address' : response.get('query'),
            '[*] Provider' : response.get('isp'),
            '[*] ORG' : response.get('org'),
            '[*] Country' : response.get('country'),
            '[*] Region Name' : response.get('regionName'),
            '[*] City' : response.get('city'),
            '[*] Zip' : response.get('zip'),
            '[*] Latitude' : response.get('lat'),
            '[*] Longitude' : response.get('lon')
        }

        for k, v in data.items():
            print(f"{k} = {v}")
        try:
            area = folium.Map(location=[ response.get('lat'),  response.get('lon')])
            area.save(f'{response.get("query")}_{ response.get("city")}.html')
        except ValueError as error:
            print(Fore.RED + f"[!] Somethings was wrong - {error}")

    except requests.exceptions.ConnectionError:
        print(Fore.RED + "[!] Please check your connection")

    d_i = data.items()

    print(Fore.GREEN + f"\n[*] The result is saved to an html file in the file folder")

def prompt_argument(prompt):
    start_time_prompt = datetime.now()    
    prompt_argument1(prompt)
    end_time_prompt = datetime.now()

    duration_time_func(start_time_prompt, end_time_prompt)
def write_argument(file_path):
    command_start()

    pass

def url_argument(prompt):
    
    try:  
        sock = socket.gethostbyname(prompt)

        command_start()
    
        print(f'HostName: {prompt} \nIP address: {sock}\n')
    except (socket.gaierror, UnboundLocalError) as error:
        print(Fore.RED + f'[!] Invalid HostName - {error} (NetSnake)')

    prompt_argument(sock)

def nm_argument(prompt):
    command_start()
    start_time = datetime.now()
    
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
    nm = nmap.PortScanner(nmap_search_path=nmap_path)
    nm.scan(prompt, '1-1024', arguments='-sV -O')
    for host in nm.all_hosts(): 
        print(f'Host: {host} ({nm[host].hostname()})') 
        print(f'State: {nm[host].state()}') 

        for proto in nm[host].all_protocols():
            print(f'Protocol: {proto}') 
            lport = nm[host][proto].keys()
            for port in lport: 
                state = nm[host][proto][port]['state'] 
                if state == 'open': # Перевірка, чи порт відкритий 
                    print(f'Open Port: {port}\tState: {state}')

    end_time = datetime.now()

    duration_time_func(start_time, end_time)
    

def main():
    try:
        parser = argparse.ArgumentParser(prog='NetSnake', add_help=True)
        parser.add_argument('-pR', '--prompt', type=prompt_argument, help="")
        parser.add_argument('-u', '--url', type=url_argument, help="Finds out the url ip address and displays information about it")
        parser.add_argument('-f', '--file', type=argparse.FileType('r'), help="Imports ip addresses from a txt file and displays information about them (used with write)")
        parser.add_argument('-w', '--write', help="Saves all files and their information to a txt file (used with file)")
        parser.add_argument('-v', '--version', action='version', version=f'Version: {VERSION}', help="Show program version and exit")
        parser.add_argument('-nS', '--nmap-scanner', type=nm_argument, help="scan with nmap")
        args = parser.parse_args()
    except (socket.gaierror, UnboundLocalError, KeyboardInterrupt) as error:
        print(Fore.RED + f'[!] Error - {error}')

if __name__ == "__main__":
    main()

