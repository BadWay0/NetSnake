import argparse
import requests
import folium 
from colorama import *
import socket
import time
import datetime
import nmap

init(autoreset=True)

VERSION =  "beta"
nm = nmap
date = datetime.datetime.today()

#functions

def command_start():
    current_time = date.strftime('%H:%M:%S')
    print(f"NetSnake Started at {current_time}\n")

def prompt_argument(prompt):

    try:
        response = requests.get(url=f"http://ip-api.com/json/{prompt}").json()
        #print(response)

        data = {
            '[IP]' : response.get('query'),
            '[Int prov]' : response.get('isp'),
            '[Org]' : response.get('org'),
            '[Country]' : response.get('country'),
            '[Region Name]' : response.get('regionName'),
            '[City]' : response.get('city'),
            '[Zip]' : response.get('zip'),
            '[Lat]' : response.get('lat'),
            '[Lon]' : response.get('lon')
        }

        for k, v in data.items():
            print(f"{k} = {v}")
        try:
            area = folium.Map(location=[ response.get('lat'),  response.get('lon')])
            area.save(f'{response.get("query")}_{ response.get("city")}.html')
        except ValueError:
            print("")

    except requests.exceptions.ConnectionError:
        print(Fore.RED + "[!] Please check your connection")

    d_i = data.items()

    print(Fore.GREEN + f"\n[*] The result is saved to an html file in the file folder")

def write_argument(file_path):
    pass
    
def help_argument():
    command_start()

    print("""
-h, --help - Show this help message and exit
-f, --file <FILEPATH> - 
    """)

help_m = help_argument

def url_argument(prompt):
    try:  
        sock = socket.gethostbyname(prompt)

        command_start()
    
        print(f'HostName: {prompt} \nIP address: {sock}\n')
    except (socket.gaierror, UnboundLocalError) as error:
        print(Fore.RED + f'[!] Invalid HostName - {error} (NetSnake)')

    prompt_argument(sock)



def main():
    try:
        parser = argparse.ArgumentParser(prog='NetSnake', add_help=True)
        parser.add_argument('-pR', '--prompt', type=prompt_argument, help="")
        parser.add_argument('-u', '--url', type=url_argument, help="Finds out the url ip address and displays information about it")
        parser.add_argument('-f', '--file', type=argparse.FileType('r'), help="Imports ip addresses from a txt file and displays information about them (used with write)")
        parser.add_argument('-w', '--write', help="Saves all files and their information to a txt file (used with file)")
        parser.add_argument('-v', '--version', action='version', version=f'Version: {VERSION}', help="Show program version and exit")

        args = parser.parse_args()
    except (socket.gaierror, UnboundLocalError, KeyboardInterrupt) as error:
        print(Fore.RED + f'[!] Error - {error}')

if __name__ == "__main__":
    main()

