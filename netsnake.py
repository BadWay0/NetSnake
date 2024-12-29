import sys
import socket
import time
import datetime
import re

import argparse
import requests
import folium 
from colorama import *
import nmap
from datetime import datetime
import pyfiglet
import ipwhois
import dns.resolver

parser = argparse.ArgumentParser(prog='NetSnake', add_help=True)
custom_text = pyfiglet.figlet_format("NetSnake", font="slant")
nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
nm = nmap.PortScanner(nmap_search_path=nmap_path)
bssid_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

init(autoreset=True)

VERSION =  "beta 0.79"

date = datetime.today()

class Begining:

    def __init__(self, duration_time, start):

        self.duration_time = duration_time()
        self.command_start = start()

    def duration_time(start_time, end_time):

        duration = (end_time - start_time).total_seconds() 
        hours, remainder = divmod(duration, 3600) 
        minutes, seconds = divmod(remainder, 60) 
        print(Fore.GREEN + f"[*] Scan duration: {seconds:.1f}s")

    def start():
        print(custom_text)
        current_time = date.strftime('%H:%M:%S')
        print(f"[*] NetSnake Started at {current_time}\n")

    
class Brain:
    def __init__(self, prompt_brain, prompt_argument):
        self.prompt_brain = prompt_brain()
        self.prompt_argument = prompt_argument()
        
    def prompt_brain(prompt):
        
        whois = ipwhois.IPWhois(prompt) 
        whois_response = whois.lookup_rdap()
    
        try:
            response = requests.get(url=f"http://ip-api.com/json/{prompt}").json()

            data = {
                '[*] IP address' : response.get('query'),
                '[*] Provider' : response.get('isp'),
                '[*] ORG' : response.get('org'),
                '[*] Country' : response.get('country'),
                '[*] Region Name' : response.get('regionName'),
                '[*] City' : response.get('city'),
                '[*] Zip' : response.get('zip'),
                '[*] Latitude' : response.get('lat'),
                '[*] Longitude' : response.get('lon'),
                '[*] ASN' : whois_response['asn'],
                '[*] CIDR' : whois_response['network']['name'],
                '[*] Time Zone' : response.get('timezone')
            } 

            for k, v in data.items():
                print(f"{k} - {v}")
            try:
                area = folium.Map(location=[ response.get('lat'),  response.get('lon')])
                area.save(f'{response.get("query")}_{ response.get("city")}.html')
            except ValueError as error:
                print(Fore.RED + f"[!] Somethings was wrong - {error}")

        except requests.exceptions.ConnectionError:
            print(Fore.RED + "[!] Please check your connection")

        d_i = data.items()
        
        print(Fore.GREEN + f"\n[*] The result is saved to an html file in the file folder")
        parser.add_argument('-pR', '--prompt', type=Brain.prompt_argument, help="Simple information from the IP")
    def prompt_argument(prompt):
        start_time_prompt = datetime.now()    
        Brain.prompt_brain(prompt)
        end_time_prompt = datetime.now()

        Begining.duration_time(start_time_prompt, end_time_prompt)

def write_argument(file_path):
    pass
class Utils:
    def __init__(self, url_argument, nm_argument):
        self.url_argument = url_argument()
        self.nm_argument = nm_argument()
        
    def url_argument(prompt):
        
        try:  
            sock = socket.gethostbyname(prompt)

            Begining.start()
        
            print(f'HostName: {prompt} \nIP address: {sock}\n')
        except (socket.gaierror, UnboundLocalError) as error:
            print(Fore.RED + f'[!] Invalid HostName - {error} (NetSnake)')

        Brain.prompt_argument(sock)

    def nm_argument(prompt):
        Begining.start()
        start_time = datetime.now()
        
        
        nm.scan(prompt, '1-1024', arguments='-sV -O')
        for host in nm.all_hosts(): 
            print(f'Host: {host} ({nm[host].hostname()})') 
            print(f'State: {nm[host].state()}') 

            for proto in nm[host].all_protocols():
                print(f'Protocol: {proto}') 
                lport = nm[host][proto].keys()
                for port in lport: 
                    state = nm[host][proto][port]['state'] 
                    if state == 'open': 
                        print(f'Open Port: {port}\t({state})')

        if 'osclass' in nm[prompt]:
            for osclass in nm[prompt]['osclass']:
                print(f"OS: {osclass['osfamily']}   probability: {osclass['accuracy']}%")

        end_time = datetime.now()

        Begining.duration_time(start_time, end_time)



    def check_spam(prompt1):
        Begining.start()
        start_time = datetime.now()
        url = 'http://www.ip-score.com/ajax_handler/get_bls'


        count = 0
        blacklist = [
            "all.s5h.net",
            'access.redhawk.org',
            "bogons.cymru.com",
            "db.wpbl.info",
            "dnsbl-2.uceprotect.net",
            "dnsbl.dronebl.org",
            "drone.abuse.ch",
            "dul.dnsbl.sorbs.net",
            "http.dnsbl.sorbs.net",
            "ix.dnsbl.manitu.net",
            "misc.dnsbl.sorbs.net",
            "orvedb.aupads.org",
            "psbl.surriel.com",
            "relays.nether.net",
            "smtp.dnsbl.sorbs.net",
            "spam.abuse.ch",
            "spam.dnsbl.sorbs.net",
            "spambot.bls.digibase.ca",
            "spamsources.fabel.dk",
            "ubl.unsubscore.com",
            "web.dnsbl.sorbs.net",
            "z.mailspike.net",
            "b.barracudacentral.org",
            "blacklist.woody.ch",
            "combined.abuse.ch",
            "dnsbl-1.uceprotect.net",
            "dnsbl-3.uceprotect.net",
            "dnsbl.sorbs.net",
            "duinv.aupads.org",
            "dyna.spamrats.com",
            "ips.backscatterer.org",
            "korea.services.net",
            "noptr.spamrats.com",
            "proxy.bl.gweep.ca",
            "relays.bl.gweep.ca",
            "singular.ttk.pte.hu",
            "socks.dnsbl.sorbs.net",
            "spam.dnsbl.anonmails.de",
            "spam.spamrats.com",
            "spamrbl.imp.ch",
            "ubl.lashback.com",
            "virus.rbl.jp",
            "wormrbl.imp.ch",
            "zombie.dnsbl.sorbs.net"
        ]
        for server in blacklist:
            try:
                
                data = {'ip': prompt1, 'server': server}

                response = requests.post(url, data=data, timeout=3)

                if response.status_code != 200:
                    raise ValueError('Expected 200 OK')

                data = response.json()

                rating = data[list(data.keys())[0]]
                if rating != "0":
                    print(server + ": " + rating)
                    count += 1
            except:
                sys.stderr.write ("Skip server: " + server + "\n")

        if count <= 5:
            print(Fore.GREEN + f"\n[*] Total servers that confirmed the IP is in the blacklist: {count}")
        elif count <= 10:
            print(Fore.YELLOW + f"\n[*] Total servers that confirmed the IP is in the blacklist: {count}")
        else:
            print(Fore.RED + f"\n[*] Total servers that confirmed the IP is in the blacklist: {count}")



    def get_mac_info(mac_address):
        Begining.start()
        
        if not isinstance(mac_address, str):
            print(f"'[!] {mac_address}' isn't a string")

        print(f"[*] Received MAC address for verification: {mac_address}")
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if not mac_pattern.match(mac_address):
            print(Fore.RED + f"[!] '{mac_address}' is not a valid MAC-address")
        
        start_mac_time = datetime.now()
        try:
            response = requests.get(f"https://www.macvendorlookup.com/api/v2/{mac_address}")
            if response.status_code == 200:
                mac_response = response.json()[0]
                mac_info_dict = {
                    '[*] MAC Address': mac_address,
                    '[*] Manufacturer': mac_response.get("company"),
                    '[*] AddressL1': mac_response.get("addressL1"),
                    '[*] AddressL2': mac_response.get("addressL2"),
                    '[*] AddressL3': mac_response.get("addressL3"),
                    '[*] Type': mac_response.get("type"),
                    '[*] Start HEX': mac_response.get("startHex"),
                    '[*] End HEX': mac_response.get("endHex"),
                    '[*] Start DEC': mac_response.get("startDec"),
                    '[*] End DEC': mac_response.get("endDec")
                }
                for k, v in mac_info_dict.items():
                    print(f"{k} - {v}")
            else:
                print(f": {response.status_code}")
        except requests.RequestException as e:
            print(Fore.RED + f"[!] Request Error: {e}")  

        end_mac_time = datetime.now()
        Begining.duration_time(start_mac_time, end_mac_time)



    def dns_resolve(resolve_url):
        Begining.start()

        start_dns_time = datetime.now()

        ip_res = dns.resolver.resolve(resolve_url, 'A')
        mx_res = dns.resolver.resolve(resolve_url, 'MX')
        ns_res = dns.resolver.resolve(resolve_url, 'NS')

        for ip_record in ip_res:
            print(f"[*] IP-address - {ip_record.to_text()}")

        for mx_r in mx_res:
            print(f"[*] MX - {mx_r.to_text()}")

        for ns_r in ns_res:
            print(f"[*] NS - {ns_r.to_text()}")

        try: 
            cname_record = dns.resolver.resolve(resolve_url, 'CNAME') 
            for record in cname_record: 
                print(f'[*] CNAME - {record.target}') 
                
        except dns.resolver.NoAnswer: print(Fore.BLUE + f'\n[*] No CNAME record found for {resolve_url}') 
        except dns.resolver.NXDOMAIN: print(Fore.RED + f'\n[*]{resolve_url} does not exist in the DNS') 
        except Exception as e: print(Fore.RED + f'[!] Error: {e}')

        try: 
            srv_record = dns.resolver.resolve(f'_sip._tcp.{resolve_url}', 'SRV') 
            for record in srv_record: 
                print(f'SRV Record for {resolve_url} - {record.target}: \nPriority: {record.priority} \nWeight: {record.weight} \nPort: {record.port}') 
        except dns.resolver.NoAnswer: print(Fore.BLUE + f'[*] No SRV record found for {resolve_url}') 
        except dns.resolver.NXDOMAIN: print(Fore.BLUE + f'[*] {resolve_url} does not exist in the DNS') 
        except Exception as e: print(f'Error: {e}')
        end_dns_time = datetime.now()
        Begining.duration_time(start_dns_time, end_dns_time)



def parse_arguments():
    parser = argparse.ArgumentParser(prog="NetSnake")
    parser.add_argument('-mI', '--mac-info', type=Utils.get_mac_info, help='Displays information about the MAC address')
    parser.add_argument('-pR', '--prompt', type=Brain.prompt_argument, help="Simple information from the IP")
    parser.add_argument('-u', '--url', type=Utils.url_argument, help="Finds out the url ip address and displays information about it")
    parser.add_argument('-f', '--file', type=write_argument, help="Imports ip addresses from a txt file and displays information about them (used with --write)")
    parser.add_argument('-w', '--write', help="Saves all files and their information to a txt file (used with --file)")
    parser.add_argument('-v', '--version', action='version', version=f'Version: {VERSION}', help="Show program version and exit")
    parser.add_argument('-nS', '--nmap-scanner', type=Utils.nm_argument, help="Normal scanning with nmap (more information on the website nmap.org)")
    parser.add_argument('-sC', '--spam-chek', type=Utils.check_spam, help="Checking spam-database")
    parser.add_argument('-dR', "--dns-resolve", type=Utils.dns_resolve, help="resolve dns")

    return parser.parse_args()

def main():
    args = parse_arguments()
    
if __name__ == "__main__":
    try:
        main()

    except Exception as exc:
        print(Fore.RED + f"[!] Error - {exc}")