import sys
import socket
import time
import datetime
import re
import ssl

import argparse
import requests
from colorama import Fore, init
import nmap 
from datetime import datetime
import pyfiglet
import ipwhois
import dns.resolver

from lists import BLACKLIST 

headers = {
    'User-Agent' : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

parser = argparse.ArgumentParser(prog='NetSnake', add_help=True)
custom_text = pyfiglet.figlet_format("NetSnake", font="slant")
nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
nm = nmap.PortScanner(nmap_search_path=nmap_path)
init(autoreset=True)

VERSION =  "beta 0.91"

date = datetime.today()

class Begining:

    def __init__(self, duration_time, start):

        self.duration_time = duration_time()
        self.command_start = start()

    def duration_time(start_time, end_time):

        duration = (end_time - start_time).total_seconds() 
        hours, remainder = divmod(duration, 3600) 
        minutes, seconds = divmod(remainder, 60) 
        print(Fore.GREEN + f"\n[*] Scan duration: {seconds:.1f}s")

    def start():
        print(custom_text)
        current_time = date.strftime('%H:%M:%S')
        print(f"[*] NetSnake Started at {current_time}\n")

    
class Main:
    def __init__(self, prompt_brain, prompt_argument):
        self.prompt_brain = prompt_brain()
        self.prompt_argument = prompt_argument()
        
    def basic_main(ip_addr):
        promptf = str(ip_addr)
        whois = ipwhois.IPWhois(promptf) 
        whois_response = whois.lookup_rdap()
        
        try:

            response = requests.get(url=f"http://ip-api.com/json/{promptf}", headers=headers).json()
            gmaps_link = f"https://maps.google.com?saddr=Current+Location&daddr={response.get('lat')},{response.get('lon')}"

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
                '[*] Link for Google Maps' : gmaps_link,
                '[*] ASN' : whois_response['asn'],
                '[*] CIDR' : whois_response['network']['name'],
                '[*] Time Zone' : response.get('timezone'),
            }

            for k, v in data.items():
                print(f"{k} - {v}")
            print('\n')

        except requests.exceptions.ConnectionError:
            print(Fore.RED + "[!] Please check your connection")

        d_i = data.items()
        
    def prompt_argument(prompt):
        start_time_prompt = datetime.now()    
        Main.basic_main(prompt)
        end_time_prompt = datetime.now()

        Begining.duration_time(start_time_prompt, end_time_prompt)

class Utils:
    def __init__(self, url_argument, nm_argument, check_spam, get_mac_info):
        self.url_argument = url_argument()
        self.nm_argument = nm_argument()
        self.check_spam  = check_spam()
        self.get_mac_info = get_mac_info()
        
    def hostname_argument(ip_addr):
        promptf = str(ip_addr)
        try:  
            sock = socket.gethostbyname(promptf)

            Begining.start()
        
            print(f'HostName: {promptf} \nIP address: {sock}\n')
        except (socket.gaierror, UnboundLocalError) as error:
            print(Fore.RED + f'[!] Invalid HostName - {error} (NetSnake)')
            
        ssl_context = ssl.create_default_context()
        conn = ssl_context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=promptf)  
        conn.connect((sock, 443))

        cert = conn.getpeercert()
        conn.close
        whois = ipwhois.IPWhois(sock) 
        whois_response = whois.lookup_rdap()
    
        try:
            response = requests.get(url=f"http://ip-api.com/json/{sock}", headers=headers).json()
            gmaps_link = f"https://maps.google.com?saddr=Current+Location&daddr={response.get('lat')},{response.get('lon')}"

            data = {
                '[*] IP address' : response.get('query'),
                '[*] Provider' : response.get('isp'),
                '[*] DNS' : cert['subjectAltName'][0],
                '[*] ORG' : response.get('org'),
                '[*] Country' : response.get('country'),
                '[*] Region Name' : response.get('regionName'),
                '[*] City' : response.get('city'),
                '[*] Zip' : response.get('zip'),
                '[*] Latitude' : response.get('lat'),
                '[*] Longitude' : response.get('lon'),
                '[*] Link for Google Maps' : gmaps_link,
                '[*] ASN' : whois_response['asn'],
                '[*] CIDR' : whois_response['network']['name'],
                '[*] Time Zone' : response.get('timezone'),
                '[*] OCSP' : cert['OCSP'],
                '[*] Not Before' : cert["notBefore"],
                '[*] Not After' : cert['notAfter'],
                '[*] caIssuers' : cert['caIssuers'],
            }

            for k, v in data.items():
                print(f"{k} - {v}")
            print('\n')

        except requests.exceptions.ConnectionError:
            print(Fore.RED + "[!] Please check your connection")

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

    def check_spam(ip):
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
        
        for server in BLACKLIST:
            try:
                
                data = {'ip': ip, 'server': server}

                response = requests.post(url, data=data, timeout=3)

                if response.status_code != 200:
                    raise ValueError('Expected 200 OK')

                data = response.json()

                rating = data[list(data.keys())[0]]
                if rating != "0":
                    print(server + ": " + rating)
                    count += 1
            except:
                sys.stderr.write(f"Skip server: {server}\n")

        if count <= 5:
            print(Fore.GREEN + f"\n[*] Total servers that confirmed the IP is in the blacklist: {count}")
        elif count <= 10:
            print(Fore.YELLOW + f"\n[*] Total servers that confirmed the IP is in the blacklist: {count}")
        else:
            print(Fore.RED + f"\n[*] Total servers that confirmed the IP is in the blacklist: {count}")

    def get_mac_info(mac_address):
        macf = str(mac_address)
        Begining.start()
        


        print(f"[*] Received MAC address for verification: {macf}")
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if not mac_pattern.match(macf):
            print(Fore.RED + f"[!] '{macf}' is not a valid MAC-address")
        
        start_mac_time = datetime.now()
        try:
            response = requests.get(f"https://www.macvendorlookup.com/api/v2/{macf}")
            if response.status_code == 200:
                mac_response = response.json()[0]
                mac_info_dict = {
                    '[*] MAC Address': macf,
                    '[*] Manufacturer': mac_response.get("company"),
                    '[*] Manufacturer Address': f"{mac_response.get("addressL1")}, {mac_response.get("addressL2"), {mac_response.get("addressL3")}}",
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
    parser.add_argument('-mA', '--mac-info', type=Utils.get_mac_info, help='Displays information about the MAC address')
    parser.add_argument('-ip', '--ip-address', type=Main.prompt_argument, help="Simple information from the IP")
    parser.add_argument('-hN', '--hostname', type=Utils.hostname_argument, help="Finds out the url ip address and displays information about it")
    parser.add_argument('-v', '--version', action='version', version=f'Version: {VERSION}', help="Show program version and exit")
    parser.add_argument('-nS', '--nmap-scan', type=Utils.nm_argument, help="Normal scanning with nmap (more information on the website nmap.org)")
    parser.add_argument('-sC', '--spam-chek', type=Utils.check_spam, help="Checking spam-database")
    parser.add_argument('-dR', "--dns-resolve", type=Utils.dns_resolve, help="resolve dns")

    args = parser.parse_args()

    return args

if __name__ == "__main__":
    try:
        parse_arguments()

    except Exception as exc:
        print(Fore.RED + f"[!] Error - {exc}")