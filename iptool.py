import argparse
import os
import whois
import dns.resolver
import subprocess
import shodan

import re
import requests
import ipaddress
import ssl
import socket

import json
import textwrap

BOX_WIDTH = 80

def print_box_top(title):
    print("=" * BOX_WIDTH)
    print(f"| {title.ljust(BOX_WIDTH - 4)} |")
    print("=" * BOX_WIDTH)

def print_box_bottom():
    print("-" * BOX_WIDTH)

def print_box_content(line):
    line_str = str(line).replace('	', '    ')
    wrapper = textwrap.TextWrapper(width=BOX_WIDTH - 4, replace_whitespace=False, drop_whitespace=False)
    for wrapped_line in wrapper.wrap(line_str):
        print(f"| {wrapped_line.ljust(BOX_WIDTH - 4)} |")



def get_whois_info(target):
    """
    Gets WHOIS information for a domain or IP.
    """
    print_box_top("WHOIS Information (Domain/CIDR)")
    try:
        if is_ip_address(target) or is_cidr(target):
            try:
                result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=10)
                raw_whois = result.stdout
                if not raw_whois:
                    print_box_content("No WHOIS information found.")
                else:
                    inetnums = re.findall(r'inetnum:[\s]*(.*)', raw_whois, re.IGNORECASE)
                    organisation = re.search(r'(?:organisation|organization):[\s]*(.*)', raw_whois, re.IGNORECASE)
                    netname = re.search(r'netname:[\s]*(.*)', raw_whois, re.IGNORECASE)
                    descr = re.search(r'descr:[\s]*(.*)', raw_whois, re.IGNORECASE)
                    country = re.search(r'country:[\s]*(.*)', raw_whois, re.IGNORECASE)

                    if len(inetnums) > 1: print_box_content(f"Inetnum: {inetnums[1].strip()}")
                    elif inetnums: print_box_content(f"Inetnum: {inetnums[0].strip()}")

                    if organisation: print_box_content(f"Organisation: {organisation.group(1).strip()}")
                    if netname: print_box_content(f"Netname: {netname.group(1).strip()}")
                    if descr: print_box_content(f"Description: {descr.group(1).strip()}")
                    if country: print_box_content(f"Country: {country.group(1).strip()}")

                    if not any([inetnums, organisation, netname, descr, country]):
                        print_box_content("Specific WHOIS fields (inetnum, organisation, netname, descr, country) not found.")
                        print_box_content("Raw WHOIS output may contain more details.")

            except FileNotFoundError:
                print_box_content("'whois' command not found. Please install it (e.g., 'sudo apt-get install whois' on Debian/Ubuntu, 'brew install whois' on macOS).")
            except Exception as e:
                print_box_content(f"An error occurred during system WHOIS lookup: {e}")
        elif is_domain(target):
            # Use python-whois for domains, but only print meaningful fields
            w = whois.whois(target)
            if w:
                # List of fields to show
                fields_to_show = [
                    'domain_name', 'registrar', 'whois_server', 'referral_url', 'updated_date',
                    'creation_date', 'expiration_date', 'name_servers', 'status', 'emails', 'dnssec', 'org', 'address', 'city', 'state', 'zipcode', 'country'
                ]
                shown = False
                for key in fields_to_show:
                    value = getattr(w, key, None)
                    if value:
                        print_box_content(f"{key.replace('_', ' ').title()}: {value}")
                        shown = True
                if not shown:
                    print_box_content("No relevant WHOIS information found.")
            else:
                print_box_content("No WHOIS information found.")
        else:
            print_box_content("No WHOIS information found.")
    except Exception as e:
        print_box_content(f"An error occurred during WHOIS lookup: {e}")
    print_box_bottom()

def get_ip_asn_info(target):
    """
    Gets IP and ASN information for an IP address using ipinfo.io.
    """
    print_box_top("IP and ASN Information")
    api_key = os.environ.get("IPINFO_API_KEY")
    if not api_key:
        print_box_content("Error: IPINFO_API_KEY environment variable not set. IP/ASN information will be limited.")
        print_box_bottom()
        return
    url = f"https://ipinfo.io/{target}/json?token={api_key}"
    try:
        response = requests.get(url)
        data = response.json()
        if response.status_code == 200:
            print_box_content(f"IP: {data.get('ip')}")
            print_box_content(f"Hostname: {data.get('hostname')}")
            print_box_content(f"City: {data.get('city')}")
            print_box_content(f"Region: {data.get('region')}")
            print_box_content(f"Country: {data.get('country')}")
            print_box_content(f"Location: {data.get('loc')}")
            print_box_content(f"Organization: {data.get('org')}")
            print_box_content(f"Postal: {data.get('postal')}")
            print_box_content(f"Timezone: {data.get('timezone')}")
            asn_info = data.get('asn')
            if not asn_info:
                org_name = data.get('org', '')
                asn_match = re.search(r'AS(\d+)', org_name)
                if asn_match:
                    asn_info = f"AS{asn_match.group(1)}"
            print_box_content(f"ASN: {asn_info}")
        else:
            print_box_content(f"Error from ipinfo.io: {data.get('error', {}).get('message', 'Unknown error')}")
    except Exception as e:
        print_box_content(f"An error occurred during IP/ASN lookup: {e}")
    print_box_bottom()


def get_dns_info(target):
    """
    Gets DNS information for a domain.
    """
    print_box_top("DNS Information")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(target, record_type)
            print_box_content(f"--- {record_type} records ---")
            for rdata in answers:
                print_box_content(rdata.to_text())
        except dns.resolver.NoAnswer:
            print_box_content(f"No {record_type} records found.")
        except Exception as e:
            print_box_content(f"An error occurred during {record_type} record lookup: {e}")
    print_box_bottom()



def get_reverse_dns_info(ip_address):
    """
    Performs a reverse DNS lookup for an IP address and formats the output like dig.
    """
    resolver = dns.resolver.Resolver()
    server_ip = resolver.nameservers[0] if resolver.nameservers else "Unknown"
    print_box_top("Reverse DNS Information")
    print_box_content(f"Server:         {server_ip}")
    print_box_content(f"Address:        {server_ip}#53")
    print_box_content("") # Blank line for spacing after Address
    try:
        addr = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(addr, "PTR")
        print_box_content("") # Blank line before Non-authoritative answer
        print_box_content("Non-authoritative answer:")
        for rdata in answers:
            full_line = f"{ip_address.split('.')[::-1][0]}.{ip_address.split('.')[::-1][1]}.{ip_address.split('.')[::-1][2]}.{ip_address.split('.')[::-1][3]}.in-addr.arpa.    name = {str(rdata)}."
            print_box_content(full_line)
        print_box_content("") # Empty line for spacing
        print_box_content("Authoritative answers can be found from:")
    except dns.resolver.NXDOMAIN:
        reverse_name = dns.reversename.from_address(ip_address).to_text()
        print_box_content(f"** server can't find {reverse_name}: NXDOMAIN")
    except Exception as e:
        print_box_content(f"An error occurred during reverse DNS lookup: {e}")
    print_box_bottom()

def is_ip_address(target):
    """
    Checks if the target is an IP address.
    """
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_pattern.match(target)

def is_asn(target):
    """
    Checks if the target is an ASN.
    """
    asn_pattern = re.compile(r"^AS\d+$")
    return asn_pattern.match(target)

def is_cidr(target):
    """
    Checks if the target is a CIDR range.
    """
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False

def is_domain(target):
    """
    Checks if the target is a domain name.
    """
    domain_pattern = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )
    return domain_pattern.match(target)

def get_ip_reputation(ip_address):
    """
    Gets IP reputation information from AbuseIPDB.
    """
    print_box_top("IP Reputation (AbuseIPDB)")
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print_box_content("Error: ABUSEIPDB_API_KEY environment variable not set. IP reputation information will be limited.")
        print_box_bottom()
        return

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90&verbose="
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        if response.status_code == 200:
            report = data['data']
            print_box_content(f"Is Public: {report.get('isPublic')}")
            print_box_content(f"Abuse Confidence Score: {report.get('abuseConfidenceScore')}%")
            print_box_content(f"Total Reports: {report.get('totalReports')}")
            print_box_content(f"This IP was reported {report.get('totalReports', 0)} times")
            print_box_content(f"Last Reported At: {report.get('lastReportedAt')}")
            # Add TinyURL for the AbuseIPDB report
            abuse_url = f"https://www.abuseipdb.com/check/{ip_address}"
            try:
                tiny_resp = requests.get(f"https://tinyurl.com/api-create.php?url={abuse_url}")
                if tiny_resp.status_code == 200:
                    tiny_url = tiny_resp.text.strip()
                    print_box_content(f"AbuseIPDB Report: {tiny_url}")
                else:
                    print_box_content(f"AbuseIPDB Report: {abuse_url}")
            except Exception:
                print_box_content(f"AbuseIPDB Report: {abuse_url}")
            if report.get('categories'):
                print_box_content("Categories:")
                for category_id in report.get('categories', []):
                    # Map category ID to a more readable description (simplified for brevity)
                    category_map = {
                        3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
                        7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
                        11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
                        15: "Hacking", 16: "SQL Injection", 17: "XSS", 18: "Exploited Host",
                        19: "SSH Brute-Force", 20: "DNS Compromise", 21: "Warez", 22: "Bad Web Bot",
                        23: "Exploit Tool", 24: "Brute-Force", 25: "Bad Host", 26: "Forced Browsing",
                        27: "Link Rot", 28: "Carding", 29: "Remote Code Execution", 30: "Malware Distribution"
                    }
                    print_box_content(f"  - {category_map.get(category_id, f'Unknown ({category_id})')}")
            else:
                print_box_content("No abuse categories reported.")
        else:
            print_box_content(f"Error from AbuseIPDB: {data.get('errors', [{}])[0].get('detail', 'Unknown error')}")
    except Exception as e:
        print_box_content(f"An error occurred during AbuseIPDB lookup: {e}")
    print_box_bottom()

def get_asn_info(asn):
    """
    Gets ASN information using the O-X-L/geoip-asn API.
    """
    print_box_top(f"ASN Information for {asn}")
    url = f"https://geoip.oxl.app/api/asn/{asn.replace('AS', '')}"
    try:
        response = requests.get(url)
        data = response.json()
        if response.status_code == 200:
            for key, value in data.items():
                print_box_content(f"{key.replace('_', ' ').title()}: {value}")
        else:
            print_box_content(f"Error from O-X-L/geoip-asn: {data.get('message', 'Unknown error')}")
    except Exception as e:
        print_box_content(f"An error occurred during ASN lookup: {e}")
    print_box_bottom()

def main():
    parser = argparse.ArgumentParser(description='A tool to get information about an IP address, domain name, or ASN.')
    parser.add_argument('target', help='The IP address, domain name, or ASN to get information about.')
    args = parser.parse_args()    
    print(f"[+] Getting information for {args.target}...\n")    

    if is_domain(args.target):        
        get_whois_info(args.target)        
        get_dns_info(args.target)        
        try:
            ip_address = socket.gethostbyname(args.target)
            print(f"\n[+] Resolved {args.target} to {ip_address}. Performing IP-based lookups.\n")
            get_ip_asn_info(ip_address)
            get_reverse_dns_info(ip_address)
            get_ip_reputation(ip_address)
        except socket.gaierror as e:
            print_box_top("Domain Resolution Error")
            print_box_content(f"Could not resolve {args.target}: {e}")
            print_box_bottom()
    elif is_ip_address(args.target):
        get_ip_asn_info(args.target)
        get_reverse_dns_info(args.target)
        get_ip_reputation(args.target)
    elif is_asn(args.target):
        get_asn_info(args.target)
    elif is_cidr(args.target):
        network = ipaddress.ip_network(args.target, strict=False)
        first_ip = str(network.network_address)
        # If /32 (IPv4) or /128 (IPv6), treat as single IP (no CIDR message or note)
        if (network.version == 4 and network.prefixlen == 32) or (network.version == 6 and network.prefixlen == 128):
            get_ip_asn_info(first_ip)
            get_reverse_dns_info(first_ip)
            get_ip_reputation(first_ip)
            get_whois_info(first_ip)
        else:
            print("[+] Detected CIDR range. Performing lookup for the network address.")
            get_ip_asn_info(first_ip)
            get_whois_info(args.target) # Try WHOIS on the CIDR itself
            print("\nNote: For CIDR ranges, detailed per-IP lookups (like individual IP reputation or reverse DNS for every IP) are not performed due to performance and API rate limit considerations. Information is provided for the network block as a whole.")
    else:
        print("Error: Invalid target. Please provide a valid IP address, domain name, ASN, or CIDR range.")



if __name__ == '__main__':
    main()