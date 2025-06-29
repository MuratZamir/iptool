# IPTool - Reconnaissance CLI Tool

IPTool is a command-line interface (CLI) tool designed to gather detailed information about IP addresses, domain names, and Autonomous System Numbers (ASNs). It aggregates data from various open-source tools and APIs to provide a comprehensive overview for security engineers and ethical hackers.

## Features

- **WHOIS Lookup:** Retrieve registration information for domains and IP addresses.
- **DNS Resolution:** Get various DNS records (A, AAAA, MX, NS, TXT, SOA) for domain names.
- **IP and ASN Information:** Retrieve detailed information about IP addresses and ASNs.
- **IP Reputation:** Check if an IP address is listed as a known bad actor on AbuseIPDB.
- **Reverse DNS Lookup:** Perform reverse DNS lookups for IP addresses.
- **CIDR Lookup:** Get information about IP address ranges (CIDRs), with a note on per-IP lookup limitations.
- **Shodan Integration:** Get information about open ports and services from Shodan.

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd iptool
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```



4.  **Obtain ipinfo.io API Key (for IP/ASN information):**
    To get detailed IP and ASN information, you need an API key from [ipinfo.io](https://ipinfo.io/).
    - Go to [ipinfo.io](https://ipinfo.io/) and sign up for a free account.
    - Once logged in, you can find your API token on your dashboard.
    - Set your API key as an environment variable named `IPINFO_API_KEY`. For persistent setting across reboots, add the `export` command to your shell's profile file (e.g., `~/.bashrc`, `~/.zshrc`):

    ```bash
    export IPINFO_API_KEY="YOUR_ACTUAL_API_KEY"
    ```

5.  **Obtain AbuseIPDB API Key (for IP Reputation):**
    To check IP reputation, you need an API key from [AbuseIPDB](https://www.abuseipdb.com/).
    - Go to [AbuseIPDB](https://www.abuseipdb.com/) and register for a free account.
    - Once logged in, navigate to your API page to generate a key.
    - Set your API key as an environment variable named `ABUSEIPDB_API_KEY`. For persistent setting across reboots, add the `export` command to your shell's profile file (e.g., `~/.bashrc`, `~/.zshrc`):

    ```bash
    export ABUSEIPDB_API_KEY="YOUR_ACTUAL_API_KEY"
    ```

6.  **Obtain Shodan API Key:**
    To get information from Shodan, you need an API key from [Shodan](https://www.shodan.io/).
    - Go to [Shodan](https://www.shodan.io/) and register for a free account.
    - Once logged in, you can find your API key on your account page.
    - Set your API key as an environment variable named `SHODAN_API_KEY`. For persistent setting across reboots, add the `export` command to your shell's profile file (e.g., `~/.bashrc`, `~/.zshrc`):

    ```bash
    export SHODAN_API_KEY="YOUR_ACTUAL_API_KEY"
    ```

## Usage

Run the tool from your terminal:

```bash
python3 iptool.py <target>
```

Replace `<target>` with an IP address, domain name, or ASN.

**Examples:**

-   **Domain Lookup:**
    ```bash
    python3 iptool.py google.com
    ```

-   **IP Address Lookup:**
    ```bash
    python3 iptool.py 8.8.8.8
    ```

-   **ASN Lookup:**
    ```bash
    python3 iptool.py AS15169 # Example ASN for Google
    ```

-   **CIDR Lookup:**
    ```bash
    python3 iptool.py 41.77.152.0/21 # Example CIDR range
    ```
    *Note: For CIDR ranges, detailed per-IP lookups (like individual IP reputation or reverse DNS for every IP) are not performed due to performance and API rate limit considerations. Information is provided for the network block as a whole.*

## Future Enhancements
