import socket
import struct
import random
import sys

# List of IPv4 root DNS servers, taken from https://www.iana.org/domains/root/servers date: january 2025
ROOT_SERVERS = [
    "198.41.0.4",    # a.root-servers.net
    "199.9.14.201",  # b.root-servers.net
    "192.33.4.12",   # c.root-servers.net
    "199.7.91.13",   # d.root-servers.net
    "192.203.230.10",# e.root-servers.net
    "192.5.5.241",   # f.root-servers.net
    "192.112.36.4",  # g.root-servers.net
    "198.97.190.53", # h.root-servers.net
    "192.36.148.17", # i.root-servers.net
    "192.58.128.30", # j.root-servers.net
    "193.0.14.129",  # k.root-servers.net
    "199.7.83.42",   # l.root-servers.net
    "202.12.27.33",  # m.root-servers.net
]

def build_dns_query(domain, qtype=1):  #qtype 1 is A record, for example qtype 16 should be TXT but it won't work with this code because txt record follows another format. This code asumes ipv4.
    """
    Build a DNS query packet for the given domain.
    Example of the return: b'98\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
    It's a binary dns query packet, it's a raw DNS query asking for record A.
    """
    ID = random.randint(0, 65535)  # Random ID for the query
    FLAGS = 0x0100  # Standard query, based on executing dig, which has "flags: qr rd ra" which means "0x0100"
    QDCOUNT = 1     # Number of questions
    ANCOUNT = 0     # Number of answers
    NSCOUNT = 0     # Number of authority records
    ARCOUNT = 0     # Number of additional records

    # Pack the header
    header = struct.pack('!HHHHHH', ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Build the question section
    QNAME = b''
    for part in domain.split('.'):
        QNAME += struct.pack('!B', len(part)) + part.encode('utf-8')
    QNAME += b'\x00'  # End of domain name

    # QTYPE (1 for A record) and QCLASS (1 for IN)
    QTYPE = qtype
    QCLASS = 1

    # Pack the question, we convert the strings and ints into bytes
    question = QNAME + struct.pack('!HH', QTYPE, QCLASS)

    return header + question #Concatenation of header and question sections, it returns a binary packet

def send_dns_query(query, server, port=53):
    """
    Send a DNS query to the specified server and return the response.
    Example of the return: Response: b'\xb4\xac\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x88\x00\x04\x8e\xfb\x85\x0e'
    We get a raw dns response, there it's contained the dns header, question (this case google.com), and the answer which will be the ipv4.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, (server, port))
    response, _ = sock.recvfrom(512)  # DNS responses are typically <= 512 bytes
    sock.close()
    return response

def parse_dns_response(response):
    """
    Parse a DNS response and extract the IP address(es) or referrals.
    Example: IF we send a response to this function, one like this b'\xb4\xac\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x88\x00\x04\x8e\xfb\x85\x0e'
    but expressed in bytes, we will get result like this one:
    (['142.251.133.14'], [], []) this means: the A record that we wanted first, the ns server second, and the third one is additional records.
    """
    # Parse the header
    header = struct.unpack('!HHHHHH', response[:12])
    ANCOUNT = header[3]  # Number of answers
    NSCOUNT = header[4]  # Number of authority records
    ARCOUNT = header[5]  # Number of additional records

    # Parse the question section (skip it)
    offset = 12
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip QTYPE and QCLASS

    # Parse answers (if any)
    answers = []
    for _ in range(ANCOUNT):
        if (response[offset] & 0xC0) == 0xC0:  # Pointer
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1

        TYPE, CLASS, TTL, RDLENGTH = struct.unpack('!HHIH', response[offset:offset+10])
        offset += 10

        if TYPE == 1:  # A record
            ip = socket.inet_ntoa(response[offset:offset+4])
            answers.append(ip)
        offset += RDLENGTH

    # Parse authority section for referrals
    referrals = []
    for _ in range(NSCOUNT):
        if (response[offset] & 0xC0) == 0xC0:  # Pointer
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1

        TYPE, CLASS, TTL, RDLENGTH = struct.unpack('!HHIH', response[offset:offset+10])
        offset += 10

        if TYPE == 2:  # NS record
            name = parse_name(response, offset)
            referrals.append(name)
        offset += RDLENGTH

    # Parse additional section for IP addresses of referrals
    additional_ips = []
    for _ in range(ARCOUNT):
        if (response[offset] & 0xC0) == 0xC0:  # Pointer
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1

        TYPE, CLASS, TTL, RDLENGTH = struct.unpack('!HHIH', response[offset:offset+10])
        offset += 10

        if TYPE == 1:  # A record
            ip = socket.inet_ntoa(response[offset:offset+4])
            additional_ips.append(ip)
        offset += RDLENGTH

    return answers, referrals, additional_ips

def parse_name(response, offset):
    """
    Parse a DNS name from the response.
    Example of the return: www.google.com
    Why? because it takes values like these: b'\x03www\x06google\x03com\x00', 0
    And turns that into the string
    """
    name = []
    while True:
        length = response[offset]
        if (length & 0xC0) == 0xC0:  # Pointer
            pointer = struct.unpack('!H', response[offset:offset+2])[0] & 0x3FFF
            name.append(parse_name(response, pointer))
            offset += 2
            break
        else:
            offset += 1
            if length == 0:
                break
            name.append(response[offset:offset+length].decode('utf-8'))
            offset += length
    return '.'.join(name)

def resolve_domain(domain):
    """
    Resolve a domain name by querying the root servers and following referrals.
    What is this? It actually queries the Root server, follows the referrall and then returns the IP adress.
    """
    servers = ROOT_SERVERS  # Start with the root servers

    while servers:
        server = random.choice(servers)  # Pick a random server. Why? Any of the, just return the same data, we pick one randomly to avoid issues in the script if one has issues

        try:
            # Build and send the DNS query
            query = build_dns_query(domain)
            response = send_dns_query(query, server)

            # Parse the response
            answers, referrals, additional_ips = parse_dns_response(response)

            if answers:
                return answers  # Return the IP address(es)

            # If no answers it means the chosen root server doesn't know, so we follow referrals because the root server just tell us which other server to ask
            if referrals:
                # Use additional IPs if available, otherwise resolve the referral domain
                if additional_ips:
                    servers = additional_ips
                else:
                    servers = [resolve_domain(referral)[0] for referral in referrals]
            else:
                servers = []  # No more referrals to follow

        except (socket.timeout, socket.error):
            print(f"Timeout or error while querying {server}")
            servers.remove(server)  # Remove from the query the server from the list because it's not responding, we don't want to ask again, let's try another root server.

    return None  # Resolution failed

def extract_reversed_ip(domain):
    parts = domain.split(".")
    if len(parts) >= 5:  # Ensure it follows the reversed IP format
        return ".".join(parts[:4][::-1])  # Reverse the first four octets
    return domain  # If the format is incorrect, return the original domain


if __name__ == "__main__":
    # Check if the domain argument is provided
    if len(sys.argv) > 1:
        domain = sys.argv[1]  # Get the domain from the command-line argument
        ip_addresses = resolve_domain(domain)
        original_ip = extract_reversed_ip(domain)  # Extract the original IP
        if ip_addresses:
            print(f"The IP address(es) for {domain} is/are: {', '.join(ip_addresses)}")
        else:
            print(f"The record queried, {domain} which is the IP {original_ip}, is not blacklisted in a RBL")
    else:
        print("No domain provided. Usage: python resolve_domain.py <domain>")

