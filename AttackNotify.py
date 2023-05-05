import dpkt
import socket
import threading
import time
import discord

# Set the IP address and port number to listen on
HOST = '0.0.0.0'
PORT = 8080

# Set the threshold for detecting a DDoS attack
THRESHOLD = 1000

# Set the Discord webhook URL for sending notifications
DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/your-webhook-url-here'

# Create a UDP socket and bind it to the specified address and port
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

# Define a function to parse incoming network traffic
def parse_packet(packet):
    try:
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        if isinstance(ip.data, dpkt.tcp.TCP):
            src_port = ip.data.sport
            dst_port = ip.data.dport
            if dst_port == PORT:
                return src_ip
    except Exception as e:
        print(e)
        return None

# Define a function to send notifications to Discord
def send_discord_notification(msg):
    client = discord.Webhook.from_url(DISCORD_WEBHOOK_URL, adapter=discord.RequestsWebhookAdapter())
    client.send(msg)

# Define a function to monitor incoming network traffic for DDoS attacks
def monitor_traffic():
    traffic = {}
    while True:
        packet, addr = sock.recvfrom(65535)
        src_ip = parse_packet(packet)
        if src_ip is not None:
            if src_ip in traffic:
                traffic[src_ip] += 1
            else:
                traffic[src_ip] = 1
            if traffic[src_ip] >= THRESHOLD:
                msg = f"DDoS attack detected from {src_ip}!"
                send_discord_notification(msg)
                print(msg)
                traffic = {}

# Start the monitoring thread
monitor_thread = threading.Thread(target=monitor_traffic)
monitor_thread.start()

# Main loop
while True:
    time.sleep(1)
