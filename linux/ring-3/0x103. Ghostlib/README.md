This shared object (.so) runs automatically when loaded. It creates a reverse shell to a specified IP and port, 
It redirects standard input, output, and error to the remote socket. It loads /bin/sh into memory using memfd_create() and executes it entirely from RAM with fexecve(). This method leaves no trace on disk and runs quietly in memory. 


so, the /bin/sh excuted from memory rather from disk this is the best area..


POC 📸:
<img width="1716" height="467" alt="image" src="https://github.com/user-attachments/assets/ff4efbea-3c6f-4db0-99d8-ce8725e13436" />



