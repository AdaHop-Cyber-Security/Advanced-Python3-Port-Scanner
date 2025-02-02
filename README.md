### Usage

1. **Port Scanning:**  
   Use the `scan` sub-command. For example, to scan the CIDR `192.168.1.0/24` for ports 22 and 80 using TCP and UDP with OS detection, run:  
   ```bash
   python advanced_net_tool.py scan --targets 192.168.1.0/24 --ports 22,80 --protocol both --os-detect --banner
   ```

2. **SMB Operations:**  
   - **Enumeration:** (Try anonymous login or provide credentials)  
     ```bash
     python advanced_net_tool.py smb --action enum --target 192.168.1.10
     ```  
   - **Credential Spraying:**  
     Prepare files with usernames and passwords and run:  
     ```bash
     python advanced_net_tool.py smb --action spray --target 192.168.1.10 --user-file users.txt --pass-file passwords.txt
     ```

3. **DNS Lookups:**  
   Reverse‑resolve IPs:  
   ```bash
   python advanced_net_tool.py dns --targets 8.8.8.8,8.8.4.4
   ```
