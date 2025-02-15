# metasploit-ldapnightmare
SafeBreaches CVE-2024-49113 POC(LdapNightmare) Integrated into Metasploit

## Overview

This module implements CVE-2024-49113, a critical vulnerability in the Windows LDAP client that can cause system instability. The module integrates with the Metasploit Framework, providing a reliable way to test system resilience against this vulnerability.

## Features

- Full Metasploit Framework integration
- Asynchronous LDAP server implementation
- Configurable parameters for testing different scenarios
- Detailed logging and status reporting
- Built-in safety checks and dependency verification

## Requirements

- Python 3.5 or newer
- Metasploit Framework
- Required Python packages:
  ```
  ldaptor
  impacket
  ```

## Installation

1. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

2. Place the module in your Metasploit modules directory:
   ```bash
   cp ldapnightmare.py /path/to/metasploit/modules/auxiliary/dos/windows/ldap/
   ```

3. Ensure the module is executable:
   ```bash
   chmod +x ldapnightmare.py
   ```

## Usage

### Within Metasploit Framework:

1. Start msfconsole:
   ```bash
   msfconsole
   ```

2. Load and configure the module:
   ```
   use auxiliary/dos/windows/ldap/ldapnightmare
   set RHOSTS target_ip
   set RPORT 49664
   set LPORT 389
   set DOMAINNAME yourdomain.com
   run
   ```

### Configuration Options

- `RHOSTS` - Target address (required)
- `RPORT` - Target port for RPC (default: 49664)
- `LPORT` - Local port for LDAP server (default: 389)
- `DOMAINNAME` - Attacker's domain name (required). This domain must have specific DNS SRV records configured (see Domain Configuration below)
- `ACCOUNT` - Target account name (default: Administrator)
- `SITENAME` - Target site name (default: empty)

### Domain Configuration

The `DOMAINNAME` parameter requires specific DNS SRV records to be configured. The domain must have two SRV records under it:

1. `ldap.tcp.dc._msdcs.domain_name` → `listen_port attacker's_machine_hostname`
2. `ldap.tcp.default-first-site-name._sites.dc._msdcs.domain_name` → `listen_port attacker's_machine_hostname`

**Important Note**: The attacker's machine hostname will work only if the victim server can resolve it using NBNS. Alternatively, you can replace the hostname with a domain name that points to the IP address of your LDAP server.

## Technical Details

The module operates in three main stages:

1. Sets up an asynchronous LDAP server to handle incoming connections
2. Initiates a DsrGetDcNameEx2 RPC call to trigger LDAP client behavior
3. Sends a specially crafted LDAP response to demonstrate the vulnerability

## Credits

- Original Research: SafeBreach Labs
- Authors: Or Yair, Shahak Morag
- Metasploit Integration: 0xMetr0

## References

- [SafeBreach Labs CVE-2024-49113 Research](https://github.com/SafeBreach-Labs/CVE-2024-49113)
- [CVE-2024-49113 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49113)

## Disclaimer

This module is intended for authorized security testing and research purposes only. Users must obtain proper authorization before testing any systems they don't own or have permission to test.

## License

This module is released under the BSD 3-Clause License.

This work contains code derived from:
- SafeBreach Labs' original PoC (BSD 3-Clause License)
- Metasploit Framework (MSF_LICENSE - BSD 3-Clause License)

Full license texts can be found in the `LICENSES` file.
