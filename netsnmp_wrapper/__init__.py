import re
from subprocess import run, PIPE
from .components import *


class Wrapper:

    def __init__(self, snmp_creds: SNMPv2 | SNMPv3, lib_location: str,
                 address: str = '127.0.0.1', port: int = 161, timeout: int = 5, retries: int = 3):
        self.lib_location = lib_location
        self.address = validate_ip(address)
        self.snmp = snmp_creds
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.parsing_regex = r"iso(.*?)(?=iso)|iso\.(.*?= OID:.*?)(?:\\r?\\n)"
        return

    def sanitize_output(self, snmp_data):
        matches = re.findall(self.parsing_regex, snmp_data, re.MULTILINE)
        count = 0
        output = []
        while count < len(matches):
            target = matches[count]
            target = target[0].rstrip("\\r\\n")          # Remove the last \\r\\n chars
            if ' = OID: ' in target:                     # Handling the OID type.
                oid = f"{target}{matches[count + 1][0]}"
                output.append(oid)
                count = count + 1
            else:
                output.append(target)
            count = count + 1
        return output

    def command_runner(self, args: list, sanitize: bool):
        get_data = run(args=args, stdout=PIPE, stderr=PIPE)
        if get_data.returncode != 0:
            valid_snmp_output(cmd_out=get_data.stdout.decode('windows-1252'))
            return 'TimeOut'
        else:
            if sanitize is True:
                return self.sanitize_output(get_data.stdout.decode('windows-1252'))
            else:
                return get_data.stdout.decode('windows-1252')

    def update_target(self, address: str):
        self.address = validate_ip(address)

    def execute(self, command: str, oid: str, sanitize: bool, *args: str):
        arguments = ["-t", str(self.timeout), "-r", str(self.retries), "-O", "n", "-v", self.address[0], oid]
        support_commands = {
            'get': 'snmpget.exe',
            'walk': 'snmpwalk.exe',
            'bulkwalk': 'snmpbulkwalk.exe',
            'getnext': 'snmpgetnext.exe',
            'table': 'snmptable.exe',
            'bulkget': 'snmpbulkget.exe'
        }
        if command not in list(support_commands.keys()):
            raise ValueError(f'Unsupported Command')
        else:
            if isinstance(self.snmp, SNMPv2):
                arguments.insert(7, '2c')
                arguments.insert(8, '-c')
                arguments.insert(9, self.snmp.community)
                arguments.insert(0, f"{self.lib_location}\\{support_commands[command]}")
                if args:
                    arguments.insert(1, args[0])
            else:
                raise ValueError(f'Unsupported SNMP Type')
        return self.command_runner(args=arguments, sanitize=sanitize)