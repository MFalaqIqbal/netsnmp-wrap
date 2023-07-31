from subprocess import run, PIPE
from components import *
from components import SNMPv3, SNMPv2


class Wrapper:
    @classmethod
    def update_target(cls, address: str, snmp_creds):
        cls.address = validate_ip(address)
        cls.snmp = snmp_creds

    def __init__(self, lib_location: str, snmp_creds: SNMPv2 | SNMPv3,
                 address: str = '127.0.0.1', port: int = 161, timeout: int = 5, retries: int = 3):
        self.lib_location = lib_location
        self.address = validate_ip(address)
        self.snmp = snmp_creds
        self.port = port
        self.timeout = timeout
        self.retries = retries
        return

    @staticmethod
    def command_runner(args: list):
        get_data = run(args=args, stdout=PIPE, stderr=PIPE)
        if get_data.returncode != 0:
            valid_snmp_output(cmd_out=get_data.stdout.decode('windows-1252'))
        else:
            pass
        return get_data.stdout.decode('windows-1252')

    def execute(self, command: str, oid: str, *args: str):
        arguments = ["-t", str(self.timeout), "-r", str(self.retries), "-v", self.address[0], oid]
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
                arguments.insert(5, '2c')
                arguments.insert(6, '-c')
                arguments.insert(7, self.snmp.community)
                arguments.insert(0, f"{self.lib_location}\\{support_commands[command]}")
                if args:
                    arguments.insert(1, args[0])
        return self.command_runner(args=arguments)
