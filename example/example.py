from os.path import abspath
from netsnmp_wrapper import *


def main():
    creds = SNMPv2('TEST')
    collector = Wrapper(snmp_creds=creds, lib_location=abspath('.\\netsnmp-complied'))
    collector.update_target(address='192.168.100.10')
    data = collector.execute('walk', oid='1')
    file = open("dump.txt", "w")
    file.write(data)
    file.close()
    return


if __name__ == "__main__":
    main()
