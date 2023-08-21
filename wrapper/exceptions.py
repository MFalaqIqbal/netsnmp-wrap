class InvalidIPAddress(Exception):
    def __init__(self, address, *error):
        self.message = None
        if error == 'Private':
            self.message = f"{address}: Address Provided is not from the Private Range."
        else:
            self.message = f"Invalid IP Address"
        super().__init__(self.message)


class InvalidSNMPVersion(Exception):
    def __init__(self):
        self.message = "Unsupported SNMP version"
        super().__init__(self.message)


class InvalidSNMPv3Credentials(Exception):
    def __init__(self, creds, error):
        if error == 1:
            self.message = f"Credentials Invalid: Missing Parameters -> Given: {creds} -> Need: [Username, Authentication, Encryption]"
        else:
            self.message = "Unknown"
        super().__init__(self.message)


class InvalidSNMPv2Credentials(Exception):
    def __init__(self, creds, error):
        if error == 1:
            self.message = f"Credentials Invalid: To Many Parameters -> Given: {creds} -> Need: [Community String]"
        else:
            self.message = "Unknown"
        super().__init__(self.message)


class SNMPTimedOut(Exception):
    def __init__(self):
        self.message = f"SNMP TimedOut -> Check Credentials are valid & IP is Reachable"
        super().__init__(self.message)
