class SsrfboundError(Exception):
    """Base error."""


class LabNxDomain(SsrfboundError):
    def __init__(self, name: str):
        super().__init__(f"NXDOMAIN: {name}")
        self.name = name


class LabUnreachable(SsrfboundError):
    def __init__(self, ip: str, port: int):
        super().__init__(f"unreachable lab endpoint {ip}:{port}")
        self.ip = ip
        self.port = port
