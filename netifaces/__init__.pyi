from typing import Union

AF_APPLETALK: int
AF_ASH: int
AF_ATMPVC: int
AF_ATMSVC: int
AF_AX25: int
AF_BLUETOOTH: int
AF_BRIDGE: int
AF_DECnet: int
AF_ECONET: int
AF_FILE: int
AF_INET: int
AF_INET6: int
AF_IPX: int
AF_IRDA: int
AF_ISDN: int
AF_KEY: int
AF_LINK: int
AF_NETBEUI: int
AF_NETLINK: int
AF_NETROM: int
AF_PACKET: int
AF_PPPOX: int
AF_ROSE: int
AF_ROUTE: int
AF_SECURITY: int
AF_SNA: int
AF_UNIX: int
AF_UNSPEC: int
AF_WANPIPE: int
AF_X25: int

address_families: dict[int, str]
version: str

def gateways() -> dict[str, dict[int, Union[tuple[str, str], tuple[str, str, bool]]]]: ...
def ifaddresses(ifname: str, /) -> dict[int, list[dict[str, str]]]: ...
def interfaces() -> list[str]: ...
