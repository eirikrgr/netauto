# Author: Eirikgr
# License: MIT
# How to use: just add to dictionary COMMANDS the command you want to parse and the function that will parse it.
# That function must receive a string (output of the command) and return a list of sets or None if nothing is found.

import re

def interface_vlan_print_detail(output: str) -> list:
    """
    This function get fields name,mtu,l2mtu and mac-address from command -> '/interface/vlan print detail without-paging' of devices mikrotik.

    Example of output :
        '
        Flags: X - disabled, R - running
        0 R ;;; COL_BTA_5C55_CN_01
            name="BLAN1100_101_5C55_01" mtu=2000 l2mtu=9578 mac-address=78:9A:18:D8:95:B7 arp=enabled arp-timeout=auto loop-protect=default
            loop-protect-status=off loop-protect-send-interval=5s loop-protect-disable-time=5m vlan-id=1100 interface=subring_01
            use-service-tag=no
        1 R ;;; COL_BTA_4K99_CN_1A
            name="BLAN1100_103_4K99_1A" mtu=2000 l2mtu=9578 mac-address=78:9A:18:D8:95:B7 arp=enabled arp-timeout=auto loop-protect=default
            loop-protect-status=off loop-protect-send-interval=5s loop-protect-disable-time=5m vlan-id=1100 interface=subring_03
            use-service-tag=no
        '
    
    Arg:
        output (str): output of command executed

    Return:
        List[Set ....] -> Correspond to every interface in output.
    """

    interface_vlan_regxp: str = r'name="([^"]+)"\s+mtu=(\d+)\s+l2mtu=(\d+)\s+mac-address=([\dA-Fa-f:]+)'
    result = re.findall(interface_vlan_regxp, output)

    if result:
        return result
    
    return None

def mikrotik(command: str, output: str) -> dict:
    """
    Parser for MikroTik devices.

    Args:
        command (str): The command that was executed.
        output (str): The raw output from the device.

    Returns:
        dict: Parsed data.
    """

    COMMANDS = {
        'interface/vlan': interface_vlan_print_detail,
    }

    # Try exact match first to preserve previous behavior when callers pass canonical keys.
    parser = COMMANDS.get(command)
    result = parser(output)

    return {command: result if result else 'not found matches w/regexp'}

