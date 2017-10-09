import argparse
import socket
import struct
import tap


""" This script is for gatewaying between Basilisk/SheepShaver instances in UDP tunnelling mode
    with others using Ethernet directly (e.g. TAP, sheep_net, etc.)
"""

# IMPORTANT NOTE:
# B2 UDP tunneling normally uses IP address-based fake MAC addresses,
# and drops replies headed to real MAC addresses. To use this
# router you need to modify B2 to instead broadcast those frames.


spanning_tree_eth_source = "\x01\x80\xc2\x00\x00\x01"
spanning_tree_eth_dest = "\x01\x80\xc2\x00\x00\x00"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("guid",
                        help="GUID of the TAP device to use")
    parser.add_argument("--port",
                        help="UDP port that the UDP tunnelling is using",
                        default=6066,
                        type=int)
    parser.add_argument("--verbose", "-v",
                        default=False,
                        action="store_true",
                        help="Show forwarded packet address details")
    return parser.parse_args()


def main():
    options = parse_args()

    tap_device_name = options.guid
    udp_gateway_port = options.port
    verbose = options.verbose

    last_packet_from_tunnel = None
    last_packet_to_tunnel = None

    # General approach:
    # - Packets from the udp tunnel get echoed onto the regular network
    # - Packets from the network to relevant addresses get echoed to UDP tunnel instances
    # - We may not have permission to UDP broadcast, so instead we keep track of UDP tunnel instances'
    #   IP addresses and send relevant traffic to them

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", udp_gateway_port))

    # a packet coming from the tunnel has the regular source mac on the outside frame
    # it has the mac's virtual eth mac address inside.  since those addresses remain, on the
    # gatewayed frame, those are the addresses other parties on the lan will be replying to

    broadcast_addresses = {"\xff\xff\xff\xff\xff\xff",  # eth broadcast address
                           "\x09\x00\x07\xff\xff\xff",  # appletalk broadcast address
                           }

    eth_dests_to_forward = set(broadcast_addresses)
    known_tunnel_ips = set()
    eth_dest_ip_addresses = {}

    def tunnel_send_packet(cur_packet):
        dest_eth = cur_packet[:6]
        src_eth = cur_packet[6:12]
        dest_ip = eth_dest_ip_addresses.get(dest_eth)
        if dest_ip is not None:
            # We know the IP address of the UDP tunnel instance that has the destination, so send just to it
            if verbose:
                print "NETWORK %s: %d bytes -> tunnel %s@%s" % (mac_to_hex(src_eth), len(cur_packet), mac_to_hex(eth_dest), dest_ip)
            udp_sock.sendto(cur_packet, (dest_ip, udp_gateway_port))
        else:
            # Send it to all known tunnel instances' IPs
            if verbose:
                print "NETWORK %s: %d bytes -> %s" % (mac_to_hex(src_eth), len(cur_packet), mac_to_hex(eth_dest))
            for ip in known_tunnel_ips:
                if verbose:
                    print "  -> tunnel @%s" % ip
                udp_sock.sendto(cur_packet, (ip, udp_gateway_port))

    # Keep track of other non-tunnel MAC addresses just so we can suppress repeated messages about them
    other_seen_macs = set()

    handle = tap.tap_open_adapter(tap_device_name)
    try:
        mac_bytes = tap.tap_get_mac(handle)
        if verbose:
            print "Our TAP adapter: %s" % mac_to_hex(mac_bytes)

        while True:
            # Read packet from TAP
            packet = tap.tap_read_packet(handle)
            eth_dest = packet[:6]
            eth_source = packet[6:12]

            is_tunnelled_packet = False

            type_len = packet[12:14]
            if type_len == "\x08\x00":
                layer_3 = 14  # offset of layer 3 packet
                # Ethernet II TCP/IP
                ip_version = packet[layer_3]
                if ip_version == "\x45":
                    # IPv4
                    ip_proto = packet[layer_3 + 9]
                    ip_src_bytes = packet[layer_3 + 12:layer_3 + 16]
                    ip_src = socket.inet_ntoa(ip_src_bytes)
                    if ip_proto == "\x11":
                        # UDP
                        layer_4 = layer_3 + 20
                        source_port, destination_port, packet_len = struct.unpack("!HHH", packet[layer_4:layer_4 + 6])
                        # print "UDP", source_port, destination_port, packet_len
                        expected_udp_payload_len = packet_len - 8
                        udp_payload = packet[layer_4 + 8:]
                        actual_udp_payload_len = len(udp_payload)
                        if actual_udp_payload_len != expected_udp_payload_len:
                            print "bad udp payload len %d (expected %d)" % (actual_udp_payload_len, expected_udp_payload_len)
                        if source_port == udp_gateway_port and destination_port == udp_gateway_port:
                            is_tunnelled_packet = True
                            wrapped_packet = udp_payload
                            dest = wrapped_packet[:6]
                            virtual_source = wrapped_packet[6:12]

                            is_new_tunnel_eth = virtual_source not in eth_dests_to_forward
                            is_new_tunnel_ip = ip_src not in known_tunnel_ips
                            is_updated_tunnel_ip = False

                            if virtual_source not in broadcast_addresses:
                                prev_ip = eth_dest_ip_addresses.get(virtual_source)
                                if prev_ip != ip_src:
                                    if prev_ip is not None and verbose:
                                        is_updated_tunnel_ip = True
                                    eth_dest_ip_addresses[virtual_source] = ip_src

                            if verbose or is_new_tunnel_eth or is_new_tunnel_ip or is_updated_tunnel_ip:
                                print "TUNNEL %s@%s: %d bytes -> %s" % (mac_to_hex(virtual_source),
                                                                        ip_src,
                                                                        len(wrapped_packet),
                                                                        mac_to_hex(dest))
                            if is_new_tunnel_eth:
                                print "- NEW tunnel eth"
                                eth_dests_to_forward.add(virtual_source)
                            if is_new_tunnel_ip:
                                print "- NEW tunnel IP endpoint"
                                known_tunnel_ips.add(ip_src)
                            if is_updated_tunnel_ip:
                                print "- UPDATED tunnel IP location"

                            # Repeat the UDP-wrapped packet outside the tunnel
                            packet_to_send = wrapped_packet
                            last_packet_from_tunnel = packet_to_send
                            tap.tap_write_packet(handle, packet_to_send)

            if not is_tunnelled_packet:
                if eth_source == spanning_tree_eth_source or eth_dest == spanning_tree_eth_dest:
                    pass
                    # print "no tunnel for spanning tree messages" % (mac_to_hex(spanning_tree_eth_source))
                elif eth_dest in eth_dests_to_forward:
                    if packet == last_packet_from_tunnel:
                        if verbose:
                            print "same as last packet we echoed from tunnel"
                    if packet == last_packet_to_tunnel:
                        pass
                        # print "same as last packet we sent to tunnel"
                    else:
                        tunnel_send_packet(packet)
                        last_packet_to_tunnel = packet
                else:
                    if eth_dest not in other_seen_macs:
                        if verbose:
                            print "NETWORK %s: sender unknown, ignored" % mac_to_hex(eth_dest)
                        other_seen_macs.add(eth_dest)

    finally:
        tap.tap_close(handle)


def mac_to_hex(mac_bytes):
    return ":".join("%02X" % ord(byte) for byte in mac_bytes)


if __name__ == "__main__":
    main()
