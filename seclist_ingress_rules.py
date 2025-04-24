import argparse
import logging
import re
import sys
from typing import Dict, List, Any

import oci

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


def load_network_list(file_path: str) -> Dict[str, List[str]]:
    """
    Load network lists from a file.

    File format (per line):
        name:cidr1,cidr2,...

    :param file_path: Path to the network list file
    :return: Mapping of network list name to list of CIDR strings
    """
    network_lists: Dict[str, List[str]] = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                name, cidrs = line.split(':', 1)
                network_lists[name.strip()] = [c.strip() for c in cidrs.split(',')]
            except ValueError:
                logger.warning(f"Skipping invalid network list line: {line}")
    return network_lists


def load_ingress_rules(file_path: str) -> List[Dict[str, str]]:
    """
    Load ingress rules from a file.

    File format (per line):
        source:protocol:ports:description

    :param file_path: Path to the ingress rules file
    :return: List of rule dictionaries
    """
    rules: List[Dict[str, str]] = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) != 4:
                logger.warning(f"Skipping invalid ingress rule line: {line}")
                continue
            source, protocol, ports, description = [p.strip() for p in parts]
            rules.append({
                'source': source,
                'protocol': protocol.lower(),
                'ports': ports.lower(),
                'description': description
            })
    return rules


def resolve_source_cidrs(
    source: str,
    subnet_map: Dict[str, str],
    network_lists: Dict[str, List[str]]
) -> List[str]:
    """
    Resolve a source specifier to one or more CIDR blocks.

    :param source: CIDR, subnet name, or network list name
    :param subnet_map: Mapping of subnet display_name to its CIDR block
    :param network_lists: Mapping of network list names to lists of CIDRs
    :return: List of CIDR strings
    """
    cidr_pattern = r"^\d+\.\d+\.\d+\.\d+/\d{1,2}$"
    if re.match(cidr_pattern, source):
        return [source]

    matches = [cidr for name, cidr in subnet_map.items() if source.lower() in name.lower()]
    if matches:
        return matches

    if source in network_lists:
        return network_lists[source]

    logger.warning(f"Could not resolve source '{source}' to any CIDR.")
    return []


def create_port_options(
    protocol: str,
    ports: str
) -> Dict[str, Any]:
    """
    Create TCP/UDP options for destination port ranges.

    For 'any' ports, omit port options entirely so OCI displays 'All'.

    :param protocol: 'tcp', 'udp'
    :param ports: Comma-separated list of ports or 'any'
    :return: Dict of options for TcpOptions or UdpOptions, or empty
    """
    # If 'any', omit options to allow all ports
    if ports == 'any':
        return {}

    # Parse specific port list
    nums = [int(p) for p in ports.split(',') if p.isdigit()]
    if not nums:
        logger.warning(f"Invalid ports specification '{ports}', skipping options.")
        return {}

    pr = oci.core.models.PortRange(min=min(nums), max=max(nums))
    if protocol == 'tcp':
        return {'tcp_options': oci.core.models.TcpOptions(destination_port_range=pr)}
    if protocol == 'udp':
        return {'udp_options': oci.core.models.UdpOptions(destination_port_range=pr)}
    return {}


def build_ingress_rules(
    rules_data: List[Dict[str, str]],
    subnet_map: Dict[str, str],
    network_lists: Dict[str, List[str]]
) -> List[oci.core.models.IngressSecurityRule]:
    """
    Build OCI IngressSecurityRule objects.

    :param rules_data: Parsed ingress rules
    :param subnet_map: Subnet name to CIDR mapping
    :param network_lists: Network list definitions
    :return: List of IngressSecurityRule models
    """
    built_rules: List[oci.core.models.IngressSecurityRule] = []
    for rule in rules_data:
        cidrs = resolve_source_cidrs(rule['source'], subnet_map, network_lists)
        if not cidrs:
            continue

        protocol_num = '6' if rule['protocol'] == 'tcp' else '17' if rule['protocol'] == 'udp' else None
        if not protocol_num:
            logger.warning(f"Unsupported protocol '{rule['protocol']}'")
            continue

        # Validate and trim description
        desc = rule['description'] or ''
        if len(desc) > 255:
            logger.warning(f"Description too long ({len(desc)} chars), trimming to 255.")
            desc = desc[:255]
        if not desc:
            logger.warning("Empty description, skipping rule.")
            continue

        port_opts = create_port_options(rule['protocol'], rule['ports'])
        for cidr in cidrs:
            built_rules.append(
                oci.core.models.IngressSecurityRule(
                    protocol=protocol_num,
                    source=cidr,
                    source_type='CIDR_BLOCK',
                    description=desc,
                    **port_opts
                )
            )
    return built_rules


def update_security_list(
    config_profile: str,
    security_list_ocid: str,
    ingress_file: str,
    network_file: str,
    dry_run: bool = False
) -> None:
    """
    Main routine to update the security list with new ingress rules.

    :param config_profile: OCI config profile name
    :param security_list_ocid: OCID of the security list to update
    :param ingress_file: Path to ingress rules file
    :param network_file: Path to network list file
    :param dry_run: If True, only print planned changes without applying them
    """
    config = oci.config.from_file(profile_name=config_profile)
    vcn_client = oci.core.VirtualNetworkClient(config)

    sec_list = vcn_client.get_security_list(security_list_ocid).data
    vcn_id = sec_list.vcn_id
    comp_id = sec_list.compartment_id

    subnets = vcn_client.list_subnets(comp_id, vcn_id=vcn_id).data
    subnet_map = {s.display_name: s.cidr_block for s in subnets}

    network_lists = load_network_list(network_file)
    ingress_rules_data = load_ingress_rules(ingress_file)

    new_ingress = build_ingress_rules(ingress_rules_data, subnet_map, network_lists)
    if not new_ingress:
        logger.error("No valid ingress rules generated. Exiting.")
        sys.exit(1)

    if dry_run:
        logger.info(f"Dry run: would apply {len(new_ingress)} new ingress rule(s) to {security_list_ocid}:")
        for rule in new_ingress:
            logger.info(f"  {rule}")
        return

    update_details = oci.core.models.UpdateSecurityListDetails(
        ingress_security_rules=new_ingress,
        egress_security_rules=sec_list.egress_security_rules,
        display_name=sec_list.display_name
    )

    vcn_client.update_security_list(security_list_ocid, update_details)
    logger.info("Security list updated successfully.")


def parse_args() -> argparse.Namespace:
    """
    Parses command-line arguments.

    :return: Namespace with arguments
    """
    parser = argparse.ArgumentParser(
        description="Generate and apply OCI security list ingress rules from text definitions"
    )
    parser.add_argument(
        '-p', '--profile', default='DEFAULT',
        help='OCI config profile to use (default: DEFAULT)'
    )
    parser.add_argument(
        '-s', '--security-list-ocid', required=True,
        help='OCID of the security list to update'
    )
    parser.add_argument(
        '-i', '--ingress-file', required=True,
        help='Path to ingress rules definition file'
    )
    parser.add_argument(
        '-n', '--network-file', required=True,
        help='Path to network list definition file'
    )
    parser.add_argument(
        '-d', '--dry-run', action='store_true',
        help='Show planned changes without applying them'
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    try:
        update_security_list(
            config_profile=args.profile,
            security_list_ocid=args.security_list_ocid,
            ingress_file=args.ingress_file,
            network_file=args.network_file,
            dry_run=args.dry_run
        )
    except Exception as e:
        logger.exception(f"Error updating security list: {e}")
        sys.exit(1)
