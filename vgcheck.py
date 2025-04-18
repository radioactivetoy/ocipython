#!/usr/bin/env python3
"""
OCI Volume Backup Compliance Checker (Refactored)

Checks all compute instances in a selected region for:
1. Volume group existence
2. All volumes included in group
3. Backup policy assigned to volume group

Generates CSV and prints compliance status.
Includes CLI fix commands for non-compliant cases.
"""

import oci
import sys
import logging
import argparse
import json
import csv
from tabulate import tabulate
from datetime import datetime
from oci.pagination import list_call_get_all_results

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PLATFORM_FILTER = "platform"

def get_regions(config):
    identity_client = oci.identity.IdentityClient(config)
    return identity_client.list_region_subscriptions(config["tenancy"]).data

def get_all_compartments(identity_client, tenancy_id, platform_filter):
    compartments = []
    names = {}

    try:
        root_name = identity_client.get_tenancy(tenancy_id).data.name
        if not platform_filter or platform_filter in root_name.lower():
            compartments.append(tenancy_id)
            names[tenancy_id] = f"Root ({root_name})"
    except Exception as e:
        logger.warning("Error retrieving root tenancy name", exc_info=e)

    try:
        all_comps = list_call_get_all_results(
            identity_client.list_compartments,
            tenancy_id,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE"
        ).data

        for comp in all_comps:
            if not platform_filter or platform_filter in comp.name.lower():
                compartments.append(comp.id)
                names[comp.id] = comp.name

        logger.info(f"Found {len(compartments)} compartments matching filter")

    except Exception as e:
        logger.error("Error listing compartments", exc_info=e)

    return compartments, names

def get_volume_group_map(blockstorage_client, compartments):
    volume_to_group = {}
    logger.info("Building volume to group mapping...")
    for comp in compartments:
        vgroups = list_call_get_all_results(blockstorage_client.list_volume_groups, compartment_id=comp).data
        for vg in vgroups:
            try:
                vg_data = blockstorage_client.get_volume_group(vg.id).data
                policy_name, policy_id = get_backup_policy_for_volume_group(blockstorage_client, vg.id)
                for vid in vg_data.volume_ids:
                    volume_to_group[vid] = (vg_data, policy_name, policy_id)
            except Exception as e:
                logger.warning("Error fetching volume group details", exc_info=e)
    logger.info(f"Mapped {len(volume_to_group)} volumes to groups")
    return volume_to_group

def get_backup_policy_for_volume_group(client, vg_id):
    try:
        assignments = client.get_volume_backup_policy_asset_assignment(vg_id).data
        for a in assignments:
            if a.policy_id:
                policy = client.get_volume_backup_policy(a.policy_id).data
                return policy.display_name, policy.id
    except Exception as e:
        logger.warning(f"Backup policy error for VG {vg_id}", exc_info=e)
    return "None", None

def generate_cli_commands(instance, volumes, group_data, policy_id):
    cmds = []
    volume_ids = [v.id for v in volumes]
    defined_tags = instance.defined_tags or {}
    freeform_tags = instance.freeform_tags or {}

    if not group_data:
        base_name = instance.display_name.replace("ins", "vg")
        name = base_name
        source_details = {
            "type": "volumeIds",
            "volumeIds": volume_ids
        }
        cmd_create = (
            f"oci bv volume-group create "
            f"--compartment-id {instance.compartment_id} "
            f"--availability-domain '{instance.availability_domain}' "
            f"--display-name '{name}' "
            f"--source-details '{json.dumps(source_details)}' "
            f"--defined-tags '{json.dumps(defined_tags)}' "
            f"--freeform-tags '{json.dumps(freeform_tags)}' "
            f"--policy-id <your-backup-policy-ocid-here>"
        )
        cmds.append(cmd_create)
    else:
        update_required = False
        if not policy_id:
            cmds.append(
                f"oci bv volume-group update --volume-group-id {group_data.id} --policy-id <your-backup-policy-ocid-here>"
            )
            update_required = True

        existing_ids = set(group_data.volume_ids)
        if set(volume_ids) != existing_ids:
            cmd_update = (
                f"oci bv volume-group update --volume-group-id {group_data.id} "
                f"--volume-ids '{json.dumps(volume_ids)}' "
                f"--defined-tags '{json.dumps(defined_tags)}' "
                f"--freeform-tags '{json.dumps(freeform_tags)}'"
            )
            cmds.append(cmd_update)
            update_required = True

        if not update_required:
            cmds.append(f"# Volume group {group_data.display_name} is already up to date.")

    return cmds

def check_instance(instance, compute_client, blockstorage_client, volume_to_group):
    all_volumes = []
    try:
        bvas = compute_client.list_boot_volume_attachments(
            availability_domain=instance.availability_domain,
            compartment_id=instance.compartment_id,
            instance_id=instance.id
        ).data
        for bva in bvas:
            all_volumes.append(blockstorage_client.get_boot_volume(bva.boot_volume_id).data)
    except Exception as e:
        logger.warning("Boot volume fetch error", exc_info=e)

    try:
        vas = compute_client.list_volume_attachments(
            compartment_id=instance.compartment_id,
            instance_id=instance.id
        ).data
        for va in vas:
            all_volumes.append(blockstorage_client.get_volume(va.volume_id).data)
    except Exception as e:
        logger.warning("Block volume fetch error", exc_info=e)

    volume_ids = [v.id for v in all_volumes]
    group_data, policy_name, policy_id, matched_ids = None, "None", None, []
    for vid in volume_ids:
        if vid in volume_to_group:
            group_data, policy_name, policy_id = volume_to_group[vid]
            matched_ids = group_data.volume_ids
            break

    if not all_volumes:
        status = "N/A (No volumes)"
    elif not group_data:
        status = "Non-compliant: No volume group"
    elif set(volume_ids) != set(matched_ids):
        status = f"Non-compliant: {len(set(volume_ids) - set(matched_ids))} volumes missing from group"
    elif policy_name == "None":
        status = "Non-compliant: No backup policy"
    else:
        status = "Compliant"

    cli_cmds = generate_cli_commands(instance, all_volumes, group_data, policy_id) if status != "Compliant" else []

    return {
        "instance_name": instance.display_name,
        "compartment": instance.compartment_id,
        "volume_group": group_data.display_name if group_data else "None",
        "backup_policy": policy_name,
        "compliance_status": status,
        "total_volumes": len(volume_ids),
        "volumes_in_group": len(set(volume_ids) & set(matched_ids)) if matched_ids else 0,
        "cli_commands": cli_cmds
    }

def main():
    parser = argparse.ArgumentParser(description="Check OCI volume group and backup policy compliance")
    parser.add_argument("--region", help="OCI region")
    parser.add_argument("--platform-filter", help="Substring filter for platform compartments", default="platform")
    parser.add_argument("--compartment-id", help="Restrict to a specific compartment")
    parser.add_argument("--show-fix-commands", action="store_true", help="Display CLI commands to fix non-compliance")
    parser.add_argument("--tag-key", help="Optional instance tag key to filter")
    parser.add_argument("--tag-namespace", help="Optional tag namespace (for defined tags)")
    parser.add_argument("--tag-value", help="Optional instance tag value to match")
    args = parser.parse_args()

    try:
        config = oci.config.from_file()
        identity = oci.identity.IdentityClient(config)
        region = args.region or get_regions(config)[0].region_name
        config["region"] = region
        logger.info(f"Using region: {region}")

        compute = oci.core.ComputeClient(config)
        block = oci.core.BlockstorageClient(config)

        if args.compartment_id:
            compartments = [args.compartment_id]
            names = {args.compartment_id: "Custom Compartment"}
        else:
            compartments, names = get_all_compartments(identity, config["tenancy"], args.platform_filter.lower())

        volume_to_group = get_volume_group_map(block, compartments)
        all_results = []

        for comp_id in compartments:
            logger.info(f"Checking compartment: {names.get(comp_id, comp_id)}")
            instances = list_call_get_all_results(compute.list_instances, compartment_id=comp_id).data
            for inst_summary in instances:
                if inst_summary.lifecycle_state != "TERMINATED":
                    try:
                        inst = compute.get_instance(inst_summary.id).data

                        # Tag-based filtering
                        defined_tags = inst.defined_tags or {}
                        freeform_tags = inst.freeform_tags or {}

                        match = True
                        if args.tag_key and args.tag_value:
                            match = False
                            if args.tag_namespace:
                                ns = defined_tags.get(args.tag_namespace, {})
                                match = ns.get(args.tag_key) == args.tag_value
                            else:
                                match = freeform_tags.get(args.tag_key) == args.tag_value

                        if not match:
                            continue

                        result = check_instance(inst, compute, block, volume_to_group)
                        result["compartment"] = names.get(comp_id, comp_id)
                        all_results.append(result)
                    except Exception as e:
                        logger.warning(f"Could not fetch full instance details for {inst_summary.id}", exc_info=e)

        headers = ["instance_name", "compartment", "volume_group", "backup_policy", "volumes", "compliance_status"]
        table = [[r["instance_name"], r["compartment"], r["volume_group"], r["backup_policy"], f"{r['volumes_in_group']}/{r['total_volumes']}", r["compliance_status"]] for r in all_results]

        print(tabulate(table, headers=headers, tablefmt="grid"))

        if args.show_fix_commands:
            for r in all_results:
                if r["cli_commands"]:
                    print(f"\nCommands to fix {r['instance_name']}:")
                    for cmd in r["cli_commands"]:
                        print(f"  {cmd}")

        compliant = sum(1 for r in all_results if r["compliance_status"] == "Compliant")
        total = len(all_results)
        logger.info(f"Compliance: {compliant}/{total} ({(compliant / total * 100) if total else 0:.1f}%)")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"oci_compliance_{region}_{ts}.csv"
        with open(fname, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(table)

        print(f"\nResults exported to {fname}")

    except Exception as e:
        logger.error("Fatal error", exc_info=e)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
