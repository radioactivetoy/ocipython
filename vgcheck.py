# --- START OF REFACTORED vgcheck_v2.py ---

#!/usr/bin/env python3
"""
OCI Volume Backup Compliance Checker (v2)

Checks compute instances in a specified OCI region for compliance regarding
volume groups and assigned backup policies.

Compliance Criteria:
1. A volume group should exist that includes the instance's volumes.
2. All attached boot and block volumes must be included in that single volume group.
3. That volume group must have a backup policy assigned.
4. (Optional) The assigned policy must match a specified name or OCID.

Features:
- Filters compartments based on a name substring (e.g., "platform").
- Can restrict checks to a specific compartment.
- Can filter instances based on defined or freeform tags.
- Generates CSV report of compliance status.
- Prints compliance status summary to the console using tabulate.
- Optionally displays OCI CLI commands to remediate non-compliant instances.
- Optionally validates against a specific required backup policy name or OCID.
- Optionally displays details (like schedule) of the assigned backup policy.
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
from typing import Dict, List, Tuple, Optional, Any, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
DEFAULT_PLATFORM_FILTER = "platform"
STATUS_COMPLIANT = "Compliant"
STATUS_NO_VOLUMES = "N/A (No attached volumes)"
STATUS_NO_GROUP = "Non-compliant: No Volume Group found"
STATUS_MISSING_VOLUMES = "Non-compliant: Volumes missing from group"
STATUS_NO_POLICY = "Non-compliant: Volume Group has no Backup Policy"
STATUS_WRONG_POLICY = "Non-compliant: Incorrect Backup Policy assigned" # New Status
POLICY_NAME_NONE = "None" # String used when no policy is found


def get_regions(identity_client: oci.identity.IdentityClient, tenancy_id: str) -> List[oci.identity.models.RegionSubscription]:
    """Fetches available region subscriptions for the tenancy."""
    try:
        regions = identity_client.list_region_subscriptions(tenancy_id).data
        logger.info(f"Successfully retrieved {len(regions)} region subscriptions.")
        return regions
    except oci.exceptions.ServiceError as e:
        logger.error(f"Error fetching regions for tenancy {tenancy_id}: {e}")
        raise


def get_all_compartments(identity_client: oci.identity.IdentityClient,
                         tenancy_id: str,
                         name_filter: Optional[str]) -> Tuple[List[str], Dict[str, str]]:
    """
    Retrieves all active compartments recursively, optionally filtering by name.
    Includes the root compartment (tenancy) if it matches the filter or if no filter is provided.

    Args:
        identity_client: The OCI IdentityClient.
        tenancy_id: The OCID of the tenancy (root compartment).
        name_filter: A lower-case string to filter compartment names. Only compartments
                     whose names contain this string will be included. If None or empty,
                     no name filtering is applied.

    Returns:
        A tuple containing:
            - A list of compartment OCIDs.
            - A dictionary mapping compartment OCIDs to their display names.
    """
    compartment_ids: List[str] = []
    compartment_names: Dict[str, str] = {}
    processed_filter = name_filter.lower() if name_filter else None

    # Add root compartment (tenancy) if it matches filter or no filter
    try:
        tenancy_data = identity_client.get_tenancy(tenancy_id).data
        root_name = tenancy_data.name or "UNKNOWN_ROOT"
        if not processed_filter or processed_filter in root_name.lower():
            compartment_ids.append(tenancy_id)
            compartment_names[tenancy_id] = f"Root ({root_name})"
            logger.info(f"Including root compartment: {compartment_names[tenancy_id]}")
        else:
             logger.info(f"Excluding root compartment '{root_name}' due to filter '{processed_filter}'.")
    except oci.exceptions.ServiceError as e:
        logger.warning(f"Could not retrieve tenancy name for {tenancy_id}. Skipping root compartment check. Error: {e}")

    # Get all other active compartments
    try:
        all_compartments_data = list_call_get_all_results(
            identity_client.list_compartments,
            tenancy_id,
            compartment_id_in_subtree=True,
            lifecycle_state=oci.identity.models.Compartment.LIFECYCLE_STATE_ACTIVE
        ).data

        logger.info(f"Retrieved {len(all_compartments_data)} total active compartments.")

        for comp in all_compartments_data:
            if not processed_filter or processed_filter in comp.name.lower():
                compartment_ids.append(comp.id)
                compartment_names[comp.id] = comp.name

        logger.info(f"Found {len(compartment_ids)} compartments matching filter '{processed_filter or 'None'}'.")

    except oci.exceptions.ServiceError as e:
        logger.error(f"Error listing compartments under tenancy {tenancy_id}: {e}")

    return compartment_ids, compartment_names


def get_backup_policy_details(blockstorage_client: oci.core.BlockstorageClient,
                              policy_id: str) -> Optional[oci.core.models.VolumeBackupPolicy]:
    """Fetches the full details of a backup policy."""
    try:
        policy = blockstorage_client.get_volume_backup_policy(policy_id).data
        return policy
    except oci.exceptions.ServiceError as e:
        logger.warning(f"Could not fetch details for policy {policy_id}: {e}")
        return None

def get_volume_group_map(blockstorage_client: oci.core.BlockstorageClient,
                         compartment_ids: List[str]) -> Dict[str, Tuple[oci.core.models.VolumeGroup, Optional[oci.core.models.VolumeBackupPolicy]]]:
    """
    Builds a map associating volume OCIDs with their volume group and backup policy objects.

    Args:
        blockstorage_client: The OCI BlockstorageClient.
        compartment_ids: List of compartment OCIDs to scan for volume groups.

    Returns:
        A dictionary where keys are volume OCIDs and values are tuples:
        (VolumeGroup object, VolumeBackupPolicy object or None).
    """
    volume_to_group_policy: Dict[str, Tuple[oci.core.models.VolumeGroup, Optional[oci.core.models.VolumeBackupPolicy]]] = {}
    logger.info("Building volume-to-volume-group-and-policy mapping...")
    processed_vgs = 0
    policy_cache: Dict[str, Optional[oci.core.models.VolumeBackupPolicy]] = {} # Cache policy lookups

    for comp_id in compartment_ids:
        try:
            volume_groups = list_call_get_all_results(
                blockstorage_client.list_volume_groups,
                compartment_id=comp_id,
                lifecycle_state = oci.core.models.VolumeGroup.LIFECYCLE_STATE_AVAILABLE
            ).data
            logger.debug(f"Found {len(volume_groups)} available volume groups in compartment {comp_id}.")

            for vg_summary in volume_groups:
                try:
                    vg_data = blockstorage_client.get_volume_group(vg_summary.id).data
                    processed_vgs += 1
                    policy: Optional[oci.core.models.VolumeBackupPolicy] = None
                    policy_id: Optional[str] = None

                    # Get policy assignment
                    try:
                        assignments = blockstorage_client.get_volume_backup_policy_asset_assignment(vg_data.id).data
                        if assignments and assignments[0].policy_id:
                            policy_id = assignments[0].policy_id
                            # Fetch policy details (use cache)
                            if policy_id not in policy_cache:
                                policy_cache[policy_id] = get_backup_policy_details(blockstorage_client, policy_id)
                            policy = policy_cache[policy_id]
                    except oci.exceptions.ServiceError as e:
                        if e.status != 404: # Ignore 404 (no assignment found)
                             logger.warning(f"Error getting policy assignment for VG {vg_data.id}: {e}")

                    policy_display = policy.display_name if policy else POLICY_NAME_NONE
                    logger.debug(f"VG '{vg_data.display_name}' ({vg_data.id}) has policy '{policy_display}' ({policy_id or 'None'}).")

                    if vg_data.volume_ids:
                        for volume_id in vg_data.volume_ids:
                            volume_to_group_policy[volume_id] = (vg_data, policy)
                    else:
                         logger.debug(f"Volume Group '{vg_data.display_name}' ({vg_data.id}) contains no volumes.")

                except oci.exceptions.ServiceError as e:
                    logger.warning(f"Error fetching details for Volume Group {vg_summary.id} in compartment {comp_id}. Skipping. Error: {e}")
                except Exception as e:
                     logger.warning(f"Unexpected error processing Volume Group {vg_summary.id} in compartment {comp_id}. Skipping. Error: {e}", exc_info=False)

        except oci.exceptions.ServiceError as e:
            logger.error(f"Error listing volume groups in compartment {comp_id}. Skipping compartment. Error: {e}")

    logger.info(f"Finished mapping: Processed {processed_vgs} volume groups, mapped {len(volume_to_group_policy)} unique volumes.")
    return volume_to_group_policy


def format_policy_schedule(policy: Optional[oci.core.models.VolumeBackupPolicy]) -> str:
    """Formats policy schedule information for display."""
    if not policy or not policy.schedules:
        return POLICY_NAME_NONE # Or maybe just ""? Let's stick with None for consistency

    schedule_summary = []
    for schedule in policy.schedules:
        # Example: DAILY at 02:00 UTC (Keep Every Week)
        details = f"{schedule.period}"
        if schedule.hour_of_day is not None:
            details += f" at {schedule.hour_of_day:02d}:00"
        if schedule.day_of_week:
            details += f" on {schedule.day_of_week}"
        if schedule.day_of_month:
             details += f" on day {schedule.day_of_month}"
        if schedule.month:
            details += f" in {schedule.month}"
        if schedule.time_zone:
            details += f" {schedule.time_zone}"
        details += f" (Retain: {schedule.retention_seconds // 86400} days / Type: {schedule.backup_type})" # Convert seconds to days
        schedule_summary.append(details)

    return " | ".join(schedule_summary) if schedule_summary else POLICY_NAME_NONE


def generate_cli_commands(instance: oci.core.models.Instance,
                          instance_volumes: List[oci.core.models.Volume | oci.core.models.BootVolume],
                          associated_group_data: Optional[oci.core.models.VolumeGroup],
                          associated_policy: Optional[oci.core.models.VolumeBackupPolicy],
                          required_policy_ocid: Optional[str],
                          compliance_status: str) -> List[str]:
    """
    Generates OCI CLI commands to fix compliance issues for an instance.

    Args:
        instance: The compute instance object.
        instance_volumes: List of all Volume and BootVolume objects attached to the instance.
        associated_group_data: The VolumeGroup object associated with the instance's volumes, if found.
        associated_policy: The VolumeBackupPolicy object associated with the group, if found.
        required_policy_ocid: The OCID of the specific backup policy required (if any).
        compliance_status: The determined compliance status string.

    Returns:
        A list of OCI CLI command strings. Returns an empty list if compliant or no fix needed.
    """
    cli_commands: List[str] = []
    instance_volume_ids: List[str] = [v.id for v in instance_volumes if v]
    if not instance_volume_ids and compliance_status != STATUS_NO_VOLUMES:
        return ["# Cannot generate commands: Failed to retrieve instance volume IDs."]
    if compliance_status == STATUS_COMPLIANT or compliance_status == STATUS_NO_VOLUMES:
        return [] # No commands needed for compliant or N/A states

    # Determine the policy OCID to use in commands (required one if specified, else placeholder)
    policy_ocid_for_command = required_policy_ocid if required_policy_ocid else "<your-backup-policy-ocid-here>"
    policy_comment = f"using required policy {required_policy_ocid}" if required_policy_ocid else "using a suitable policy"

    # Prepare common arguments
    compartment_id_arg = f"--compartment-id {instance.compartment_id}"
    defined_tags_arg = f"--defined-tags '{json.dumps(instance.defined_tags)}'" if instance.defined_tags else ""
    freeform_tags_arg = f"--freeform-tags '{json.dumps(instance.freeform_tags)}'" if instance.freeform_tags else ""


    if not associated_group_data:
        # Case 1: No volume group exists (STATUS_NO_GROUP)
        vg_base_name = instance.display_name.replace(" ", "_").replace(":", "_")
        vg_display_name = f"vg_{vg_base_name}_{instance.id[-6:]}"
        availability_domain_arg = f"--availability-domain \"{instance.availability_domain}\""
        source_details = {"type": "volumeIds", "volumeIds": instance_volume_ids}
        source_details_arg = f"--source-details '{json.dumps(source_details)}'"
        policy_arg = f"--backup-policy-id {policy_ocid_for_command}"

        command = (
            f"oci bv volume-group create {compartment_id_arg} {availability_domain_arg} "
            f"--display-name \"{vg_display_name}\" {source_details_arg} "
            f"{defined_tags_arg} {freeform_tags_arg} {policy_arg}"
        )
        cli_commands.append(f"# Suggestion: Create a new volume group for this instance's volumes, {policy_comment}.")
        cli_commands.append(command.strip())

    else:
        # Case 2: Volume group exists, but is non-compliant
        vg_id_arg = f"--volume-group-id {associated_group_data.id}"
        group_name = associated_group_data.display_name
        needs_volume_update = False

        # Check 2a: Volumes missing/mismatched (STATUS_MISSING_VOLUMES)
        if compliance_status.startswith(STATUS_MISSING_VOLUMES):
            volume_ids_arg = f"--volume-ids '{json.dumps(instance_volume_ids)}'"
            command_update_volumes = (
                f"oci bv volume-group update {vg_id_arg} {volume_ids_arg} "
                f"{defined_tags_arg} {freeform_tags_arg}" # Also update tags potentially
            )
            cli_commands.append(f"# Suggestion: Update volume list for group '{group_name}' to match instance.")
            cli_commands.append(command_update_volumes.strip())
            needs_volume_update = True

        # Check 2b: No policy or wrong policy (STATUS_NO_POLICY or STATUS_WRONG_POLICY)
        if compliance_status == STATUS_NO_POLICY or compliance_status == STATUS_WRONG_POLICY:
            policy_assign_arg = f"--backup-policy-id {policy_ocid_for_command}"
            command_update_policy = (
                f"oci bv volume-group update {vg_id_arg} {policy_assign_arg}"
            )

            reason = "assign" if compliance_status == STATUS_NO_POLICY else "correct"
            policy_target_desc = f"required policy {required_policy_ocid}" if required_policy_ocid else "a suitable backup policy"

            if not needs_volume_update: # If only policy is wrong/missing
                 cli_commands.append(f"# Suggestion: {reason.capitalize()} {policy_target_desc} to group '{group_name}'.")
                 cli_commands.append(command_update_policy)
            else: # If volumes also needed update, add note about policy
                 cli_commands.append(f"# NOTE: Group '{group_name}' also needs policy updated. {reason.capitalize()} {policy_target_desc}.")
                 cli_commands.append(f"# Either add '{policy_assign_arg}' to the volume update command above,")
                 cli_commands.append(f"# OR run separately: {command_update_policy}")

        # If no specific fix commands generated but status is non-compliant (shouldn't happen with current statuses)
        if not cli_commands and compliance_status != STATUS_COMPLIANT:
             cli_commands.append(f"# NOTE: Instance is non-compliant ({compliance_status}), but no specific command generated. Manual review needed for group '{group_name}'.")


    return cli_commands


def check_instance_compliance(instance: oci.core.models.Instance,
                              compute_client: oci.core.ComputeClient,
                              blockstorage_client: oci.core.BlockstorageClient,
                              volume_to_group_policy_map: Dict[str, Tuple[oci.core.models.VolumeGroup, Optional[oci.core.models.VolumeBackupPolicy]]],
                              required_policy_name: Optional[str],
                              required_policy_ocid: Optional[str]) -> Dict[str, Any]:
    """
    Checks a single compute instance for volume group and backup policy compliance.

    Args:
        instance: The full instance object.
        compute_client: The OCI ComputeClient.
        blockstorage_client: The OCI BlockstorageClient.
        volume_to_group_policy_map: Pre-computed map from volume OCID to (VG object, Policy object).
        required_policy_name: The display name of the required backup policy, if specified.
        required_policy_ocid: The OCID of the required backup policy, if specified.

    Returns:
        A dictionary containing compliance details for the instance.
        (Includes added fields: `policy_details`, `compliance_status` includes `STATUS_WRONG_POLICY`)
    """
    instance_volumes: List[oci.core.models.Volume | oci.core.models.BootVolume] = []
    instance_volume_ids: List[str] = []
    error_messages: List[str] = []

    # 1. Get attached volumes (Boot and Block) - Same logic as before
    try:
        boot_volume_attachments = list_call_get_all_results(...).data # Ellipsis for brevity
        # ... loop through bvas, get boot_volume, check state, append ...
        # (Error handling remains the same)
    except oci.exceptions.ServiceError as e:
        # ... error handling ...
    try:
        volume_attachments = list_call_get_all_results(...).data # Ellipsis for brevity
        # ... loop through vas, get block_volume, check state, append ...
        # (Error handling remains the same)
    except oci.exceptions.ServiceError as e:
        # ... error handling ...

    # --- Refetch logic (copied from previous version, slightly adapted for clarity) ---
    # 1. Get attached boot volumes
    try:
        boot_volume_attachments = list_call_get_all_results(
            compute_client.list_boot_volume_attachments,
            availability_domain=instance.availability_domain,
            compartment_id=instance.compartment_id,
            instance_id=instance.id
        ).data
        for bva in boot_volume_attachments:
            if bva.lifecycle_state == oci.core.models.BootVolumeAttachment.LIFECYCLE_STATE_ATTACHED and bva.boot_volume_id:
                try:
                    boot_volume = blockstorage_client.get_boot_volume(bva.boot_volume_id).data
                    if boot_volume.lifecycle_state == oci.core.models.BootVolume.LIFECYCLE_STATE_AVAILABLE:
                         instance_volumes.append(boot_volume)
                         instance_volume_ids.append(boot_volume.id)
                    else:
                         logger.debug(f"Skipping boot volume {bva.boot_volume_id} for instance {instance.display_name} due to state: {boot_volume.lifecycle_state}")
                except oci.exceptions.ServiceError as e:
                     error_messages.append(f"Failed to get boot volume {bva.boot_volume_id}: {e.status}")
                     logger.warning(f"Error fetching boot volume {bva.boot_volume_id} for instance {instance.id}: {e}")
    except oci.exceptions.ServiceError as e:
        error_messages.append(f"Failed to list boot volume attachments: {e.status}")
        logger.warning(f"Error listing boot volume attachments for instance {instance.id}: {e}")

    # 2. Get attached block volumes
    try:
        volume_attachments = list_call_get_all_results(
            compute_client.list_volume_attachments,
            compartment_id=instance.compartment_id,
            instance_id=instance.id
        ).data
        for va in volume_attachments:
            if va.lifecycle_state == oci.core.models.VolumeAttachment.LIFECYCLE_STATE_ATTACHED and va.volume_id:
                try:
                    block_volume = blockstorage_client.get_volume(va.volume_id).data
                    if block_volume.lifecycle_state == oci.core.models.Volume.LIFECYCLE_STATE_AVAILABLE:
                        instance_volumes.append(block_volume)
                        instance_volume_ids.append(block_volume.id)
                    else:
                         logger.debug(f"Skipping block volume {va.volume_id} for instance {instance.display_name} due to state: {block_volume.lifecycle_state}")
                except oci.exceptions.ServiceError as e:
                    error_messages.append(f"Failed to get block volume {va.volume_id}: {e.status}")
                    logger.warning(f"Error fetching block volume {va.volume_id} for instance {instance.id}: {e}")
    except oci.exceptions.ServiceError as e:
        error_messages.append(f"Failed to list volume attachments: {e.status}")
        logger.warning(f"Error listing volume attachments for instance {instance.id}: {e}")
    # --- End Refetch logic ---


    # 3. Determine compliance status
    volume_group_data: Optional[oci.core.models.VolumeGroup] = None
    assigned_policy: Optional[oci.core.models.VolumeBackupPolicy] = None
    group_volume_ids: List[str] = []
    status: str = ""

    # Find the group and policy associated with *any* of the instance's volumes
    for vol_id in instance_volume_ids:
        if vol_id in volume_to_group_policy_map:
            volume_group_data, assigned_policy = volume_to_group_policy_map[vol_id]
            group_volume_ids = volume_group_data.volume_ids or []
            break # Assume all instance volumes should be in the *same* group

    # Evaluate compliance
    instance_volume_ids_set = set(instance_volume_ids)
    group_volume_ids_set = set(group_volume_ids)

    if not instance_volume_ids:
        status = STATUS_NO_VOLUMES
    elif not volume_group_data:
        status = STATUS_NO_GROUP
    elif instance_volume_ids_set != group_volume_ids_set:
        # (Same logic for calculating missing/extra volumes as before)
        missing_from_group = len(instance_volume_ids_set - group_volume_ids_set)
        unexpected_in_group = len(group_volume_ids_set - instance_volume_ids_set)
        status_details = []
        if missing_from_group > 0: status_details.append(f"{missing_from_group} vols missing")
        if unexpected_in_group > 0: status_details.append(f"{unexpected_in_group} extra vols")
        status = f"{STATUS_MISSING_VOLUMES} ({', '.join(status_details)})"
    elif not assigned_policy:
        status = STATUS_NO_POLICY
    # --- NEW: Check against required policy ---
    elif required_policy_name and assigned_policy.display_name != required_policy_name:
        status = f"{STATUS_WRONG_POLICY} (Found '{assigned_policy.display_name}', Expected '{required_policy_name}')"
    elif required_policy_ocid and assigned_policy.id != required_policy_ocid:
         # Avoid logging full OCID in status for brevity unless debugging
        status = f"{STATUS_WRONG_POLICY} (OCID mismatch)"
        logger.debug(f"Policy OCID mismatch for instance {instance.id}: Found {assigned_policy.id}, Expected {required_policy_ocid}")
    # --- End NEW ---
    else:
        status = STATUS_COMPLIANT # All checks passed

    # 4. Generate CLI commands if non-compliant
    cli_cmds: List[str] = generate_cli_commands(
        instance,
        instance_volumes,
        volume_group_data,
        assigned_policy,
        required_policy_ocid, # Pass required OCID for command generation
        status # Pass status to guide command logic
    )

    # 5. Compile results
    result = {
        "instance_name": instance.display_name,
        "instance_id": instance.id,
        "compartment_id": instance.compartment_id,
        "availability_domain": instance.availability_domain,
        "volume_group_name": volume_group_data.display_name if volume_group_data else POLICY_NAME_NONE,
        "volume_group_id": volume_group_data.id if volume_group_data else None,
        "backup_policy_name": assigned_policy.display_name if assigned_policy else POLICY_NAME_NONE,
        "backup_policy_id": assigned_policy.id if assigned_policy else None,
        "backup_policy_details": assigned_policy, # Store the full policy object or None
        "compliance_status": status,
        "total_volumes": len(instance_volume_ids_set),
        "volumes_in_group": len(instance_volume_ids_set.intersection(group_volume_ids_set)),
        "instance_volume_ids": sorted(list(instance_volume_ids_set)),
        "group_volume_ids": sorted(list(group_volume_ids_set)),
        "cli_commands": cli_cmds,
        "errors": error_messages
    }
    return result

# filter_instance_by_tags remains the same as before

# --- Main Execution ---
def main():
    """Main function to parse arguments and run the compliance check."""
    parser = argparse.ArgumentParser(description="Check OCI volume group and backup policy compliance for compute instances.")
    # --- Existing Args ---
    parser.add_argument("--region", help="Specify the OCI region to check. If omitted, uses the first subscribed region found.")
    parser.add_argument("--platform-filter", default=DEFAULT_PLATFORM_FILTER,
                        help=f"Substring filter for compartment names (case-insensitive). Default: '{DEFAULT_PLATFORM_FILTER}'. Use '' to disable filtering.")
    parser.add_argument("--compartment-id", help="Restrict check to only this compartment OCID (ignores platform-filter).")
    parser.add_argument("--show-fix-commands", action="store_true",
                        help="Display OCI CLI commands to fix non-compliant instances.")
    parser.add_argument("--tag-key", help="Filter instances by this tag key.")
    parser.add_argument("--tag-namespace", help="Namespace for the defined tag key (required if filtering by defined tag).")
    parser.add_argument("--tag-value", help="Filter instances by this tag value (requires --tag-key).")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")

    # --- NEW Args for Point 1 ---
    policy_group = parser.add_mutually_exclusive_group()
    policy_group.add_argument("--required-policy-name", help="Require a specific backup policy by its display name.")
    policy_group.add_argument("--required-policy-ocid", help="Require a specific backup policy by its OCID.")
    parser.add_argument("--show-policy-details", action="store_true",
                        help="Display details (like schedule) of the assigned backup policy in the output.")
    # --- End NEW Args ---

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers: handler.setLevel(logging.DEBUG)
        logger.info("Debug logging enabled.")

    if args.tag_key and not args.tag_value: parser.error("--tag-value is required when using --tag-key.")
    if args.tag_namespace and not (args.tag_key and args.tag_value): parser.error("--tag-key and --tag-value are required when using --tag-namespace.")

    try:
        # --- Config, Client Init, Region determination --- (Same as before)
        try:
            config = oci.config.from_file(); oci.config.validate_config(config)
        except (oci.exceptions.ConfigFileNotFound, oci.exceptions.InvalidConfig) as e:
             logger.error(f"OCI Config Error: {e}"); return 1

        identity_client = oci.identity.IdentityClient(config)
        tenancy_id = config["tenancy"]
        target_region = args.region
        if not target_region:
            # ... (logic to get first region) ...
            logger.info(f"Using first subscribed region: {target_region}")
        else:
             logger.info(f"Using specified region: {target_region}")
        config["region"] = target_region
        compute_client = oci.core.ComputeClient(config)
        blockstorage_client = oci.core.BlockstorageClient(config)


        # --- Get Compartments --- (Same as before)
        compartment_ids_to_check: List[str]
        compartment_names_map: Dict[str, str]
        if args.compartment_id:
            # ... (logic for specific compartment) ...
            logger.info(f"Checking specified compartment: {args.compartment_id}")
        else:
            # ... (logic for filtered compartments) ...
            logger.info(f"Searching compartments with filter: '{args.platform_filter}'")
            compartment_ids_to_check, compartment_names_map = get_all_compartments(...)
            if not compartment_ids_to_check: logger.warning("No compartments found."); return 0

        # --- Pre-fetch Volume Group & Policy Data ---
        # Modified to use the updated get_volume_group_map
        volume_to_group_policy_map = get_volume_group_map(blockstorage_client, compartment_ids_to_check)

        # --- Process Instances --- (Loop structure same, call to check_instance_compliance updated)
        all_results: List[Dict[str, Any]] = []
        instances_processed = 0
        instances_skipped_state = 0
        instances_skipped_tag = 0

        for comp_id in compartment_ids_to_check:
            comp_name = compartment_names_map.get(comp_id, comp_id)
            logger.info(f"--- Checking compartment: {comp_name} ({comp_id}) ---")
            try:
                instance_summaries = list_call_get_all_results(...) # Ellipsis for brevity
                if not instance_summaries: logger.info("No instances found."); continue

                for inst_summary in instance_summaries:
                     # ... (skip terminated/terminating) ...

                    try:
                        instance = compute_client.get_instance(inst_summary.id).data
                        instances_processed += 1

                        # ... (tag filtering) ...

                        logger.info(f"Checking instance: {instance.display_name} ({instance.id})")
                        # *** Updated call with required policy args ***
                        result = check_instance_compliance(
                            instance, compute_client, blockstorage_client,
                            volume_to_group_policy_map,
                            args.required_policy_name, # Pass required name
                            args.required_policy_ocid   # Pass required OCID
                        )
                        result["compartment_name"] = comp_name
                        all_results.append(result)

                    except oci.exceptions.ServiceError as e:
                        logger.warning(f"Could not get details for instance {inst_summary.id}. Skipping. Error: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error processing instance {inst_summary.id}. Skipping.", exc_info=True)

            except oci.exceptions.ServiceError as e:
                 logger.error(f"Error listing instances in compartment {comp_id}. Skipping. Error: {e}")

        # --- Reporting ---
        logger.info(f"--- Compliance Check Summary ---")
        # ... (Log processed/skipped counts) ...

        if not all_results: logger.info("No instances processed."); return 0

        # Define headers for output - Conditionally add Policy Details
        headers = ["Instance Name", "Compartment", "VG Name", "Policy Name", "Volumes", "Status", "Errors"]
        if args.show_policy_details:
            headers.insert(4, "Policy Details") # Insert after Policy Name

        table_data = []
        csv_headers = ["instance_name", "instance_id", "compartment_name", "compartment_id",
                       "availability_domain", "volume_group_name", "volume_group_id",
                       "backup_policy_name", "backup_policy_id", "backup_policy_schedule", # Added policy schedule
                       "volumes_in_group", "total_volumes", "compliance_status",
                       "errors", "instance_volume_ids", "group_volume_ids", "cli_commands"]
        csv_data = []

        for r in all_results:
            volume_info = f"{r['volumes_in_group']}/{r['total_volumes']}"
            error_summary = "; ".join(r['errors']) if r['errors'] else "None"
            policy_schedule_formatted = format_policy_schedule(r['backup_policy_details']) # Format schedule

            row = [
                r["instance_name"],
                r["compartment_name"],
                r["volume_group_name"],
                r["backup_policy_name"],
                # Add policy details column if requested
                # Keep it concise for the table
                volume_info,
                r["compliance_status"],
                error_summary
            ]
            if args.show_policy_details:
                # Use the formatted, potentially multi-line schedule string here
                 # Let's try to keep it concise for the table, maybe just the first schedule type?
                brief_schedule = policy_schedule_formatted.split('|')[0].split('(')[0].strip() if policy_schedule_formatted != POLICY_NAME_NONE else POLICY_NAME_NONE
                row.insert(4, brief_schedule) # Insert formatted schedule detail

            table_data.append(row)

            # Prepare full data row for CSV
            csv_data.append([
                r["instance_name"], r["instance_id"], r["compartment_name"], r["compartment_id"],
                r["availability_domain"], r["volume_group_name"], r["volume_group_id"],
                r["backup_policy_name"], r["backup_policy_id"],
                policy_schedule_formatted, # Store full formatted schedule in CSV
                r["volumes_in_group"], r["total_volumes"], r["compliance_status"],
                error_summary,
                json.dumps(r["instance_volume_ids"]),
                json.dumps(r["group_volume_ids"]),
                "\n".join(r["cli_commands"])
            ])

        # Print table to console
        print("\n--- Compliance Results ---")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

        # Print CLI commands if requested (logic remains the same)
        if args.show_fix_commands:
            print("\n--- Suggested OCI CLI Fix Commands ---")
            # ... (loop and print commands) ...

        # Calculate and print overall compliance percentage (logic remains the same)
        compliant_count = sum(1 for r in all_results if r["compliance_status"] == STATUS_COMPLIANT)
        # ... (calculate and log percentage) ...

        # Write results to CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"oci_vg_compliance_{target_region}_{timestamp}.csv"
        try:
            with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(csv_headers)
                writer.writerows(csv_data)
            logger.info(f"Full results exported to: {csv_filename}")
        except IOError as e:
            logger.error(f"Failed to write CSV report to {csv_filename}: {e}")

    except oci.exceptions.ServiceError as e:
        logger.error(f"Service error: {e}", exc_info=True); return 1
    except Exception as e:
        logger.error("Unexpected error:", exc_info=True); return 1

    return 0

if __name__ == "__main__":
    # Make sure to replace placeholder logic (...) with actual code from previous version
    # Specifically in:
    # - main(): region determination, compartment logic, instance processing loops
    # - check_instance_compliance(): volume fetching loops
    sys.exit(main())

# --- END OF REFACTORED vgcheck_v2.py ---


