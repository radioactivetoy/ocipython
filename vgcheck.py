#!/usr/bin/env python3
"""
OCI Volume Backup Compliance Checker (v2.1 - Python < 3.10 Compatible)

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
- Looks up policy OCID if --required-policy-name is used for command generation.
- Generates correct two-step CLI commands for creating a VG and assigning policy.
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
# Ensure Union is imported for Python < 3.10 compatibility
from typing import Dict, List, Tuple, Optional, Any, Set, Union

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
            # Filter only if a filter string is provided
            if not processed_filter or processed_filter in comp.name.lower():
                compartment_ids.append(comp.id)
                compartment_names[comp.id] = comp.name
            # else:
                # logger.debug(f"Excluding compartment '{comp.name}' ({comp.id}) due to filter.")

        logger.info(f"Found {len(compartment_ids)} compartments matching filter '{processed_filter or 'None'}'.")

    except oci.exceptions.ServiceError as e:
        logger.error(f"Error listing compartments under tenancy {tenancy_id}: {e}")
        # Decide if we should continue with potentially incomplete list or raise
        # raise # Or return potentially incomplete data

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
            # Using list_call_get_all_results for pagination
            volume_groups = list_call_get_all_results(
                blockstorage_client.list_volume_groups,
                compartment_id=comp_id,
                lifecycle_state = oci.core.models.VolumeGroup.LIFECYCLE_STATE_AVAILABLE # Only check available VGs
            ).data
            logger.debug(f"Found {len(volume_groups)} available volume groups in compartment {comp_id}.")

            for vg_summary in volume_groups:
                try:
                    # Get full VG details to access volume_ids
                    vg_data = blockstorage_client.get_volume_group(vg_summary.id).data
                    processed_vgs += 1
                    policy: Optional[oci.core.models.VolumeBackupPolicy] = None
                    policy_id: Optional[str] = None

                    # Get policy assignment
                    try:
                        assignments = blockstorage_client.get_volume_backup_policy_asset_assignment(vg_data.id).data
                        # A volume group should have at most one policy assignment directly
                        if assignments and assignments[0].policy_id:
                            policy_id = assignments[0].policy_id
                            # Fetch policy details (use cache)
                            if policy_id not in policy_cache:
                                policy_cache[policy_id] = get_backup_policy_details(blockstorage_client, policy_id)
                            policy = policy_cache[policy_id]
                    except oci.exceptions.ServiceError as e:
                        if e.status == 404:
                            # 404 means no assignment exists, which is expected if no policy is set
                            logger.debug(f"No backup policy assignment found for VG {vg_data.id} (404).")
                        else:
                            # Log other service errors
                             logger.warning(f"Error getting policy assignment for VG {vg_data.id}: {e}")
                    except Exception as e: # Catch broader errors
                         logger.warning(f"Unexpected error getting backup policy for VG {vg_data.id}: {e}", exc_info=False)

                    policy_display = policy.display_name if policy else POLICY_NAME_NONE
                    logger.debug(f"VG '{vg_data.display_name}' ({vg_data.id}) has policy '{policy_display}' ({policy_id or 'None'}).")

                    if vg_data.volume_ids:
                        for volume_id in vg_data.volume_ids:
                            # If a volume is somehow in multiple groups (unlikely managed this way),
                            # this will overwrite with the last one found.
                            volume_to_group_policy[volume_id] = (vg_data, policy)
                    else:
                        logger.debug(f"Volume Group '{vg_data.display_name}' ({vg_data.id}) contains no volumes.")

                except oci.exceptions.ServiceError as e:
                    # Log specific VG error but continue processing others
                    logger.warning(f"Error fetching details for Volume Group {vg_summary.id} in compartment {comp_id}. Skipping. Error: {e}")
                except Exception as e: # Catch broader errors during processing a single VG
                     logger.warning(f"Unexpected error processing Volume Group {vg_summary.id} in compartment {comp_id}. Skipping. Error: {e}", exc_info=False) # Set exc_info=True for stack trace

        except oci.exceptions.ServiceError as e:
            logger.error(f"Error listing volume groups in compartment {comp_id}. Skipping compartment. Error: {e}")
            # Continue to the next compartment

    logger.info(f"Finished mapping: Processed {processed_vgs} volume groups, mapped {len(volume_to_group_policy)} unique volumes.")
    return volume_to_group_policy


def find_policy_ocid_by_name(blockstorage_client: oci.core.BlockstorageClient,
                             policy_name: str,
                             compartment_ids: List[str]) -> Optional[str]:
    """
    Searches for a volume backup policy by display name across specified compartments.

    Args:
        blockstorage_client: The OCI BlockstorageClient.
        policy_name: The display name of the policy to find.
        compartment_ids: List of compartment OCIDs to search within (should include tenancy root).

    Returns:
        The OCID of the policy if exactly one enabled policy is found, otherwise None.
    """
    logger.info(f"Searching for enabled backup policy with name: '{policy_name}'...")
    found_policies = []
    # Note: Backup policies can be defined at the tenancy root or in compartments.
    for comp_id in compartment_ids:
        try:
            policies = list_call_get_all_results(
                blockstorage_client.list_volume_backup_policies,
                compartment_id=comp_id,
                display_name=policy_name # Filter by display name
            ).data
            if policies:
                # Filter for ENABLED state (or AVAILABLE, depending on OCI API)
                enabled_policies = [p for p in policies if p.lifecycle_state == oci.core.models.VolumeBackupPolicy.LIFECYCLE_STATE_ENABLED]
                if enabled_policies:
                    found_policies.extend(enabled_policies)
                    logger.debug(f"Found {len(enabled_policies)} enabled policies matching name '{policy_name}' in compartment {comp_id}.")

        except oci.exceptions.ServiceError as e:
            # Ignore auth errors for compartments the user might not have access to list policies in
            if e.status == 404 or e.status == 401 or e.status == 403:
                 logger.debug(f"Skipping policy search in compartment {comp_id} due to permissions/not found: {e.status}")
            else:
                 logger.warning(f"Error listing backup policies in compartment {comp_id} while searching for '{policy_name}': {e}")

    if len(found_policies) == 1:
        policy_ocid = found_policies[0].id
        logger.info(f"Found unique enabled policy OCID: {policy_ocid} for name '{policy_name}'.")
        return policy_ocid
    elif len(found_policies) == 0:
        logger.warning(f"Could not find any enabled backup policy named '{policy_name}' in the searched compartments.")
        return None
    else:
        # Remove duplicates if policy was found in multiple compartments (e.g., tenancy and another)
        unique_ocids = list(set([p.id for p in found_policies]))
        if len(unique_ocids) == 1:
             policy_ocid = unique_ocids[0]
             logger.info(f"Found unique enabled policy OCID (across compartments): {policy_ocid} for name '{policy_name}'.")
             return policy_ocid
        else:
            logger.warning(f"Found {len(unique_ocids)} distinct enabled backup policies named '{policy_name}'. Cannot determine unique OCID. OCIDs found: {unique_ocids}")
            return None


def format_policy_schedule(policy: Optional[oci.core.models.VolumeBackupPolicy]) -> str:
    """Formats policy schedule information for display."""
    if not policy or not policy.schedules:
        return POLICY_NAME_NONE

    schedule_summary = []
    for schedule in policy.schedules:
        # Example: DAILY at 02:00 UTC (Retain: 7 days / Type: INCREMENTAL)
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
        else: # Default timezone is UTC if not specified
            details += " UTC"

        retention_days = schedule.retention_seconds // 86400 if schedule.retention_seconds else 'N/A'
        details += f" (Retain: {retention_days} days / Type: {schedule.backup_type})"
        schedule_summary.append(details)

    return " | ".join(schedule_summary) if schedule_summary else POLICY_NAME_NONE


def generate_cli_commands(instance: oci.core.models.Instance,
                          instance_volumes: List[Union[oci.core.models.Volume, oci.core.models.BootVolume]],
                          associated_group_data: Optional[oci.core.models.VolumeGroup],
                          associated_policy: Optional[oci.core.models.VolumeBackupPolicy],
                          policy_ocid_for_command: Optional[str], # The resolved OCID to USE in the command
                          compliance_status: str) -> List[str]:
    """
    Generates OCI CLI commands to fix compliance issues for an instance.

    Args:
        instance: The compute instance object.
        instance_volumes: List of all Volume and BootVolume objects attached to the instance.
        associated_group_data: The VolumeGroup object associated with the instance's volumes, if found.
        associated_policy: The VolumeBackupPolicy object associated with the group, if found.
        policy_ocid_for_command: The specific policy OCID to use in generated commands (resolved from name or explicit).
        compliance_status: The determined compliance status string.

    Returns:
        A list of OCI CLI command strings. Returns an empty list if compliant or no fix needed.
    """
    cli_commands: List[str] = []
    instance_volume_ids: List[str] = [v.id for v in instance_volumes if v]
    if not instance_volume_ids and compliance_status != STATUS_NO_VOLUMES:
        return ["# Cannot generate commands: Failed to retrieve instance volume IDs."]
    if compliance_status == STATUS_COMPLIANT or compliance_status == STATUS_NO_VOLUMES:
        return []

    # Use the passed-in OCID if available, else placeholder
    effective_policy_ocid = policy_ocid_for_command if policy_ocid_for_command else "<your-backup-policy-ocid-here>"
    policy_comment = f"using policy {effective_policy_ocid}" if policy_ocid_for_command else "using a suitable policy (placeholder)"

    logger.debug(f"generate_cli_commands for {instance.display_name}, status: {compliance_status}, policy_for_cmd: {policy_ocid_for_command}")

    # Prepare common arguments
    compartment_id_arg = f"--compartment-id {instance.compartment_id}"
    defined_tags_arg = f"--defined-tags '{json.dumps(instance.defined_tags)}'" if instance.defined_tags else ""
    freeform_tags_arg = f"--freeform-tags '{json.dumps(instance.freeform_tags)}'" if instance.freeform_tags else ""

    if not associated_group_data:
        # Case 1: No volume group exists (STATUS_NO_GROUP)
        # --- Needs TWO commands: Create VG, then Assign Policy ---
        logger.debug("  - Generating command for creating a new Volume Group.")
        vg_base_name = instance.display_name.replace(" ", "_").replace(":", "_")
        vg_display_name = f"vg_{vg_base_name}_{instance.id[-6:]}"
        availability_domain_arg = f"--availability-domain \"{instance.availability_domain}\""
        source_details = {"type": "volumeIds", "volumeIds": instance_volume_ids}
        source_details_arg = f"--source-details '{json.dumps(source_details)}'"

        # Command 1: Create the Volume Group (NO policy here)
        command_create_vg = (
            f"oci bv volume-group create {compartment_id_arg} {availability_domain_arg} "
            f"--display-name \"{vg_display_name}\" {source_details_arg} "
            f"{defined_tags_arg} {freeform_tags_arg}"
            # ADD --wait-for-state AVAILABLE to ensure it's ready for policy assignment
            f" --wait-for-state AVAILABLE"
        ).strip() # Remove potential trailing spaces

        cli_commands.append(f"# Step 1: Create a new volume group for instance {instance.display_name}")
        cli_commands.append(command_create_vg)
        cli_commands.append(f"# Note: Replace '{vg_display_name}' with desired name if needed.")
        cli_commands.append(f"#       The command waits until the VG is AVAILABLE.")

        # Command 2: Assign the Backup Policy
        # We need the NEW VG OCID for this, which isn't known yet. Use a placeholder.
        new_vg_ocid_placeholder = f"<ocid-of-newly-created-vg-{vg_display_name}>"
        policy_assign_asset_id_arg = f"--asset-id {new_vg_ocid_placeholder}"
        policy_assign_policy_id_arg = f"--policy-id {effective_policy_ocid}"

        # Using the dedicated assignment command:
        command_assign_policy = (
            f"oci bv volume-backup-policy-assignment create "
            f"{policy_assign_asset_id_arg} {policy_assign_policy_id_arg}"
        )

        cli_commands.append(f"# Step 2: Assign the backup policy ({policy_comment})")
        cli_commands.append(f"#         You MUST replace '{new_vg_ocid_placeholder}' with the actual OCID from Step 1.")
        cli_commands.append(command_assign_policy)
        if not policy_ocid_for_command:
             cli_commands.append(f"#         You MUST also replace '{effective_policy_ocid}' with the actual policy OCID.")


    else:
        # Case 2: Volume group exists, but is non-compliant
        logger.debug(f"  - Generating command(s) for updating existing VG: {associated_group_data.display_name} ({associated_group_data.id})")
        vg_id_arg = f"--volume-group-id {associated_group_data.id}"
        group_name = associated_group_data.display_name
        needs_volume_update = False
        update_command_parts = [] # Collect parts for a potential combined update

        # Check 2a: Volumes missing/mismatched (STATUS_MISSING_VOLUMES)
        if compliance_status.startswith(STATUS_MISSING_VOLUMES):
            volume_ids_arg = f"--volume-ids '{json.dumps(instance_volume_ids)}'"
            update_command_parts.append(volume_ids_arg)
            # Also add tags to the update command parts if they exist
            if defined_tags_arg: update_command_parts.append(defined_tags_arg)
            if freeform_tags_arg: update_command_parts.append(freeform_tags_arg)

            cli_commands.append(f"# Suggestion: Update volume list (and tags) for group '{group_name}' to match instance.")
            needs_volume_update = True # Mark that an update command will be generated

        # Check 2b: No policy or wrong policy (STATUS_NO_POLICY or STATUS_WRONG_POLICY)
        # Volume group update also allows setting the backup policy ID
        if compliance_status == STATUS_NO_POLICY or compliance_status == STATUS_WRONG_POLICY:
            policy_assign_arg = f"--backup-policy-id {effective_policy_ocid}"
            update_command_parts.append(policy_assign_arg) # Add policy to the update command parts
            logger.debug(f"  - Policy argument for update command: '{policy_assign_arg}'")

            reason = "assign" if compliance_status == STATUS_NO_POLICY else "correct"
            policy_target_desc = f"policy {effective_policy_ocid}" if policy_ocid_for_command else "a suitable backup policy (placeholder)"

            if not needs_volume_update: # If only policy is wrong/missing, generate a specific update command
                 command_update_policy = (
                     f"oci bv volume-group update {vg_id_arg} {policy_assign_arg}"
                 )
                 cli_commands.append(f"# Suggestion: {reason.capitalize()} {policy_target_desc} to group '{group_name}'.")
                 cli_commands.append(command_update_policy)
                 if not policy_ocid_for_command:
                     cli_commands.append(f"#         You MUST replace '{effective_policy_ocid}' with the actual policy OCID.")
            # else: The policy arg was added to update_command_parts and will be included below

        # Generate the combined update command if needed
        if needs_volume_update:
            combined_update_command = f"oci bv volume-group update {vg_id_arg} {' '.join(update_command_parts)}"
            # If policy was also added, the command is already combined
            if compliance_status == STATUS_NO_POLICY or compliance_status == STATUS_WRONG_POLICY:
                 cli_commands.append(f"# Suggestion: Update volume list/tags AND assign/correct policy for group '{group_name}'.")
                 cli_commands.append(combined_update_command.strip())
                 if not policy_ocid_for_command:
                     cli_commands.append(f"#         You MUST replace '{effective_policy_ocid}' with the actual policy OCID.")
            else: # Only volume update was needed
                 cli_commands.append(combined_update_command.strip())


        # If no specific fix commands generated but status is non-compliant
        if not cli_commands and compliance_status != STATUS_COMPLIANT:
             cli_commands.append(f"# NOTE: Instance is non-compliant ({compliance_status}), but no specific command generated. Manual review needed for group '{group_name}'.")

    return cli_commands


def check_instance_compliance(instance: oci.core.models.Instance,
                              compute_client: oci.core.ComputeClient,
                              blockstorage_client: oci.core.BlockstorageClient,
                              volume_to_group_policy_map: Dict[str, Tuple[oci.core.models.VolumeGroup, Optional[oci.core.models.VolumeBackupPolicy]]],
                              required_policy_name: Optional[str], # For validation
                              required_policy_ocid: Optional[str], # For validation
                              resolved_policy_ocid_for_fix: Optional[str] # For command generation
                              ) -> Dict[str, Any]:
    """
    Checks a single compute instance for volume group and backup policy compliance.

    Args:
        instance: The full instance object.
        compute_client: The OCI ComputeClient.
        blockstorage_client: The OCI BlockstorageClient.
        volume_to_group_policy_map: Pre-computed map from volume OCID to (VG object, Policy object).
        required_policy_name: The display name of the required backup policy for validation, if specified.
        required_policy_ocid: The OCID of the required backup policy for validation, if specified.
        resolved_policy_ocid_for_fix: The OCID to use when generating fix commands.

    Returns:
        A dictionary containing compliance details for the instance.
    """
    # Use Union for compatibility with Python < 3.10
    instance_volumes: List[Union[oci.core.models.Volume, oci.core.models.BootVolume]] = []
    instance_volume_ids: List[str] = []
    error_messages: List[str] = []

    # 1. Get attached boot volumes
    try:
        boot_volume_attachments = list_call_get_all_results(
            compute_client.list_boot_volume_attachments,
            availability_domain=instance.availability_domain,
            compartment_id=instance.compartment_id,
            instance_id=instance.id
        ).data
        for bva in boot_volume_attachments:
            # Ensure BVA is attached and Boot Volume ID exists
            if bva.lifecycle_state == oci.core.models.BootVolumeAttachment.LIFECYCLE_STATE_ATTACHED and bva.boot_volume_id:
                try:
                    boot_volume = blockstorage_client.get_boot_volume(bva.boot_volume_id).data
                    # Check if boot volume is available before adding
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
            # Ensure VA is attached and Volume ID exists
            if va.lifecycle_state == oci.core.models.VolumeAttachment.LIFECYCLE_STATE_ATTACHED and va.volume_id:
                try:
                    block_volume = blockstorage_client.get_volume(va.volume_id).data
                     # Check if block volume is available before adding
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


    # 3. Determine compliance status
    volume_group_data: Optional[oci.core.models.VolumeGroup] = None
    assigned_policy: Optional[oci.core.models.VolumeBackupPolicy] = None
    group_volume_ids: List[str] = []
    status: str = "" # Initialize status

    # Find the group and policy associated with *any* of the instance's volumes
    # Assumption: All volumes for an instance should belong to the *same* group.
    for vol_id in instance_volume_ids:
        if vol_id in volume_to_group_policy_map:
            volume_group_data, assigned_policy = volume_to_group_policy_map[vol_id]
            group_volume_ids = volume_group_data.volume_ids or [] # Ensure it's a list
            break # Found the group associated with this instance

    # Evaluate compliance based on findings
    instance_volume_ids_set = set(instance_volume_ids)
    group_volume_ids_set = set(group_volume_ids)

    if not instance_volume_ids:
        status = STATUS_NO_VOLUMES
    elif not volume_group_data:
        status = STATUS_NO_GROUP
    elif instance_volume_ids_set != group_volume_ids_set:
        missing_from_group = len(instance_volume_ids_set - group_volume_ids_set)
        unexpected_in_group = len(group_volume_ids_set - instance_volume_ids_set)
        status_details = []
        if missing_from_group > 0:
            status_details.append(f"{missing_from_group} vols missing")
        if unexpected_in_group > 0:
             status_details.append(f"{unexpected_in_group} extra vols")
        status = f"{STATUS_MISSING_VOLUMES} ({', '.join(status_details)})"
    elif not assigned_policy:
        status = STATUS_NO_POLICY
    # --- Validation uses the original requirements from args ---
    elif required_policy_name and assigned_policy.display_name != required_policy_name:
        status = f"{STATUS_WRONG_POLICY} (Found '{assigned_policy.display_name}', Expected '{required_policy_name}')"
    elif required_policy_ocid and assigned_policy.id != required_policy_ocid:
        status = f"{STATUS_WRONG_POLICY} (OCID mismatch: Found {assigned_policy.id})" # Log found OCID for clarity
    # --- End validation check ---
    else:
        status = STATUS_COMPLIANT # All checks passed


    # 4. Generate CLI commands if non-compliant and applicable
    cli_cmds: List[str] = generate_cli_commands(
        instance,
        instance_volumes,
        volume_group_data,
        assigned_policy,
        resolved_policy_ocid_for_fix, # Pass the OCID intended for the fix command
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
        "instance_volume_ids": sorted(list(instance_volume_ids_set)), # Store for potential debugging
        "group_volume_ids": sorted(list(group_volume_ids_set)),      # Store for potential debugging
        "cli_commands": cli_cmds,
        "errors": error_messages # Include any errors encountered fetching volumes
    }
    return result


def filter_instance_by_tags(instance: oci.core.models.Instance,
                           tag_namespace: Optional[str],
                           tag_key: Optional[str],
                           tag_value: Optional[str]) -> bool:
    """
    Checks if an instance matches the provided tag filters.

    Args:
        instance: The instance object.
        tag_namespace: The defined tag namespace (required if using defined tags).
        tag_key: The tag key to filter on.
        tag_value: The tag value to match.

    Returns:
        True if the instance matches the tags (or if no tags are provided), False otherwise.
    """
    if not tag_key or not tag_value:
        return True # No tag filter applied

    # Check defined tags if namespace is provided
    if tag_namespace:
        defined_tags = instance.defined_tags or {}
        namespace_tags = defined_tags.get(tag_namespace, {})
        return namespace_tags.get(tag_key) == tag_value
    # Check freeform tags if no namespace is provided
    else:
        freeform_tags = instance.freeform_tags or {}
        return freeform_tags.get(tag_key) == tag_value


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

    # --- Args for Enhanced Policy Validation ---
    policy_group = parser.add_mutually_exclusive_group()
    policy_group.add_argument("--required-policy-name", help="Require a specific backup policy by its display name.")
    policy_group.add_argument("--required-policy-ocid", help="Require a specific backup policy by its OCID.")
    parser.add_argument("--show-policy-details", action="store_true",
                        help="Display details (like schedule) of the assigned backup policy in the output.")
    # --- End Args ---

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG) # Set root logger to DEBUG
        for handler in logging.getLogger().handlers:
             handler.setLevel(logging.DEBUG)
        logger.info("Debug logging enabled.")


    if args.tag_key and not args.tag_value:
        parser.error("--tag-value is required when using --tag-key.")
    if args.tag_namespace and not (args.tag_key and args.tag_value):
         parser.error("--tag-key and --tag-value are required when using --tag-namespace.")


    try:
        # --- Configuration and Client Initialization ---
        try:
            config = oci.config.from_file()
            oci.config.validate_config(config)
        except (oci.exceptions.ConfigFileNotFound, oci.exceptions.InvalidConfig) as e:
             logger.error(f"OCI Config Error: {e}. Please ensure ~/.oci/config is valid.")
             return 1

        identity_client = oci.identity.IdentityClient(config)
        tenancy_id = config["tenancy"]

        # Determine region
        target_region = args.region
        if not target_region:
            available_regions = get_regions(identity_client, tenancy_id)
            if not available_regions:
                logger.error("No subscribed regions found for this tenancy.")
                return 1
            target_region = available_regions[0].region_name
            logger.info(f"No region specified, using first subscribed region: {target_region}")
        else:
            logger.info(f"Using specified region: {target_region}")

        # Update config for the target region before creating regional clients
        config["region"] = target_region
        compute_client = oci.core.ComputeClient(config)
        blockstorage_client = oci.core.BlockstorageClient(config)

        # --- Get Compartments ---
        compartment_ids_to_check: List[str]
        compartment_names_map: Dict[str, str]
        if args.compartment_id:
            logger.info(f"Checking specified compartment: {args.compartment_id}")
            # Basic validation if it's an OCID
            if not args.compartment_id.startswith("ocid1.compartment.oc1."):
                 logger.warning(f"Provided ID '{args.compartment_id}' doesn't look like a compartment OCID.")
            try:
                 comp_data = identity_client.get_compartment(args.compartment_id).data
                 compartment_ids_to_check = [args.compartment_id]
                 compartment_names_map = {args.compartment_id: f"Specified: {comp_data.name}"}
            except oci.exceptions.ServiceError as e:
                 logger.error(f"Failed to validate/get specified compartment {args.compartment_id}: {e}. Aborting.")
                 return 1
        else:
            compartment_filter = args.platform_filter if args.platform_filter else None # Pass None if empty string
            logger.info(f"Searching for compartments with filter: '{compartment_filter or 'None'}'")
            compartment_ids_to_check, compartment_names_map = get_all_compartments(
                identity_client, tenancy_id, compartment_filter
            )
            if not compartment_ids_to_check:
                logger.warning("No compartments found matching the criteria. Exiting.")
                return 0 # Not an error, just nothing to check

        # Create a list of compartments to search for policies (include root)
        policy_search_compartments = list(set(compartment_ids_to_check + [tenancy_id]))


        # --- Resolve Required Policy OCID for Fix Commands ---
        resolved_policy_ocid_for_fix: Optional[str] = None
        if args.required_policy_ocid:
            resolved_policy_ocid_for_fix = args.required_policy_ocid
            logger.info(f"Using explicitly provided required policy OCID for fix commands: {resolved_policy_ocid_for_fix}")
        elif args.required_policy_name:
            # Find the OCID based on the name provided
            resolved_policy_ocid_for_fix = find_policy_ocid_by_name(
                blockstorage_client,
                args.required_policy_name,
                policy_search_compartments # Search in the relevant compartments + root
            )
            if not resolved_policy_ocid_for_fix:
                logger.warning(f"Could not resolve unique OCID for policy name '{args.required_policy_name}'. Placeholder will be used in fix commands.")
            else:
                 logger.info(f"Resolved policy OCID for fix commands based on name '{args.required_policy_name}': {resolved_policy_ocid_for_fix}")
        # else: resolved_policy_ocid_for_fix remains None


        # --- Pre-fetch Volume Group & Policy Data ---
        # This is more efficient than checking per-instance
        volume_to_group_policy_map = get_volume_group_map(blockstorage_client, compartment_ids_to_check)

        # --- Process Instances ---
        all_results: List[Dict[str, Any]] = []
        instances_processed = 0
        instances_skipped_state = 0
        instances_skipped_tag = 0

        for comp_id in compartment_ids_to_check:
            comp_name = compartment_names_map.get(comp_id, comp_id) # Use name if available
            logger.info(f"--- Checking compartment: {comp_name} ({comp_id}) ---")
            try:
                # Get instance summaries first
                instance_summaries = list_call_get_all_results(
                    compute_client.list_instances,
                    compartment_id=comp_id
                ).data

                if not instance_summaries:
                    logger.info("No instances found in this compartment.")
                    continue

                for inst_summary in instance_summaries:
                     # Filter out terminated/terminating instances early
                    if inst_summary.lifecycle_state in [oci.core.models.Instance.LIFECYCLE_STATE_TERMINATED,
                                                         oci.core.models.Instance.LIFECYCLE_STATE_TERMINATING]:
                        instances_skipped_state += 1
                        logger.debug(f"Skipping instance {inst_summary.display_name} ({inst_summary.id}) due to state: {inst_summary.lifecycle_state}")
                        continue

                    try:
                        # Get full instance details needed for tags, AD etc.
                        instance = compute_client.get_instance(inst_summary.id).data
                        instances_processed += 1

                        # Apply tag filtering if specified
                        if not filter_instance_by_tags(instance, args.tag_namespace, args.tag_key, args.tag_value):
                            instances_skipped_tag += 1
                            logger.debug(f"Skipping instance {instance.display_name} ({instance.id}) due to tag filter.")
                            continue

                        logger.info(f"Checking instance: {instance.display_name} ({instance.id})")
                        # Call compliance check, passing BOTH original requirements and the RESOLVED OCID for fix generation
                        result = check_instance_compliance(
                            instance, compute_client, blockstorage_client,
                            volume_to_group_policy_map,
                            args.required_policy_name, # Original requirement for validation
                            args.required_policy_ocid,  # Original requirement for validation
                            resolved_policy_ocid_for_fix # OCID to use in generated commands
                        )
                        # Add compartment name to the result for easier reading
                        result["compartment_name"] = comp_name
                        all_results.append(result)

                    except oci.exceptions.ServiceError as e:
                         # Log error fetching full instance details but continue loop
                        logger.warning(f"Could not fetch full details for instance {inst_summary.display_name} ({inst_summary.id}). Skipping instance check. Error: {e}")
                    except Exception as e: # Catch other unexpected errors during single instance processing
                         logger.error(f"Unexpected error processing instance {inst_summary.display_name} ({inst_summary.id}). Skipping instance check.", exc_info=True) # Log stack trace

            except oci.exceptions.ServiceError as e:
                logger.error(f"Error listing instances in compartment {comp_name} ({comp_id}). Skipping compartment. Error: {e}")
                # Continue to the next compartment

        # --- Reporting ---
        logger.info(f"--- Compliance Check Summary ---")
        logger.info(f"Processed {instances_processed} active instances.")
        if instances_skipped_state > 0:
            logger.info(f"Skipped {instances_skipped_state} terminated/terminating instances.")
        if args.tag_key and args.tag_value:
            logger.info(f"Skipped {instances_skipped_tag} instances due to tag filter.")

        if not all_results:
            logger.info("No instances found or processed matching the criteria.")
            return 0

        # Define headers for output - Conditionally add Policy Schedule
        headers = ["Instance Name", "Compartment", "VG Name", "Policy Name", "Volumes", "Status", "Errors"]
        if args.show_policy_details:
            headers.insert(4, "Policy Schedule") # Insert after Policy Name

        # Prepare data rows for tabulate and CSV
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
                r["compartment_name"], # Use friendly name
                r["volume_group_name"],
                r["backup_policy_name"],
                # Add policy schedule column if requested
                volume_info,
                r["compliance_status"],
                error_summary # Show brief error summary in table
            ]
            if args.show_policy_details:
                # Use the formatted schedule string for the table
                row.insert(4, policy_schedule_formatted) # Insert formatted schedule detail

            table_data.append(row)

            # Prepare full data row for CSV
            csv_data.append([
                r["instance_name"], r["instance_id"], r["compartment_name"], r["compartment_id"],
                r["availability_domain"], r["volume_group_name"], r["volume_group_id"],
                r["backup_policy_name"], r["backup_policy_id"],
                policy_schedule_formatted, # Store full formatted schedule in CSV
                r["volumes_in_group"], r["total_volumes"], r["compliance_status"],
                error_summary, # Full error summary
                json.dumps(r["instance_volume_ids"]), # Store volume IDs as JSON list
                json.dumps(r["group_volume_ids"]), # Store group volume IDs as JSON list
                "\n".join(r["cli_commands"]) # Store commands separated by newline
            ])


        # Print table to console
        print("\n--- Compliance Results ---")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

        # Print CLI commands if requested
        if args.show_fix_commands:
            print("\n--- Suggested OCI CLI Fix Commands ---")
            fix_commands_printed = False
            for r in all_results:
                if r["cli_commands"]:
                    print(f"\n# Commands for Instance: {r['instance_name']} ({r['instance_id']})")
                    for cmd in r["cli_commands"]:
                        print(cmd)
                    fix_commands_printed = True
            if not fix_commands_printed:
                 print("No fix commands generated (all applicable instances are compliant or N/A).")


        # Calculate and print overall compliance percentage
        compliant_count = sum(1 for r in all_results if r["compliance_status"] == STATUS_COMPLIANT)
        # Exclude N/A from total for percentage calculation? Or include? Let's include all processed.
        total_relevant_instances = len(all_results)
        if total_relevant_instances > 0:
            compliance_percent = (compliant_count / total_relevant_instances) * 100
            logger.info(f"Overall Compliance: {compliant_count} / {total_relevant_instances} instances = {compliance_percent:.1f}% compliant.")
        else:
            logger.info("No relevant instances processed for compliance calculation.")

        # Write results to CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"oci_vg_compliance_{target_region}_{timestamp}.csv"
        try:
            with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(csv_headers) # Use detailed headers for CSV
                writer.writerows(csv_data)
            logger.info(f"Full results exported to: {csv_filename}")
        except IOError as e:
            logger.error(f"Failed to write CSV report to {csv_filename}: {e}")

    except oci.exceptions.ServiceError as e:
        logger.error(f"A service error occurred: {e}", exc_info=True) # Log stack trace for service errors
        return 1
    except Exception as e:
        logger.error("An unexpected error occurred during script execution.", exc_info=True) # Log stack trace
        return 1

    return 0 # Success

if __name__ == "__main__":
    sys.exit(main())
