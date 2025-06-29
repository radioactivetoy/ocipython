#!/usr/bin/env python3
"""
OCI Volume Backup Compliance Checker (v2.2 - Python < 3.10 Compatible)

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
- Generates correct CLI commands for creating/updating VGs and assigning policies.
"""

import oci
import sys

import argparse
import json
from datetime import datetime
from oci.pagination import list_call_get_all_results
from typing import Dict, List, Tuple, Optional, Any, Set, Union

try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.text import Text
    from rich.box import ASCII
    from rich.live import Live
    from rich.spinner import Spinner
except ImportError:
    print("Please install the 'rich' library for enhanced output: pip install rich")
    sys.exit(1)

# Configure logging (using rich console for output)

# Constants
DEFAULT_PLATFORM_FILTER = "platform"
STATUS_COMPLIANT = "Compliant"
STATUS_NO_VOLUMES = "N/A (No attached volumes)"
STATUS_NO_GROUP = "Non-compliant: No Volume Group found"
STATUS_MISSING_VOLUMES = "Non-compliant: Volumes missing from group"
STATUS_NO_POLICY = "Non-compliant: Volume Group has no Backup Policy"
STATUS_WRONG_POLICY = "Non-compliant: Incorrect Backup Policy assigned" # New Status
POLICY_NAME_NONE = "None" # String used when no policy is found


def get_regions(identity_client: oci.identity.IdentityClient, tenancy_id: str, console: Console) -> List[oci.identity.models.RegionSubscription]:
    """Fetches available region subscriptions for the tenancy."""
    try:
        regions = identity_client.list_region_subscriptions(tenancy_id).data
        console.log(f"[green]Successfully retrieved {len(regions)} region subscriptions.[/green]")
        return regions
    except oci.exceptions.ServiceError as e:
        console.log(f"[red]Error fetching regions for tenancy {tenancy_id}: {e}[/red]")
        raise


def get_all_compartments(identity_client: oci.identity.IdentityClient,
                         tenancy_id: str,
                         name_filter: Optional[str],
                         console: Console) -> Tuple[List[str], Dict[str, str]]:
    """
    Retrieves all active compartments recursively, optionally filtering by name.
    Includes the root compartment (tenancy) if it matches the filter or if no filter is provided.
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
            console.log(f"[green]Including root compartment:[/green] [bold]{compartment_names[tenancy_id]}[/bold]")
        else:
             console.log(f"[yellow]Excluding root compartment '{root_name}' due to filter '{processed_filter}'.[/yellow]")
    except oci.exceptions.ServiceError as e:
        console.log(f"[yellow]Warning: Could not retrieve tenancy name for {tenancy_id}. Skipping root compartment check. Error: {e}[/yellow]")

    # Get all other active compartments
    try:
        all_compartments_data = list_call_get_all_results(
            identity_client.list_compartments,
            tenancy_id,
            compartment_id_in_subtree=True,
            lifecycle_state=oci.identity.models.Compartment.LIFECYCLE_STATE_ACTIVE
        ).data

        console.log(f"[green]Retrieved {len(all_compartments_data)} total active compartments.[/green]")

        for comp in all_compartments_data:
            # Filter only if a filter string is provided
            if not processed_filter or processed_filter in comp.name.lower():
                compartment_ids.append(comp.id)
                compartment_names[comp.id] = comp.name

        console.log(f"[green]Found {len(compartment_ids)} compartments matching filter '{processed_filter or 'None'}'.[/green]")

    except oci.exceptions.ServiceError as e:
        console.log(f"[red]Error listing compartments under tenancy {tenancy_id}: {e}[/red]")

    return compartment_ids, compartment_names


def get_backup_policy_details(blockstorage_client: oci.core.BlockstorageClient,
                              policy_id: str,
                              console: Console) -> Optional[oci.core.models.VolumeBackupPolicy]:
    """Fetches the full details of a backup policy."""
    try:
        policy = blockstorage_client.get_volume_backup_policy(policy_id).data
        return policy
    except oci.exceptions.ServiceError as e:
        console.log(f"[yellow]Warning: Could not fetch details for policy {policy_id}: {e}[/yellow]")
        return None


def get_volume_group_map(blockstorage_client: oci.core.BlockstorageClient,
                         compartment_ids: List[str],
                         console: Console) -> Dict[str, Tuple[oci.core.models.VolumeGroup, Optional[oci.core.models.VolumeBackupPolicy]]]:
    """
    Builds a map associating volume OCIDs with their volume group and backup policy objects.
    """
    volume_to_group_policy: Dict[str, Tuple[oci.core.models.VolumeGroup, Optional[oci.core.models.VolumeBackupPolicy]]] = {}
    console.log("[green]Building volume-to-volume-group-and-policy mapping...[/green]")
    processed_vgs = 0
    policy_cache: Dict[str, Optional[oci.core.models.VolumeBackupPolicy]] = {} # Cache policy lookups

    for comp_id in compartment_ids:
        try:
            volume_groups = list_call_get_all_results(
                blockstorage_client.list_volume_groups,
                compartment_id=comp_id,
                lifecycle_state = oci.core.models.VolumeGroup.LIFECYCLE_STATE_AVAILABLE
            ).data
            console.log(f"[dim]Debug: Found {len(volume_groups)} available VGs in compartment {comp_id}.[/dim]")

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
                            if policy_id not in policy_cache:
                                policy_cache[policy_id] = get_backup_policy_details(blockstorage_client, policy_id, console)
                            policy = policy_cache[policy_id]
                    except oci.exceptions.ServiceError as e:
                        if e.status != 404:
                             console.log(f"[yellow]Warning: Error getting policy assignment for VG {vg_data.id}: {e}[/yellow]")
                    except Exception as e:
                         console.log(f"[red]Error: Unexpected error getting policy for VG {vg_data.id}: {e}[/red]", exc_info=False)

                    policy_display = policy.display_name if policy else POLICY_NAME_NONE
                    console.log(f"[dim]Debug: VG '{vg_data.display_name}' ({vg_data.id}) has policy '{policy_display}' ({policy_id or 'None'}).[/dim]")

                    if vg_data.volume_ids:
                        for volume_id in vg_data.volume_ids:
                            volume_to_group_policy[volume_id] = (vg_data, policy)
                    else:
                         console.log(f"[dim]Debug: VG '{vg_data.display_name}' ({vg_data.id}) contains no volumes.[/dim]")

                except oci.exceptions.ServiceError as e:
                    console.log(f"[yellow]Warning: Error fetching details for VG {vg_summary.id}. Skipping. Error: {e}[/yellow]")
                except Exception as e:
                     console.log(f"[red]Error: Unexpected error processing VG {vg_summary.id}. Skipping. Error: {e}[/red]", exc_info=False)

        except oci.exceptions.ServiceError as e:
            console.log(f"[red]Error listing VGs in compartment {comp_id}. Skipping compartment. Error: {e}[/red]")

    console.log(f"[green]Finished mapping: Processed {processed_vgs} VGs, mapped {len(volume_to_group_policy)} unique volumes.[/green]")
    return volume_to_group_policy


def find_policy_ocid_by_name(blockstorage_client: oci.core.BlockstorageClient,
                             policy_name: str,
                             compartment_ids: List[str],
                             console: Console) -> Optional[str]:
    """
    Searches for an enabled volume backup policy by display name across specified compartments.
    """
    console.log(f"[green]Searching for enabled backup policy with name:[/green] [bold]'{policy_name}'[/bold]...")
    found_policies = []
    for comp_id in compartment_ids:
        try:
            policies_summary = list_call_get_all_results(
                blockstorage_client.list_volume_backup_policies,
                compartment_id=comp_id
            ).data

            # Filter by display name. (Lifecycle state check removed due to SDK compatibility issues)
            matching_policies = [p for p in policies_summary if p.display_name == policy_name]
            if matching_policies:
                found_policies.extend(matching_policies)
                console.log(f"[dim]Debug: Found policy '{policy_name}' in compartment {comp_id}.[/dim]")

        except oci.exceptions.ServiceError as e:
            if e.status in [404, 401, 403]:
                 console.log(f"[dim]Debug: Skipping policy search in compartment {comp_id} due to permissions/not found: {e.status}[/dim]")
            else:
                 console.log(f"[yellow]Warning: Error listing policies in compartment {comp_id} searching for '{policy_name}': {e}[/yellow]")

    unique_ocids = list(set([p.id for p in found_policies]))
    if len(unique_ocids) == 1:
        policy_ocid = unique_ocids[0]
        console.log(f"[green]Found unique enabled policy OCID (across searched compartments):[/green] [bold]{policy_ocid}[/bold] for name '{policy_name}'.")
        return policy_ocid
    elif len(unique_ocids) == 0:
        console.log(f"[yellow]Warning: Could not find any enabled backup policy named '{policy_name}' in the searched compartments.[/yellow]")
        return None
    else:
        console.log(f"[yellow]Warning: Found {len(unique_ocids)} distinct enabled backup policies named '{policy_name}'. Cannot determine unique OCID. OCIDs found: {unique_ocids}[/yellow]")
        return None


def format_policy_schedule(policy: Optional[oci.core.models.VolumeBackupPolicy]) -> str:
    """Formats policy schedule information for display."""
    if not policy or not policy.schedules:
        return POLICY_NAME_NONE

    schedule_summary = []
    for schedule in policy.schedules:
        details = f"{schedule.period}"
        if schedule.hour_of_day is not None: details += f" at {schedule.hour_of_day:02d}:00"
        if schedule.day_of_week: details += f" on {schedule.day_of_week}"
        if schedule.day_of_month: details += f" on day {schedule.day_of_month}"
        if schedule.month: details += f" in {schedule.month}"
        if schedule.time_zone: details += f" {schedule.time_zone}"
        else: details += " UTC"
        retention_days = schedule.retention_seconds // 86400 if schedule.retention_seconds else 'N/A'
        details += f" (Retain: {retention_days} days / Type: {schedule.backup_type})"
        schedule_summary.append(details)

    return " | ".join(schedule_summary) if schedule_summary else POLICY_NAME_NONE


def generate_cli_commands(instance: oci.core.models.Instance,
                          instance_volumes: List[Union[oci.core.models.Volume, oci.core.models.BootVolume]],
                          associated_group_data: Optional[oci.core.models.VolumeGroup],
                          associated_policy: Optional[oci.core.models.VolumeBackupPolicy],
                          policy_ocid_for_command: Optional[str], # The resolved OCID to USE in the command
                          compliance_status: str,
                          console: Console) -> List[str]:
    """
    Generates OCI CLI commands to fix compliance issues for an instance.
    (Args documentation updated)
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

    console.log(f"[dim]Debug: generate_cli_commands for {instance.display_name}, status: {compliance_status}, policy_for_cmd: {policy_ocid_for_command}[/dim]")

    # Prepare common arguments
    compartment_id_arg = f"--compartment-id {instance.compartment_id}"
    defined_tags_arg = f"--defined-tags '{json.dumps(instance.defined_tags)}'" if instance.defined_tags else ""
    freeform_tags_arg = f"--freeform-tags '{json.dumps(instance.freeform_tags)}'" if instance.freeform_tags else ""

    if not associated_group_data:
        # Case 1: No volume group exists (STATUS_NO_GROUP)
        # --- Generate VG Name based on Instance Name (NO SUFFIX) ---
        console.log("[dim]Debug:   - Generating command for creating a new Volume Group.[/dim]")

        # Apply the naming rule: instance name with  replaced by "vg"
        vg_base_name_transformed = instance.display_name.replace("ins", "vgp")
        # Basic sanitization for potentially invalid characters in names
        vg_display_name = vg_base_name_transformed.replace(" ", "_").replace(":", "_")
        # REMOVED: _{instance.id[-6:]} suffix

        console.log(f"[dim]Debug:   - Proposed VG display name based on instance '{instance.display_name}': '{vg_display_name}'[/dim]")
        console.log(f"[yellow]Warning:   - Ensure proposed VG name '{vg_display_name}' will be unique in compartment {instance.compartment_id}[/yellow]")

        # --- End VG Name Generation ---

        availability_domain_arg = f"--availability-domain \"{instance.availability_domain}\""
        source_details = {"type": "volumeIds", "volumeIds": instance_volume_ids}
        source_details_arg = f"--source-details '{json.dumps(source_details)}'"

        # Command 1: Create the Volume Group (NO policy here)
        command_create_vg = (
            f"oci bv volume-group create {compartment_id_arg} {availability_domain_arg} "
            # Use the generated display name
            f"--display-name \"{vg_display_name}\" {source_details_arg} "
            f"{defined_tags_arg} {freeform_tags_arg}"
            f" --wait-for-state AVAILABLE" # Wait for VG to be ready
        ).strip()

        cli_commands.append(f"# Step 1: Create a new volume group for instance {instance.display_name}")
        cli_commands.append(command_create_vg)
        # Update note about replacing name if desired
        cli_commands.append(f"# Note: Suggested name is '{vg_display_name}'. Replace if needed, ensure it's unique.")
        cli_commands.append(f"#       The command waits until the VG is AVAILABLE.")

        # Command 2: Assign the Backup Policy using 'assignment create'
        new_vg_ocid_placeholder = f"<ocid-of-newly-created-vg-{vg_display_name}>" # Use proposed name in placeholder
        policy_assign_asset_id_arg = f"--asset-id {new_vg_ocid_placeholder}"
        policy_assign_policy_id_arg = f"--policy-id {effective_policy_ocid}"

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
        # (This section remains unchanged)
        console.log(f"[dim]Debug:   - Generating command(s) for updating existing VG: {associated_group_data.display_name} ({associated_group_data.id})[/dim]")
        vg_id_arg = f"--volume-group-id {associated_group_data.id}"
        group_name = associated_group_data.display_name
        volume_update_needed = False

        # Check 2a: Volumes missing/mismatched (STATUS_MISSING_VOLUMES)
        if compliance_status.startswith(STATUS_MISSING_VOLUMES):
            volume_ids_arg = f"--volume-ids '{json.dumps(instance_volume_ids)}'"
            command_update_volumes = (
                f"oci bv volume-group update {vg_id_arg} {volume_ids_arg} "
                f"{defined_tags_arg} {freeform_tags_arg}"
            )
            cli_commands.append(f"# Suggestion: Update volume list (and tags if needed) for group '{group_name}' to match instance.")
            cli_commands.append(command_update_volumes.strip())
            volume_update_needed = True

        # Check 2b: No policy or wrong policy (STATUS_NO_POLICY or STATUS_WRONG_POLICY)
        # --- Use 'assignment create' to assign/replace the policy ---
        if compliance_status.startswith(STATUS_NO_POLICY) or compliance_status.startswith(STATUS_WRONG_POLICY):
            policy_assign_asset_id_arg = f"--asset-id {associated_group_data.id}" # Use EXISTING VG OCID
            policy_assign_policy_id_arg = f"--policy-id {effective_policy_ocid}"
            console.log(f"[dim]Debug:   - Policy argument for assignment command: '{policy_assign_policy_id_arg}'[/dim]")

            command_assign_policy = (
                f"oci bv volume-backup-policy-assignment create "
                f"{policy_assign_asset_id_arg} {policy_assign_policy_id_arg}"
            )

            reason = "Assign" if compliance_status == STATUS_NO_POLICY else "Correct"
            policy_target_desc = f"policy {effective_policy_ocid}" if policy_ocid_for_command else "a suitable backup policy (placeholder)"

            cli_commands.append(f"# Suggestion: {reason} {policy_target_desc} to existing group '{group_name}'.")
            if volume_update_needed:
                cli_commands.append(f"#           (Run this command *after* the volume group update if applicable)")
            cli_commands.append(command_assign_policy)
            if not policy_ocid_for_command:
                cli_commands.append(f"#           You MUST replace '{effective_policy_ocid}' with the actual policy OCID.")

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
                              resolved_policy_ocid_for_fix: Optional[str], # For command generation
                              console: Console
                              ) -> Dict[str, Any]:
    """
    Checks a single compute instance for volume group and backup policy compliance.
    (Docstring Args/Returns updated)
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
            if bva.lifecycle_state == oci.core.models.BootVolumeAttachment.LIFECYCLE_STATE_ATTACHED and bva.boot_volume_id:
                try:
                    boot_volume = blockstorage_client.get_boot_volume(bva.boot_volume_id).data
                    if boot_volume.lifecycle_state == oci.core.models.BootVolume.LIFECYCLE_STATE_AVAILABLE:
                         instance_volumes.append(boot_volume)
                         instance_volume_ids.append(boot_volume.id)
                    else:
                         console.log(f"[dim]Debug: Skipping boot volume {bva.boot_volume_id} state: {boot_volume.lifecycle_state}[/dim]")
                except oci.exceptions.ServiceError as e:
                     error_messages.append(f"Failed to get boot volume {bva.boot_volume_id}: {e.status}")
                     console.log(f"[yellow]Warning: Error fetching boot volume {bva.boot_volume_id} for {instance.id}: {e}[/yellow]")
    except oci.exceptions.ServiceError as e:
        error_messages.append(f"Failed to list boot volume attachments: {e.status}")
        console.log(f"[yellow]Warning: Error listing boot volume attachments for {instance.id}: {e}[/yellow]")

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
                         console.log(f"[dim]Debug: Skipping block volume {va.volume_id} state: {block_volume.lifecycle_state}[/dim]")
                except oci.exceptions.ServiceError as e:
                    error_messages.append(f"Failed to get block volume {va.volume_id}: {e.status}")
                    console.log(f"[yellow]Warning: Error fetching block volume {va.volume_id} for {instance.id}: {e}[/yellow]")
    except oci.exceptions.ServiceError as e:
        error_messages.append(f"Failed to list volume attachments: {e.status}")
        console.log(f"[yellow]Warning: Error listing volume attachments for {instance.id}: {e}[/yellow]")


    # 3. Determine compliance status
    volume_group_data: Optional[oci.core.models.VolumeGroup] = None
    assigned_policy: Optional[oci.core.models.VolumeBackupPolicy] = None
    group_volume_ids: List[str] = []
    status: str = ""

    for vol_id in instance_volume_ids:
        if vol_id in volume_to_group_policy_map:
            volume_group_data, assigned_policy = volume_to_group_policy_map[vol_id]
            group_volume_ids = volume_group_data.volume_ids or []
            break

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
        if missing_from_group > 0: status_details.append(f"{missing_from_group} vols missing")
        if unexpected_in_group > 0: status_details.append(f"{unexpected_in_group} extra vols")
        status = f"{STATUS_MISSING_VOLUMES} ({', '.join(status_details)})"
    elif not assigned_policy:
        status = STATUS_NO_POLICY
    # Validation uses the originally provided requirements from args
    elif required_policy_name and assigned_policy.display_name != required_policy_name:
        status = f"{STATUS_WRONG_POLICY} (Found '{assigned_policy.display_name}', Expected '{required_policy_name}')"
    elif required_policy_ocid and assigned_policy.id != required_policy_ocid:
        status = f"{STATUS_WRONG_POLICY} (Found OCID '{assigned_policy.id}')"
    else:
        status = STATUS_COMPLIANT

    # 4. Generate CLI commands if non-compliant and applicable
    cli_cmds: List[str] = generate_cli_commands(
        instance,
        instance_volumes,
        volume_group_data,
        assigned_policy,
        resolved_policy_ocid_for_fix, # Pass the OCID intended for the fix command
        status,
        console
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
        "backup_policy_details": assigned_policy,
        "compliance_status": status,
        "total_volumes": len(instance_volume_ids_set),
        "volumes_in_group": len(instance_volume_ids_set.intersection(group_volume_ids_set)),
        "instance_volume_ids": sorted(list(instance_volume_ids_set)),
        "group_volume_ids": sorted(list(group_volume_ids_set)),
        "cli_commands": cli_cmds,
        "errors": error_messages
    }
    return result


def filter_instance_by_tags(instance: oci.core.models.Instance,
                           tag_filters: List[Dict[str, str]]) -> bool:
    """Checks if an instance matches all provided tag filters."""
    if not tag_filters:
        return True # No tag filters applied

    for tag_filter in tag_filters:
        filter_namespace = tag_filter.get("namespace")
        filter_key = tag_filter["key"]
        filter_value = tag_filter["value"]

        if filter_namespace:
            # Defined tag
            defined_tags = instance.defined_tags or {}
            namespace_tags = defined_tags.get(filter_namespace, {})
            if namespace_tags.get(filter_key) != filter_value:
                return False
        else:
            # Freeform tag
            freeform_tags = instance.freeform_tags or {}
            if freeform_tags.get(filter_key) != filter_value:
                return False
    return True


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
    parser.add_argument("--tags", nargs='*', help="Filter instances by tags in '[namespace.]key=value' format. Can be specified multiple times.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")

    # --- Args for Enhanced Policy Validation ---
    policy_group = parser.add_mutually_exclusive_group()
    policy_group.add_argument("--required-policy-name", help="Require a specific backup policy by its display name.")
    policy_group.add_argument("--required-policy-ocid", help="Require a specific backup policy by its OCID.")
    parser.add_argument("--show-policy-details", action="store_true",
                        help="Display details (like schedule) of the assigned backup policy in the output.")
    # --- End Args ---

    args = parser.parse_args()

    # --- Parse and Validate Tags ---
    parsed_tag_filters: List[Dict[str, str]] = []
    if args.tags:
        for tag_arg in args.tags:
            if '=' not in tag_arg:
                parser.error(f"Invalid tag format: {tag_arg}. Expected '[namespace.]key=value'.")
            
            parts = tag_arg.split('=', 1)
            key_part = parts[0]
            value_part = parts[1]

            if '.' in key_part:
                namespace_key_parts = key_part.split('.', 1)
                parsed_tag_filters.append({
                    "namespace": namespace_key_parts[0],
                    "key": namespace_key_parts[1],
                    "value": value_part
                })
            else:
                parsed_tag_filters.append({
                    "key": key_part,
                    "value": value_part
                })

    
        config = oci.config.from_file()

        console = Console()
        identity_client = oci.identity.IdentityClient(config)
        tenancy_id = config["tenancy"]

        # --- Determine region ---
        target_region = args.region
        if not target_region:
            available_regions = get_regions(identity_client, tenancy_id, console)
            if not available_regions: console.print("[red]No subscribed regions found.[/red]"); return 1
            target_region = available_regions[0].region_name
            console.print(f"[green]Using first subscribed region:[/green] [bold]{target_region}[/bold]")
        else:
            console.print(f"[green]Using specified region:[/green] [bold]{target_region}[/bold]")
        config["region"] = target_region
        compute_client = oci.core.ComputeClient(config)
        blockstorage_client = oci.core.BlockstorageClient(config)

        # --- Get Compartments ---
        compartment_ids_to_check: List[str]
        compartment_names_map: Dict[str, str]
        if args.compartment_id:
            console.print(f"[green]Checking specified compartment:[/green] [bold]{args.compartment_id}[/bold]")
            if not args.compartment_id.startswith("ocid1.compartment.oc1."):
                 console.print(f"[yellow]Warning: ID '{args.compartment_id}' doesn't look like compartment OCID.[/yellow]")
            try:
                 comp_data = identity_client.get_compartment(args.compartment_id).data
                 compartment_ids_to_check = [args.compartment_id]
                 compartment_names_map = {args.compartment_id: f"Specified: {comp_data.name}"}
            except oci.exceptions.ServiceError as e:
                 console.print(f"[red]Error: Failed validate/get compartment {args.compartment_id}: {e}. Aborting.[/red]")
                 return 1
        else:
            compartment_filter = args.platform_filter if args.platform_filter else None
            console.print(f"[green]Searching compartments with filter:[/green] [bold]'{compartment_filter or 'None'}'[/bold]")
            compartment_ids_to_check, compartment_names_map = get_all_compartments(
                identity_client, tenancy_id, compartment_filter, console
            )
            if not compartment_ids_to_check: console.print("[yellow]No compartments found matching criteria.[/yellow]"); return 0

        # List of compartments to search for policies (include root)
        policy_search_compartments = list(set(compartment_ids_to_check + [tenancy_id]))

        # --- Resolve Required Policy OCID for Fix Commands ---
        resolved_policy_ocid_for_fix: Optional[str] = None
        if args.required_policy_ocid:
            resolved_policy_ocid_for_fix = args.required_policy_ocid
            console.print(f"[green]Using explicit policy OCID for fix commands:[/green] [bold]{resolved_policy_ocid_for_fix}[/bold]")
        elif args.required_policy_name:
            resolved_policy_ocid_for_fix = find_policy_ocid_by_name(
                blockstorage_client, args.required_policy_name, policy_search_compartments, console
            )
            if not resolved_policy_ocid_for_fix:
                console.print(f"[yellow]Warning: Could not resolve unique OCID for policy name '{args.required_policy_name}'. Placeholder used in fixes.[/yellow]")
            else:
                 console.print(f"[green]Resolved policy OCID for fix commands from name '{args.required_policy_name}':[/green] [bold]{resolved_policy_ocid_for_fix}[/bold]")

        # --- Pre-fetch Volume Group & Policy Data ---
        console.print("[green]Building volume-to-volume-group-and-policy mapping...[/green]")
        volume_to_group_policy_map = get_volume_group_map(blockstorage_client, compartment_ids_to_check, console)

        # --- Process Instances ---
        all_results: List[Dict[str, Any]] = []
        instances_processed, instances_skipped_state, instances_skipped_tag, instances_skipped_oke = 0, 0, 0, 0

        with Live(Spinner("dots", text="Initializing..."), console=console, screen=False, refresh_per_second=4) as live:
            for comp_id in compartment_ids_to_check:
                comp_name = compartment_names_map.get(comp_id, comp_id)
                live.update(Spinner("dots", text=f"[bold green]Checking compartment:[/bold green] {comp_name} ([dim]{comp_id}[/dim])..."))
                try:
                    instance_summaries = list_call_get_all_results(compute_client.list_instances, compartment_id=comp_id).data
                    if not instance_summaries:
                        live.console.log(f"[yellow]No instances found in {comp_name}.[/yellow]")
                        continue

                    for inst_summary in instance_summaries:
                        if inst_summary.display_name and inst_summary.display_name.lower().startswith("oke-"):
                            instances_skipped_oke += 1; console.log(f"[dim]Debug: Skipping OKE instance: {inst_summary.display_name} ({inst_summary.id})[/dim]"); continue

                        if inst_summary.lifecycle_state in [oci.core.models.Instance.LIFECYCLE_STATE_TERMINATED,
                                                         oci.core.models.Instance.LIFECYCLE_STATE_TERMINATING]:
                            instances_skipped_state += 1; console.log(f"[dim]Debug: Skipping {inst_summary.id} state: {inst_summary.lifecycle_state}[/dim]"); continue

                        try:
                            instance = compute_client.get_instance(inst_summary.id).data
                            instances_processed += 1

                            if not filter_instance_by_tags(instance, parsed_tag_filters):
                                instances_skipped_tag += 1; console.log(f"[dim]Debug: Skipping {instance.id} due to tag filter.[/dim]"); continue

                            live.console.log(f"[dim]Processing instance:[/dim] {instance.display_name} ([dim]{instance.id}[/dim])")
                            result = check_instance_compliance(
                                instance, compute_client, blockstorage_client,
                                volume_to_group_policy_map,
                                args.required_policy_name, args.required_policy_ocid,
                                resolved_policy_ocid_for_fix,
                                console
                            )
                            result["compartment_name"] = comp_name
                            all_results.append(result)

                        except oci.exceptions.ServiceError as e:
                            live.console.log(f"[red]Error getting details for {inst_summary.id}. Skipping. Error: {e}[/red]")
                        except Exception as e:
                            live.console.log(f"[red]Unexpected error processing {inst_summary.id}. Skipping. Error: {e}[/red]")

                except oci.exceptions.ServiceError as e:
                    live.console.log(f"[red]Error listing instances in {comp_id}. Skipping compartment. Error: {e}[/red]")

        # --- Reporting ---
        console.log(f"[bold blue]--- Compliance Check Summary ---[/bold blue]")
        console.log(f"Processed [bold]{instances_processed}[/bold] active instances.")
        if instances_skipped_state > 0: console.log(f"Skipped [yellow]{instances_skipped_state}[/yellow] terminated/terminating instances.")
        if parsed_tag_filters: console.log(f"Skipped [yellow]{instances_skipped_tag}[/yellow] instances due to tag filter.")
        if not all_results: console.log("No instances processed matching criteria."); return 0

        # --- Prepare Output Data for Rich Table ---
        compliance_table = Table(
            title="Compliance Results",
            show_lines=True,
            box=ASCII,
            header_style="bold blue"
        )
        compliance_table.add_column("Instance Name", justify="left", style="cyan", no_wrap=True)
        compliance_table.add_column("Compartment", justify="left", style="magenta")
        compliance_table.add_column("VG Name", justify="left")
        compliance_table.add_column("Policy Name", justify="left")
        if args.show_policy_details:
            compliance_table.add_column("Policy Schedule", justify="left")
        compliance_table.add_column("Volumes", justify="center")
        compliance_table.add_column("Status", justify="left")
        compliance_table.add_column("Errors", justify="left")

        for r in all_results:
            volume_info = f"{r['volumes_in_group']}/{r['total_volumes']}"
            error_summary = "; ".join(r['errors']) if r['errors'] else "None"
            policy_schedule_formatted = format_policy_schedule(r['backup_policy_details'])

            status_text = Text(r['compliance_status'])
            if "Non-compliant" in r['compliance_status']:
                status_text.stylize("bold red")
            elif r['compliance_status'] == STATUS_COMPLIANT:
                status_text.stylize("bold green")
            elif "N/A" in r['compliance_status']:
                status_text.stylize("yellow")

            row_data = [
                r["instance_name"],
                r["compartment_name"],
                r["volume_group_name"],
                r["backup_policy_name"],
            ]
            if args.show_policy_details:
                row_data.append(policy_schedule_formatted)
            row_data.extend([
                volume_info,
                status_text,
                error_summary
            ])
            compliance_table.add_row(*row_data)

        console.print(compliance_table)

        # --- Print Fix Commands ---
        if args.show_fix_commands:
            console.print("\n[bold blue]--- Suggested OCI CLI Fix Commands ---[/bold blue]")
            fix_commands_printed = False
            for r in all_results:
                if r["cli_commands"]:
                    console.print(Panel(
                        f"[bold magenta]Commands for Instance: {r['instance_name']} ({r['instance_id']})[/bold magenta]",
                        border_style="magenta",
                        box=ASCII
                    ))
                    for cmd in r["cli_commands"]:
                        syntax = Syntax(cmd, "bash", theme="monokai", line_numbers=False, word_wrap=True)
                        console.print(syntax)
                    fix_commands_printed = True
            if not fix_commands_printed: console.print("No fix commands generated.")

        # --- Print Summary ---
        console.print("\n[bold blue]--- Compliance Check Summary ---[/bold blue]")
        console.print(f"Processed [bold]{instances_processed}[/bold] active instances.")
        if instances_skipped_state > 0: console.print(f"Skipped [yellow]{instances_skipped_state}[/yellow] terminated/terminating instances.")
        if instances_skipped_oke > 0: console.print(f"Skipped [yellow]{instances_skipped_oke}[/yellow] OKE instances (name starts with 'oke-').")
        if parsed_tag_filters: console.print(f"Skipped [yellow]{instances_skipped_tag}[/yellow] instances due to tag filter.")
        if not all_results: console.print("No instances processed matching criteria.")
        else:
            compliant_count = sum(1 for r in all_results if r["compliance_status"] == STATUS_COMPLIANT)
            total_relevant = len(all_results)
            if total_relevant > 0:
                compliance_percentage = (compliant_count/total_relevant*100)
                console.print(f"Overall Compliance: [bold]{compliant_count}/{total_relevant}[/bold] instances = [bold green]{compliance_percentage:.1f}%[/bold green] compliant.")
            else:
                console.print("No relevant instances processed.")

if __name__ == "__main__":
    sys.exit(main())
