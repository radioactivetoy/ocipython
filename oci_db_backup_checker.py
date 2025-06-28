
import oci
import argparse
import json
from datetime import datetime

# This script connects to the Oracle Cloud Infrastructure (OCI) Recovery Service
# to generate a detailed report of protected databases and their backup configurations.
# It leverages the OCI Python SDK to interact with Identity, Recovery, and Database services.
#
# Features:
# - Recursively searches compartments for protected databases.
# - Filters databases by defined and freeform tags.
# - Provides detailed information about each protected database, including:
#   - General details (ID, Lifecycle State, Health, Time Created, Compartment)
#   - Associated DB System Name and ID (if applicable)
#   - Protection Policy details (Name, ID, Backup Retention, Real-Time Data Protection)
#   - Various backup-related metrics (DB Size, Backup Space Used/Estimate, Unprotected Window, etc.)
# - Presents the output in a visually appealing and organized format using the 'rich' library.
#
# Prerequisites:
# - OCI Python SDK installed (`pip install oci`)
# - 'rich' library installed (`pip install rich`)
# - OCI configuration file (~/.oci/config) set up with appropriate credentials and region.
#
# Usage:
# python oci_db_backup_checker.py --region <your_oci_region> [--compartment-id <compartment_ocid>] [--tags "key=value" "key2=value2"]
#
# Example:
# python oci_db_backup_checker.py --region us-ashburn-1 --tags "Environment=Production"
# python oci_db_backup_checker.py --region eu-frankfurt-1 --compartment-id ocid1.compartment.oc1..aaaaaaaaxxxxxxx

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.text import Text
    from rich.box import HEAVY_HEAD, ASCII
    from rich.console import Group
except ImportError:
    print("Please install the 'rich' library for enhanced output: pip install rich")
    exit(1)


def get_all_compartments(identity_client, compartment_id):
    """
    Get all compartments recursively starting from a given compartment.
    """
    compartments = []
    try:
        list_compartments_response = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id=compartment_id,
            compartment_id_in_subtree=True
        )
        compartments = list_compartments_response.data
    except oci.exceptions.ServiceError as e:
        print(f"Error fetching compartments: {e}")
    return compartments


def get_protected_databases(recovery_client, compartment_id):
    """
    Get all protected databases in a given compartment.
    """
    try:
        list_protected_databases_response = oci.pagination.list_call_get_all_results(
            recovery_client.list_protected_databases,
            compartment_id=compartment_id
        )
        return list_protected_databases_response.data
    except oci.exceptions.ServiceError as e:
        print(f"Error fetching protected databases in compartment {compartment_id}: {e}")
        return []


def get_protection_policy(recovery_client, protection_policy_id):
    """
    Get the protection policy for a given protected database.
    """
    try:
        get_protection_policy_response = recovery_client.get_protection_policy(protection_policy_id=protection_policy_id)
        return get_protection_policy_response.data
    except oci.exceptions.ServiceError as e:
        print(f"Error fetching protection policy {protection_policy_id}: {e}")
        return None





def get_db_system_details(database_client, db_system_id):
    """
    Get DB System details for a given DB System ID.
    """
    try:
        get_db_system_response = database_client.get_db_system(db_system_id=db_system_id)
        return get_db_system_response.data
    except oci.exceptions.ServiceError as e:
        print(f"Error fetching DB System {db_system_id}: {e}")
        return None

def get_database_details(database_client, database_id):
    """
    Get Database details for a given Database ID.
    """
    try:
        get_database_response = database_client.get_database(database_id=database_id)
        return get_database_response.data
    except oci.exceptions.ServiceError as e:
        print(f"Error fetching Database {database_id}: {e}")
        return None

def format_tags(freeform_tags, defined_tags):
    """
    Format tags for display as a list of (key, value) tuples.
    """
    tags_list = []
    if freeform_tags:
        for key, value in freeform_tags.items():
            tags_list.append((key, value))
    if defined_tags:
        for namespace, tag_set in defined_tags.items():
            for key, value in tag_set.items():
                tags_list.append((f"{namespace}.{key}", value))
    return tags_list


def main():
    parser = argparse.ArgumentParser(
        description="""Generate a detailed report of OCI protected databases and their backup configurations.

This script connects to the OCI Recovery Service to retrieve information about protected databases,
including their general details, associated protection policies, and various metrics.
It can search recursively through compartments and filter databases by tags.

Usage Examples:
  python oci_db_backup_checker.py --region us-ashburn-1
  python oci_db_backup_checker.py --region eu-frankfurt-1 --compartment-id ocid1.compartment.oc1..aaaaaaaaxxxxxxx
  python oci_db_backup_checker.py --region us-phoenix-1 --tags "Environment=Production" "Project=MyProject"
  python oci_db_backup_checker.py --region ap-sydney-1 --tags "ManagedBy=DBA Team"
"""
    )
    parser.add_argument("--region", required=True, help="OCI region (e.g., us-ashburn-1)")
    parser.add_argument("--compartment-id", help="Compartment ID to start search from. Defaults to tenancy root.")
    parser.add_argument("--tags", nargs='*', help="Tag filters in 'key=value' format.")
    args = parser.parse_args()

    config = oci.config.from_file()
    if args.region:
        config["region"] = args.region

    identity_client = oci.identity.IdentityClient(config)
    recovery_client = oci.recovery.DatabaseRecoveryClient(config)
    database_client = oci.database.DatabaseClient(config)
    console = Console()

    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    root_compartment_id = args.compartment_id or config["tenancy"]

    all_compartments = [oci.identity.models.Compartment(id=root_compartment_id, name="Root")]
    all_compartments.extend(get_all_compartments(identity_client, root_compartment_id))

    for compartment in all_compartments:
        protected_databases = get_protected_databases(recovery_client, compartment.id)

        if not protected_databases:
            continue

        for protected_db in protected_databases:
            if args.tags:
                filter_tags = {t.split('=')[0]: t.split('=')[1] for t in args.tags}
                resource_tags = {}
                if protected_db.freeform_tags:
                    resource_tags.update(protected_db.freeform_tags)
                if protected_db.defined_tags:
                    for namespace, tag_set in protected_db.defined_tags.items():
                        for key, value in tag_set.items():
                            resource_tags[f"{namespace}.{key}"] = value

                match = all(resource_tags.get(key) == value for key, value in filter_tags.items())
                if not match:
                    continue

            # --- Main Info Table ---
            info_table = Table(box=None, show_header=False, pad_edge=False)
            info_table.add_column(style="cyan")
            info_table.add_column()
            info_table.add_row("DB Unique Name:", protected_db.db_unique_name)
            if protected_db.database_id:
                database = get_database_details(database_client, protected_db.database_id)
                if database and database.db_system_id:
                    db_system = get_db_system_details(database_client, database.db_system_id)
                    if db_system:
                        info_table.add_row("DB System Name:", db_system.display_name)
                        info_table.add_row("DB System ID:", db_system.id)
            info_table.add_row("Lifecycle State:", Text(protected_db.lifecycle_state, style="green" if "AVAILABLE" in protected_db.lifecycle_state else "yellow"))
            info_table.add_row("Health:", Text(protected_db.health, style="green" if protected_db.health == "PROTECTED" else "red"))
            if protected_db.health_details:
                info_table.add_row("Health Details:", protected_db.health_details)
            info_table.add_row("Time Created:", str(protected_db.time_created))
            info_table.add_row("Compartment:", compartment.name)
            info_table.add_row("ID:", protected_db.id)

            # --- Protection Policy Panel ---
            policy_content = Table(box=None, show_header=False, pad_edge=False)
            policy_content.add_column(style="cyan")
            policy_content.add_column()
            if protected_db.protection_policy_id:
                policy = get_protection_policy(recovery_client, protected_db.protection_policy_id)
                if policy:
                    policy_content.add_row("Name:", policy.display_name)
                    policy_content.add_row("ID:", policy.id)
                    policy_content.add_row("Backup Retention:", f"{policy.backup_retention_period_in_days} days")
                    policy_content.add_row("Time Created:", str(policy.time_created))
                    if protected_db.metrics:
                        is_real_time = protected_db.metrics.is_redo_logs_enabled
                        policy_content.add_row("Real-Time Protection:", Text(str(is_real_time), style="bold green" if is_real_time else "bold red"))
            else:
                policy_content.add_row("No protection policy associated.")
            policy_panel = Panel(policy_content, title="Protection Policy", border_style="blue", box=ASCII)

            # --- Metrics Panel ---
            metrics_content = Table(box=None, show_header=False, pad_edge=False)
            metrics_content.add_column(style="cyan")
            metrics_content.add_column()
            if protected_db.metrics:
                metrics_content.add_row("DB Size:", f"{protected_db.metrics.db_size_in_gbs} GB")
                metrics_content.add_row("Backup Space Used:", f"{protected_db.metrics.backup_space_used_in_gbs} GB")
                metrics_content.add_row("Backup Space Estimate:", f"{protected_db.metrics.backup_space_estimate_in_gbs} GB")
                metrics_content.add_row("Unprotected Window:", f"{protected_db.metrics.unprotected_window_in_seconds} seconds")
                metrics_content.add_row("Configured Retention:", f"{protected_db.metrics.retention_period_in_days} days")
                metrics_content.add_row("Current Retention:", f"{protected_db.metrics.current_retention_period_in_seconds} seconds")
                metrics_content.add_row("Minimum Recovery Needed:", f"{protected_db.metrics.minimum_recovery_needed_in_days} days")
            metrics_panel = Panel(metrics_content, title="Metrics", border_style="blue", box=ASCII)

            # --- Tags Panel ---
            tags_list = format_tags(protected_db.freeform_tags, protected_db.defined_tags)
            tags_table = Table(box=None, show_header=False, pad_edge=False)
            tags_table.add_column(style="cyan")
            tags_table.add_column()
            if tags_list:
                for key, value in tags_list:
                    tags_table.add_row(f"{key}:", value)
            else:
                tags_table.add_row("No tags defined.")
            tags_panel = Panel(tags_table, title="Tags", border_style="blue", box=ASCII)

            # --- Combine and Print ---
            full_report_group = Group(
                info_table,
                policy_panel,
                metrics_panel,
                tags_panel
            )

            console.print(
                Panel(
                    full_report_group,
                    title=f"[bold blue]DATABASE: {protected_db.display_name.upper()}[/bold blue]",
                    subtitle=f"[dim]Report generated on: {current_datetime}[/dim]",
                    border_style="blue",
                    expand=True,
                    box=ASCII
                )
            )
            console.print()


if __name__ == "__main__":
    main()
