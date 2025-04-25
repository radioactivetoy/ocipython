#!/usr/bin/env python3
import argparse
import oci

def parse_args():
    p = argparse.ArgumentParser(
        description="Sync OCI LB backends to current OKE nodes (OCI SDK only, auto-detect compartment)"
    )
    p.add_argument("--lb-ocid",      required=True,  help="OCID of the Load Balancer")
    p.add_argument("--cluster-ocid", required=True,  help="OCID of the OKE cluster")
    p.add_argument("--region",       required=True,  help="OCI region (e.g. eu-madrid-1)")
    p.add_argument("--profile",      default="DEFAULT", help="OCI config profile")
    p.add_argument("--dry-run",      action="store_true", help="Perform a dry run without making changes")
    return p.parse_args()

def init_clients(region, profile):
    cfg = oci.config.from_file(profile_name=profile)
    cfg["region"] = region
    lb_client   = oci.load_balancer.LoadBalancerClient(cfg)
    ce_client   = oci.container_engine.ContainerEngineClient(cfg)
    compute     = oci.core.ComputeClient(cfg)
    vcn_client  = oci.core.VirtualNetworkClient(cfg)
    return lb_client, ce_client, compute, vcn_client

def list_node_ips(ce_client, compute, vcn_client, cluster_id, compartment_id):
    pools = ce_client.list_node_pools(compartment_id, cluster_id=cluster_id).data
    ips = set()
    for pool in pools:
        nodes = ce_client.list_node_pool_nodes(compartment_id, pool.id).data
        for node in nodes:
            inst_id = node.compute_instance_id
            attachments = vcn_client.list_vnic_attachments(
                compartment_id, instance_id=inst_id
            ).data
            for attach in attachments:
                vnic = vcn_client.get_vnic(attach.vnic_id).data
                if vnic.private_ip:
                    ips.add(vnic.private_ip)
    return sorted(ips)

def sync_backends(lb_client, lb_id, node_ips, dry_run=False):
    for bs in lb_client.list_backend_sets(lb_id).data:
        name = bs.name
        port = bs.port
        print(f"\nBackend set '{name}' (port {port}):")
        current = lb_client.list_backends(lb_id, name).data
        curr = {(b.ip_address, b.port) for b in current}
        desired = {(ip, port) for ip in node_ips}

        to_add = desired - curr
        to_remove = curr - desired

        for ip, prt in sorted(to_remove):
            if dry_run:
                print(f"  - [DRY RUN] Would remove {ip}:{prt}")
            else:
                print(f"  - Removing {ip}:{prt}")
                lb_client.remove_backend(lb_id, name, ip_address=ip, port=prt)

        for ip, prt in sorted(to_add):
            if dry_run:
                print(f"  + [DRY RUN] Would add {ip}:{prt}")
            else:
                print(f"  + Adding    {ip}:{prt}")
                add = oci.load_balancer.models.AddBackendDetails(
                    ip_address=ip,
                    port=prt,
                    weight=1
                )
                lb_client.add_backend(lb_id, name, add_backend_details=add)

        if not to_add and not to_remove:
            print("  ✔ Up to date")

def main():
    args = parse_args()
    lb_client, ce_client, compute, vcn_client = init_clients(
        args.region, args.profile
    )

    # auto-detect compartment from cluster
    cluster = ce_client.get_cluster(args.cluster_ocid).data
    compartment_id = cluster.compartment_id
    print(f"Detected compartment {compartment_id} from cluster {args.cluster_ocid}")

    print("Discovering current OKE node IPs…")
    node_ips = list_node_ips(
        ce_client, compute, vcn_client,
        cluster_id=args.cluster_ocid,
        compartment_id=compartment_id
    )
    print(f"  → Found {len(node_ips)} nodes: {node_ips}")

    print("\nSynchronizing backends on Load Balancer…")
    sync_backends(lb_client, args.lb_ocid, node_ips, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
