import oci

# --- Configuration ---
# By default, the SDK will load the configuration from the default location:
# ~/.oci/config and use the [DEFAULT] profile.
# You can specify a different config file or profile:
# config = oci.config.from_file(file_location="~/.oci/config", profile_name="YOUR_PROFILE")
# If you are using instance principals, resource principals, or security token authentication,
# you might initialize the signer differently. For basic config file testing, this is usually sufficient.
try:
    config = oci.config.from_file()
    # Validate the configuration (optional, but good practice)
    oci.config.validate_config(config)
except oci.exceptions.ConfigFileNotFound as e:
    print(f"ERROR: OCI configuration file not found. {e}")
    print("Please ensure you have a valid OCI config file at ~/.oci/config or specify its location.")
    exit(1)
except oci.exceptions.InvalidConfig as e:
    print(f"ERROR: Invalid OCI configuration. {e}")
    exit(1)
except Exception as e:
    print(f"ERROR: An unexpected error occurred while loading OCI config: {e}")
    exit(1)

# --- Initialize Identity Client ---
# The IdentityClient is used for managing users, groups, policies, compartments, and regions.
# Listing regions is a good basic test as it usually doesn't require special permissions.
try:
    identity_client = oci.identity.IdentityClient(config)
except Exception as e:
    print(f"ERROR: Could not initialize IdentityClient: {e}")
    exit(1)

# --- Make API Call to List Regions ---
try:
    print("Attempting to list OCI regions...")
    # The list_regions call requires no specific compartment ID.
    regions = identity_client.list_regions()

    if regions.data:
        print("\nSuccessfully retrieved OCI regions. API connection is likely working!")
        print("--------------------------------------------------------------------")
        for region in regions.data:
            print(f"- Region Name: {region.name}, Key: {region.key}")
        print("--------------------------------------------------------------------")
        print("\n✅ Basic OCI API connection test successful!")
    else:
        print("⚠️  Successfully connected to OCI, but no regions were returned. This is unusual.")
        print("Please check your OCI tenancy details.")

except oci.exceptions.ServiceError as e:
    print(f"\n❌ ERROR connecting to OCI API or during API call:")
    print(f"Service Error Code: {e.code}")
    print(f"Service Error Message: {e.message}")
    print(f"Request ID: {e.request_id}")
    print("This could be due to incorrect configuration, network issues, or lack of basic authentication success.")
    print("Ensure your API keys, tenancy OCID, user OCID, and region in the config file are correct.")
except Exception as e:
    print(f"\n❌ An unexpected error occurred: {e}")
