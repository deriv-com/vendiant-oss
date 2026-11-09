#!/usr/bin/env python3
"""
CLI tools for managing the Vendiant API Layer
Interactive menu-driven interface for API key management
"""

import os
import sys
from dotenv import load_dotenv

# Add the api_layer directory to Python path for absolute imports
api_layer_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, api_layer_dir)

# Load environment variables from the api_layer directory
env_path = os.path.join(api_layer_dir, '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)

from auth.api_key_manager import APIKeyManager
from middleware.audit_logger import AuditLogger
from config.settings import get_config, get_db_connection

def prompt_for_input(prompt, required=True, input_type=str, default=None):
    """Helper function to prompt for user input with validation"""
    while True:
        if default is not None:
            user_input = input(f"{prompt} [{default}]: ").strip()
            if not user_input:
                user_input = str(default)
        else:
            user_input = input(f"{prompt}: ").strip()
        
        if not user_input and required:
            print("This field is required. Please enter a value.")
            continue
        
        if not user_input and not required:
            return None
        
        try:
            if input_type == int:
                return int(user_input)
            elif input_type == bool:
                return user_input.lower() in ['y', 'yes', 'true', '1']
            else:
                return user_input
        except ValueError:
            print(f"Invalid input. Please enter a valid {input_type.__name__}.")

def prompt_for_groups():
    """Prompt for permission groups"""
    try:
        # Import here to avoid circular imports
        import psycopg2
        from config.settings import get_config, get_db_connection
        
        config = get_config()
        
        # Fetch available groups from database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT group_name, description FROM access_groups ORDER BY group_name;")
        available_groups = cursor.fetchall()
        
        cursor.close()
        conn.close()
        valid_groups = [group[0] for group in available_groups]
        group_descriptions = {group[0]: group[1] for group in available_groups}
        
        print("\nAvailable permission groups:")
        for group_name in valid_groups:
            description = group_descriptions.get(group_name, 'No description available')
            print(f"  - {group_name}: {description}")
        
        while True:
            default_group = valid_groups[0] if valid_groups else 'read_only'
            groups_input = input(f"Enter permission group [{default_group}]: ").strip()
            if not groups_input:
                return [default_group]
            
            # Only take the first group if multiple are entered
            group = groups_input.split(',')[0].strip()
            
            if group not in valid_groups:
                print(f"Invalid group: {group}")
                print(f"Valid groups are: {', '.join(valid_groups)}")
                continue
            
            return [group]
            
    except Exception as e:
        print(f"Warning: Could not fetch groups from database ({e}). Using defaults.")
        print("\nAvailable permission groups:")
        print("  - read_only: Can read reports and vendor data")
        print("  - admin: Full access including API key management")
        
        while True:
            groups_input = input("Enter permission group [read_only]: ").strip()
            if not groups_input:
                return ['read_only']
            
            group = groups_input.split(',')[0].strip()
            valid_groups = ['read_only', 'admin']
            
            if group not in valid_groups:
                print(f"Invalid group: {group}")
                print(f"Valid groups are: {', '.join(valid_groups)}")
                continue
            
            return [group]

def show_main_menu():
    """Display the main menu and get user choice"""
    print("\n" + "="*60)
    print(" VENDIANT API LAYER MANAGEMENT")
    print("="*60)
    #print("1. Setup Database Schema")
    print("1. Create API Key")
    print("2. List API Keys")
    print("3. Revoke API Key")
    print("4. View Audit Statistics")
    print("5. Exit")
    print("="*60)
    
    while True:
        try:
            choice = input("\nSelect an option (1-5): ").strip()
            if choice in ['1', '2', '3', '4', '5']:
                return int(choice)
            else:
                print("Invalid choice. Please enter a number between 1 and 6.")
        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)

def create_api_key_interactive():
    """Create a new API key with interactive prompts"""
    try:
        manager = APIKeyManager()
        
        print("\n" + "="*50)
        print("CREATE NEW API KEY")
        print("="*50)
        
        # Prompt for required fields
        name = prompt_for_input("API Key Name", required=True)
        
        # Prompt for optional fields
        description = prompt_for_input("Description", required=False)
        created_by = prompt_for_input("Created By", required=False)
        
        # Get configuration settings
        config = get_config()
        
        # Permission groups
        groups = prompt_for_groups()
        
        # Ask for temporary or permanent access
        while True:
            access_type = input("Access type - Temporary (T) or Permanent (P): ").strip().upper()
            if access_type in ['T', 'P']:
                break
            print("Invalid input. Please enter 'T' for Temporary or 'P' for Permanent.")
        
        # Only prompt for expiry days if temporary access is chosen
        expires_days = None
        if access_type == 'T':
            expires_days = prompt_for_input("Expiry days", required=True, input_type=int)
        else:
            print("Permanent access selected - no expiry date will be set.")
        
        # Set rate limits based on group permissions (from settings.py)
        if groups and ('admin' in groups or any('admin' in group.lower() for group in groups)):
            request_limit = config.ADMIN_RATE_LIMIT  # From settings.py: ADMIN_RATE_LIMIT
            group_type = "Admin"
        else:
            request_limit = config.READ_ONLY_RATE_LIMIT  # From settings.py: READ_ONLY_RATE_LIMIT
            group_type = "Read-Only"
        
        print(f"\nSummary:")
        print(f"   Name: {name}")
        print(f"   Description: {description or 'None'}")
        print(f"   Created By: {created_by}")
        print(f"   Key Type: {group_type}")
        print(f"   Access Type: {'Temporary' if access_type == 'T' else 'Permanent'}")
        print(f"   Expires: {f'{expires_days} days' if expires_days else 'Never'}")
        print(f"   Rate Limit: {request_limit}/minute ")
        print(f"   Groups: {', '.join(groups)}")
        
        confirm = input("\nCreate this API key? (y/N): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("API key creation cancelled.")
            return
        
        # Generate the API key with the selected group
        # Get default group from database if none selected
        if not groups:
            try:
                manager_temp = APIKeyManager()
                available_groups = manager_temp._get_available_groups()
                selected_group = available_groups[0] if available_groups else 'read_only'
            except:
                selected_group = 'read_only'
        else:
            selected_group = groups[0]
        api_key, credential_id = manager.generate_api_key(
            name=name,
            description=description,
            created_by=created_by,
            expires_days=expires_days,
            request_limit=request_limit,
            group_name=selected_group
        )
        
        print(f" ✅ Assigned group: {selected_group}")
        
        print(f"\n API Key Created Successfully!")
        print(f"   ID: {credential_id}")
        print(f"   Name: {name}")
        print(f"   API Key: {api_key}")
        print(f"\n  IMPORTANT: Store this API key securely. It will not be shown again!")
        
        input("\nPress Enter to continue...")
        
    except Exception as e:
        print(f" Error creating API key: {str(e)}")
        input("\nPress Enter to continue...")

def list_api_keys_interactive():
    """List all API keys"""
    try:
        manager = APIKeyManager()
        
        print("\n" + "="*50)
        print(" API KEYS LIST")
        print("="*50)
        
        include_disabled = input("Include disabled keys? (y/N): ").strip().lower() in ['y', 'yes']
        keys = manager.list_api_keys(include_disabled=include_disabled)
        
        if not keys:
            print(" No API keys found.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n Found {len(keys)} API key(s):")
        print("-" * 80)
        
        for key in keys:
            status = "Active" if key['is_enabled'] else " Disabled"
            print(f"ID: {key['id']} | {key['credential_prefix']}... | {key['name']}")
            print(f"   Status: {status}")
            print(f"   Created: {key['created_at'].strftime('%Y-%m-%d %H:%M')} by {key['created_by']}")
            print(f"   Last Used: {key['last_accessed'].strftime('%Y-%m-%d %H:%M') if key['last_accessed'] else 'Never'}")
            
            # Determine access type based on expires_at
            access_type = "Permanent" if key["expires_at"] is None else "Temporary"
            expires_info = "Never" if key["expires_at"] is None else key["expires_at"].strftime("%Y-%m-%d %H:%M")
            
            print(f"   Access Type: {access_type}")
            print(f"   Expires: {expires_info}")
            print(f"   Rate Limit: {key['request_limit']}/minute")
            if key['description']:
                print(f"   Description: {key['description']}")
            print()
        
        input("Press Enter to continue...")
        
    except Exception as e:
        print(f" Error listing API keys: {str(e)}")
        input("\nPress Enter to continue...")

def revoke_api_key_interactive():
    """Revoke an API key with interactive prompt"""
    try:
        manager = APIKeyManager()
        
        print("\n" + "="*50)
        print("REVOKE API KEY")
        print("="*50)
        
        # First show available keys
        keys = manager.list_api_keys(include_disabled=False)
        if not keys:
            print(" No active API keys found.")
            input("\nPress Enter to continue...")
            return
        
        print("\n Active API Keys:")
        for key in keys:
            print(f"   ID: {key['id']} - {key['name']} ({key['credential_prefix']}...)")
        
        key_id = prompt_for_input("\nEnter API Key ID to revoke", required=True, input_type=int)
        
        # Find and show the key details
        target_key = next((k for k in keys if k['id'] == key_id), None)
        if not target_key:
            print(f" API key with ID {key_id} not found.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n Key to revoke:")
        print(f"   ID: {target_key['id']}")
        print(f"   Name: {target_key['name']}")
        print(f"   Created: {target_key['created_at'].strftime('%Y-%m-%d %H:%M')}")
        
        # Confirm revocation
        confirm = input(f"\n Are you sure you want to revoke this API key? (y/N): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("Revocation cancelled.")
            input("\nPress Enter to continue...")
            return
        
        success = manager.revoke_api_key(key_id)
        
        if success:
            print(f" API key {key_id} revoked successfully!")
        else:
            print(f" Failed to revoke API key {key_id}")
        
        input("\nPress Enter to continue...")
        
    except Exception as e:
        print(f" Error revoking API key: {str(e)}")
        input("\nPress Enter to continue...")

def show_audit_stats_interactive():
    """Show audit statistics"""
    try:
        logger = AuditLogger()
        
        print("\n" + "="*50)
        print("AUDIT STATISTICS")
        print("="*50)
        
        days = prompt_for_input("Number of days to analyze", required=False, input_type=int, default=7)
        
        print(f"\n Analyzing last {days} days...")
        stats = logger.get_audit_stats(days=days)
        
        print(f"\n API Usage Statistics:")
        print("-" * 40)
        print(f" Total Requests: {stats.get('total_requests', 0):,}")
        print(f" Successful: {stats.get('successful_requests', 0):,}")
        print(f" Failed: {stats.get('failed_requests', 0):,}")
        print(f" Success Rate: {stats.get('success_rate', 0):.1f}%")
        print(f"Unique API Keys: {stats.get('unique_credentials', 0)}")
        print(f" Unique IPs: {stats.get('unique_ips', 0)}")
        print(f" Unique Endpoints: {stats.get('unique_endpoints', 0)}")
        
        input("\nPress Enter to continue...")
        
    except Exception as e:
        print(f" Error getting audit stats: {str(e)}")
        input("\nPress Enter to continue...")

'''def setup_database_interactive():
    """Set up the database schema"""
    try:
        print("\n" + "="*50)
        print("🗄️  DATABASE SETUP")
        print("="*50)
        
        print("This will create the required database tables for the API layer.")
        confirm = input("Continue with database setup? (y/N): ").strip().lower()
        
        if confirm not in ['y', 'yes']:
            print(" Database setup cancelled.")
            input("\nPress Enter to continue...")
            return
        
        import psycopg2
        from config.settings import get_config, get_db_connection
        
        config = get_config()
        
        # Read schema file
        schema_path = os.path.join(api_layer_dir, 'database', 'schema.sql')
        
        if not os.path.exists(schema_path):
            print(f" Schema file not found: {schema_path}")
            input("\nPress Enter to continue...")
            return
        
        print(f" Reading schema from: {schema_path}")
        with open(schema_path, 'r') as f:
            schema_sql = f.read()
        
        print(f" Connecting to database: {config.DATABASE_URL}")
        
        # Execute schema
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print(" Executing schema...")
        cursor.execute(schema_sql)
        conn.commit()
        
        cursor.close()
        conn.close()
        
        print(" Database schema set up successfully!")
        input("\nPress Enter to continue...")
        
    except Exception as e:
        print(f" Error setting up database: {str(e)}")
        print("Make sure DATABASE_URL is set correctly in your .env file")
        input("\nPress Enter to continue...")'''

def main():
    """Main CLI entry point with interactive menu"""
    try:
        while True:
            choice = show_main_menu()
            
           # if choice == 1:
           #     setup_database_interactive()
            if choice == 1:
                create_api_key_interactive()
            elif choice == 2:
                list_api_keys_interactive()
            elif choice == 3:
                revoke_api_key_interactive()
            elif choice == 4:
                show_audit_stats_interactive()
            elif choice == 5:
                print("\n Exiting...")
                sys.exit(0)
                
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)

if __name__ == '__main__':
    main() 