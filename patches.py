#!/usr/bin/python

import subprocess
import re
import os
import stat
import time

endpath = os.getcwd() + "/report.txt"
report_file = open(endpath, 'w')
os.system('touch /etc/motd')
os.system('touch /etc/issue')
os.system('touch /etc/issue.net')


def initial_head():

    report_file.write('\n')
    report_file.write("-------------------------------------------------\n")
    report_file.write("               Intial Setup Compliance           \n")
    report_file.write("-------------------------------------------------\n")


def run_apt_cache_policy():

    try:
        result = subprocess.run(['apt-cache', 'policy'], check=True, capture_output=True, text=True)
        print (result.stdout)
        print ("APT cache policy view completed")
        report_file.write("\n-APT cache policy view completed\n")
    except subprocess.CalledProcessError as e:
        print ("\nError has occurred when running 'apt-cache policy': {e}")
        report_file.write("\n-Error has occurred when running APT cache policy\n")


def run_apt_key_list():

    try:
        result = subprocess.run(['apt-key', 'list'], check=True, capture_output=True, text=True)
        print (result.stdout)
        print ("GPG keys have been verified")
        report_file.write("\n-APT key list view completed\n")
    except subprocess.CalledProcessError as e:
        print ("\nError has occurred when verifying 'apt-key list': {e}") 
        report_file.write("\n-Error has occurred when verifying APT key list\n")


def apt_upgrade(simulate=False):

    try:
        print ("Welcome to the System")


        while True:
             policy_option = input("Do you want to view APT package policy? (y/n): ").lower()
             if policy_option in ['y', 'n']:
                 break 
             else:
                 print ("Invalid input. Please enter 'y' or 'n'.")

        if policy_option == 'y':
            run_apt_cache_policy()

        while True:
             key_option =  input("Do you want to view APT key list? (y/n): ").lower()
             if key_option in ['y', 'n']:
                 break
             else:
                 print ("Invalid input. Please enter 'y' or 'n'.")

        if key_option == 'y':
            run_apt_key_list()


        while True:
             upgrade_option = input("Do you want to simulate (s) or perform (p) an APT upgrade? ")
             if upgrade_option in ['s', 'p']:
                 break
             else:
                 print ("Invalid input. Please enter 's' or 'p'.")
        if upgrade_option == 's':
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            result = subprocess.run(['apt', '-s', 'upgrade'], check=True, capture_output=True, text=True)
            print (result.stdout)
            print ("APT upgrade simulation completed.")
            report_file.write("-APT simulation upgrade completed\n")

        elif upgrade_option == 'p':
             subprocess.run(['sudo', 'apt', 'update'], check=True)
             subprocess.run(['sudo', 'apt', 'upgrade', '-y'], check=True)
             print ("APT upgrade completed successfully")
             report_file.write("-APT upgrade completed")
    except subprocess.CalledProcessError as e:
       print (f"Error during APT operation: {e}")



def check_etc_motd_for_patterns():

    try:
        with open('/etc/motd', 'r') as motd_file:
            motd_content = motd_file.read()

            #Defining the pattern
            pattern = '==== AUTHORISED USE ONLY. ALL ACTIVITY MAY BE MONITORED AND REPORTED ===='

            #Search for the pattern in the motd content
            match = re.search(pattern, motd_content)

            if match:
                print("\nRecommended MOTD Has Been Configured!\n")
            else:
                print("\nRecommended MOTD Has Not Been Configured. Proceeding to Configure...\n")
                os.system('echo "==== AUTHORISED USE ONLY. ALL ACTIVITY MAY BE MONITORED AND REPORTED ====" > /etc/motd')
                print("Message written to /etc/motd file.\n")
                report_file.write("\n- Message has been written to /etc/motd file.\n")
    except FileNotFoundError:
       print ("Error: /etc/motd not found")
    except Exception as e:
       print (f"Error: {e}")
       report_file.write("\n- MOTD Error: {e}")

#Write the message to '/etc/issue.net'
    message = "==== Authorized use only. All activity may be monitored and reported ====.\n"

    with open('/etc/issue.net', 'w') as file:
        file.write(message)
        print ("Message written to /etc/issue.net.\n")
        report_file.write("\n- Message written to /etc/issue.net.")

#Read the contents of '/etc/issue.net'
    with open('/etc/issue.net', 'r') as file:
        content = file.read()
        print (f"Contents of /etc/issue.net:\n{content}")


#Check for patterns in /etc/issue
def check_etc_issue_for_patterns():

    try: 
        #Get the value of the ID field from /etc/os-release
        os_release_id = subprocess.check_output(['grep', '^ID=', '/etc/os-release']).decode('utf-8').split('=')[1].strip().replace('"', '')
   
        #Construct the pattern 
        pattern = re.compile(f"(\\\v|\\\r|\\\m|\\\s|{os_release_id})", re.IGNORECASE)

        #Search for the pattern in the content of /etc/issue
        with open('/etc/issue', 'r') as issue_file:
            issue_content = issue_file.read()
            match = pattern.search(issue_content)

            if match:
                print ("Pattern found in /etc/issue. Proceeding to Modify...")
                os.system('echo "Authorized use only. All activity may be monitored and reported." > /etc/issue')
                report_file.write("\n- Issue File has Been Modified. (/etc/issue)")
            else:
                print ("\nPattern was not found in /etc/issue. No changes need to be made.")

    except FileNotFoundError:
        print ("Error: /etc/issue not found.")
    except subprocess.CalledProcessError as e:
        print (f"Error running 'grep' command: {e}")
    except Exception as e:
        print (f"Error: {e}")


#Check for patterns in /etc/issue.net
#def check_etc_issue_net_for_patterns():
#    try:
        #Get the value of the ID field from /etc/os-release
#        os_release_id = subprocess.check_output(['grep', '^ID=', '/etc/os-release']).decode('utf-8').split('=')[1].strip().replace('"', '')

        #Construct the pattern
#        pattern = re.compile(f"(\\\v|\\\r|\\\m|\\\s|{os_release_id})", re.IGNORECASE)

        #Open and read /etc/issue.net
#        with open('/etc/issue.net', 'r') as issue_net_file:
#            for line in issue_net_file:
#                if re.search(pattern, line, re.IGNORECASE):
#                    print (line.strip()) 


#    except FileNotFoundError:
#        print ("Error: /etc/issue.net not found.")
#    except subprocess.CalledProcessError as e: 
#        print (f"Error running 'grep' command {e}")
#    except Exception as e:
#        print (f"Error: {e}")




def get_file_info_etc_motd(file_path):

    if os.path.exists(file_path):
        file_stat = os.stat(file_path)
        access_mode_octal = oct(file_stat.st_mode & 0o777)  #Extract the permission bits and convert to octal
        access_mode_human = stat.filemode(file_stat.st_mode)
        uid = file_stat.st_uid
        gid = file_stat.st_gid
        username = os.path.basename(os.path.expanduser('~'))
        groupname = os.path.basename(os.path.expanduser('~'))

        report_file.write("Access: ({access_mode_octal}/{access_mode_human}) Uid: ({uid}/{username}) Gid: ({gid})/{groupname}) for /etc/motd-\n")
    else:
        report_file.write("Nothing is returned")


file_path = '/etc/motd'
result = get_file_info_etc_motd(file_path)
print (result)


def display_permission_options():
    print ("\nPermission Options:")
    print ("1. Read (r)")
    print ("2. Write (w)")
    print ("3. Execute (x)")



def get_permission_choice():
    while True:
        choice = input("Enter the permission option (1-3): ")
        if choice in ['1', '2', '3']:
            return choice
        else:
            print ("Invalid choice. Please enter a number between 1 and 3.")



def get_permissions_from_user():
    display_permission_options()

    owner_permission = get_permission_choice()
    group_permission = get_permission_choice()
    others_permission = get_permission_choice()

    # Convert the choices to octal format
    octal_permissions = int(f"{owner_permission}{group_permission}{others_permission}", 8)
    
    return octal_permissions



def set_file_permissions_etc_motd(file_path, new_owner_uid, new_group_gid, new_permissions):
    try:
        # Change ownership to specified UID and GID
        os.chown(file_path, new_owner_uid, new_group_gid)

        # Set permissions
        os.chmod(file_path, new_permissions)

        print (f"Ownership and permissions for {file_path} set successfully.")
        print (f"Chosen owner UID: {new_owner_uid}, Chosen group GID: {new_group_gid}")

    except OSError as e:
        print (f"Error setting ownership and permissions: {e}")

# Example usage
file_path = '/etc/motd'

# Assign default values
default_owner_uid = 1000  # Replace with your desired UID
default_group_gid = 1000  # Replace with your desired GID

time.sleep(1)
# Ask the user if they want to change the ownership
change_owner_option = input("\nDo you want to change the ownership for owner? (y/n): ").lower()
if change_owner_option == 'y':
    new_owner_uid = int(input("\nEnter the new owner UID: "))
    print (f"\nChosen owner UID: {new_owner_uid}")
else:
    new_owner_uid = default_owner_uid
    print (f"\nDefault owner UID chosen: {default_owner_uid}")

time.sleep(1)
# Ask the user if they want to change the group
change_group_option = input("\nDo you want to change group? (y/n): ").lower()
if change_group_option == 'y':
    new_group_gid = int(input("\nEnter the new group GID: "))
    print (f"\nChosen group GID: {new_group_gid}")
else:
    new_group_gid = default_group_gid
    print (f"\nDefault group GID chosen: {default_group_gid}")

time.sleep(1)
# Ask the user if they want to change permissions
change_permissions_input = input("\nDo you want to change the permissions /etc/motd file? (y/n): ").lower()
if change_permissions_input == 'y':
    new_permissions = get_permissions_from_user()
    print (f"\nPermission for etc/motd changed to {oct(new_permissions)[2:]}")
    set_file_permissions_etc_motd(file_path, new_owner_uid, new_group_gid, new_permissions)
    report_file.write("\nPermission for etc/issue changed successfully\n")
else:
    print ("\nOwnership and permissions not set.")




def get_file_info_etc_issue(file_path):

    if os.path.exists(file_path):
        file_stat = os.stat(file_path)
        access_mode_octal = oct(file_stat.st_mode & 0o777)  #Extract the permissi>
        access_mode_human_read = stat.filemode(file_stat.st_mode)
        uid = file_stat.st_uid
        gid = file_stat.st_gid
        username = os.path.basename(os.path.expanduser('~'))
        groupname = os.path.basename(os.path.expanduser('~'))

        report_file.write("Access: ({access_mode_octal}/{access_mode_human_read}) Uid: ({uid}/{username}) Gid: ({gid}/{groupname}) for /etc/issue - \n")
    else:
        report_file.write("Nothing is returned")


file_path = '/etc/issue'
result = get_file_info_etc_issue(file_path)
print (result)


def display_permission_options():
    print ("\nPermission Options:")
    print ("1. Read (r)")
    print ("2. Write (w)")
    print ("3. Execute (x)")

def get_permission_choice():
    while True:
        choice = input("\nEnter the permission option (1-3): ")
        if choice in ['1', '2', '3']:
            return choice
        else:
            print ("\nInvalid choice. Please enter a number between 1 and 3.")

def get_permissions_from_user():
    display_permission_options()

    owner_permission = get_permission_choice()
    group_permission = get_permission_choice()
    others_permission = get_permission_choice()

    # Convert the choices to octal format
    octal_permissions = int(f"{owner_permission}{group_permission}{others_permission}", 8)
    
    return octal_permissions

def set_permissions_change_ownership_etc_issue(file_path, new_owner_uid, new_group_gid, new_permissions):
    try:
        # Change ownership to specified UID and GID
        os.chown(file_path, new_owner_uid, new_group_gid)

        # Set permissions
        os.chmod(file_path, new_permissions)

        print (f"\nOwnership and permissions for {file_path} set successfully.")
        print (f"\nChosen owner UID: {new_owner_uid}, Chosen group GID: {new_group_gid}")

    except OSError as e:
        print (f"\nError setting ownership and permissions: {e}")

# Example usage
file_path = '/etc/issue'

# Assign default values
default_owner_uid = 1000  # Replace with your desired UID
default_group_gid = 1000  # Replace with your desired GID

time.sleep(1)
# Ask the user if they want to change the ownership
change_owner_option = input("\nDo you want to change the ownership for owner? (y/n): ").lower()
if change_owner_option == 'y':
    new_owner_uid = int(input("\nEnter the new owner UID: "))
    print (f"\nChosen owner UID: {new_owner_uid}")
else:
    new_owner_uid = default_owner_uid
    print (f"\nDefault owner UID chosen: {default_owner_uid}")

time.sleep(1)
# Ask the user if they want to change the group
change_group_option = input("\nDo you want to change group? (y/n): ").lower()
if change_group_option == 'y':
    new_group_gid = int(input("\nEnter the new group GID: "))
    print (f"\nChosen group GID: {new_group_gid}")
else:
    new_group_gid = default_group_gid
    print (f"\nDefault group GID chosen: {default_group_gid}")

time.sleep(1)
# Ask the user if they want to change permissions
change_permissions_input = input("\nDo you want to change the permissions /etc/issue file? (y/n): ").lower()
if change_permissions_input == 'y':
    new_permissions = get_permissions_from_user()
    print (f"\nPermission for etc/issue changed to {oct(new_permissions)[2:]}")
    set_permissions_change_ownership_etc_issue(file_path, new_owner_uid, new_group_gid, new_permissions)
    report_file.write("\nPermission for etc/issue changed successfully\n")
else:
    print ("\nOwnership and permissions not set.")




def get_file_info_etc_issue_net(file_path):

    if os.path.exists(file_path):
       file_stat = os.stat(file_path)
       access_mode_octal = oct(file_stat.st_mode & 0o777) #Extract the permission bits and convert to octal
       access_mode_human_read = stat.filemode(file_stat.st_mode)
       uid = file_stat.st_uid
       gid = file_stat.st_gid
       username = os.path.basename(os.path.expanduser('~'))
       groupname = os.path.basename(os.path.expanduser('~'))

       report_file.write("Access: ({access_mode_octal}/{access_mode_human_read}) Uid: ({uid}/{username}) Gid: ({gid}/{groupname}) for /etc/issue/net\n")
   
    else: 
       report_file.write("Nothing is returned\n") 

file_path = '/etc/issue.net'
result = get_file_info_etc_issue_net(file_path)
print (result)



def display_permission_options():
    print ("\nPermission Options:")
    print ("1. Read (r)")
    print ("2. Write (w)")
    print ("3. Execute (x)")



def get_permission_choice():
    while True:
        choice = input("\nEnter the permission option (1-3): ")
        if choice in ['1', '2', '3']:
            return choice
        else:
            print ("\nInvalid choice. Please enter a number between 1 and 3.")




def get_permissions_from_user():
    display_permission_options()

    owner_permission = get_permission_choice()
    group_permission = get_permission_choice()
    others_permission = get_permission_choice()

    # Convert the choices to octal format
    octal_permissions = int(f"{owner_permission}{group_permission}{others_permission}", 8)
    
    return octal_permissions



def set_permissions_change_ownership_etc_issue_net(file_path, new_owner_uid, new_group_gid, new_permissions):
    try:
        # Change ownership to specified UID and GID
        os.chown(file_path, new_owner_uid, new_group_gid)

        # Set permissions
        os.chmod(file_path, new_permissions)

        print (f"\nOwnership and permissions for {file_path} set successfully.")
        print (f"\nChosen owner UID: {new_owner_uid}, Chosen group GID: {new_group_gid}")

    except OSError as e:
        print (f"\nError setting ownership and permissions: {e}")



# Example usage
file_path = '/etc/issue.net'

# Assign default values
default_owner_uid = 1000  # Replace with your desired UID
default_group_gid = 1000  # Replace with your desired GID

time.sleep(1)
# Ask the user if they want to change the ownership
change_owner_option = input("\nDo you want to change the ownership for owner? (y/n): ").lower()
if change_owner_option == 'y':
    new_owner_uid = int(input("\nEnter the new owner UID: "))
    print (f"\nChosen owner UID: {new_owner_uid}")
else:
    new_owner_uid = default_owner_uid
    print (f"\nDefault owner UID chosen: {default_owner_uid}")

time.sleep(1)
# Ask the user if they want to change the group
change_group_option = input("\nDo you want to change group? (y/n): ").lower()
if change_group_option == 'y':
    new_group_gid = int(input("\nEnter the new group GID: "))
    print (f"\nChosen group GID: {new_group_gid}")
else:
    new_group_gid = default_group_gid
    print (f"\nDefault group GID chosen: {default_group_gid}")

time.sleep(1)
# Ask the user if they want to change permissions
change_permissions_input = input("\nDo you want to change the permissions /etc/issue/net file? (y/n): ").lower()
if change_permissions_input == 'y':
    new_permissions = get_permissions_from_user()
    print (f"\nPermission for etc/issue/net changed to {oct(new_permissions)[2:]}")
    set_permissions_change_ownership_etc_issue_net(file_path, new_owner_uid, new_group_gid, new_permissions)
    report_file.write("\nPermission for etc/issue/net changed successfully\n")
else:
    print ("\nOwnership and permissions not set.")




if __name__ == "__main__":
    initial_head()
    time.sleep(2)
    check_etc_motd_for_patterns()
    time.sleep(2)
    apt_upgrade(simulate=True)
    time.sleep(2)
    check_etc_issue_for_patterns()
    time.sleep(2)
    #check_etc_issue_net_for_patterns()

report_file.close()


