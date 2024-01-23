import os
import re
import subprocess
import time
import io
from contextlib import redirect_stdout
from datetime import datetime
from colorama import Fore
from colorama import Style
from colorama import init as colorama_init
from getpass import getpass

if not os.path.exists('logs'):
    os.makedirs('logs')

log_ufw = []
log_services = []
log_passwords = []
log_patching = []
current_date = ""
current_datetime = ""


def log_setup():
    global current_date
    global current_datetime
    log_file_path = 'logs/script_log.log'
    current_date = datetime.now().strftime("%Y-%m-%d")
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = f"{'-' * 70}\nCIS Compliance Suite Logging\n{'-' * 70}\n"

    if not os.path.exists(log_file_path):
        with open(log_file_path, "w") as log_file:
            log_file.write(header)
            log_file.write(f"{current_datetime} - ============ SCRIPT INITIATION ============\n")
    else:
        with open(log_file_path, "a") as log_file:
            log_file.write(f"{current_datetime} - ============ SCRIPT Execution ============\n")


def log_changes(changes, control):
    global log_ufw, log_services, log_passwords, log_patching
    if control == "ufw":
        log_ufw.append(changes)
    elif control == "services":
        log_services.append(changes)
    elif control == "pam":
        log_passwords.append(changes)
    elif control == "patching":
        log_patching.append(changes)


def log_category(control):
    log_file_path = 'logs/script_log.log'
    with open(log_file_path, "a") as log_file:
        if control == "ufw":
            log_file.write(f"-----------------------------------------------------------------------\n")
            log_file.write(f"                           UFW CONFIGURATIONS                          \n")
            log_file.write(f"-----------------------------------------------------------------------\n")
            for line in log_ufw:
                log_file.write(f"{line}")
        elif control == "services":
            log_file.write(f"-----------------------------------------------------------------------\n")
            log_file.write(f"                           SERVICES CONFIGURATIONS                          \n")
            log_file.write(f"-----------------------------------------------------------------------\n")
            for line in log_services:
                log_file.write(f"{line}")
        elif control == "passwords":
            log_file.write(f"-----------------------------------------------------------------------\n")
            log_file.write(f"                           PASSWORD CONFIGURATIONS                          \n")
            log_file.write(f"-----------------------------------------------------------------------\n")
            for line in log_passwords:
                log_file.write(f"{line}")

        elif control == "patching":
            log_file.write(f"-----------------------------------------------------------------------\n")
            log_file.write(f"                           PATCHING CONFIGURATIONS                          \n")
            log_file.write(f"-----------------------------------------------------------------------\n")
            for line in enumerate(log_patching):
                log_file.write(f"{line}")


def ask(name):
    while True:
        choice = input(
            f"The script will remove {Fore.RED} " + str(name) + f"{Style.RESET_ALL} . Do you want to remove it y/n ")
        if choice.lower() == "y":
            return True
        elif choice.lower() == "n":
            return False
        else:
            print("Please enter a valid input")


def check_service(service_name):
    result = subprocess.call(f"dpkg -l | grep '^ii  {service_name} ' > /dev/null 2>&1", shell=True)
    return result == 0


def scan_service(service_name):
    if check_service(service_name):
        print(f"- {service_name} is installed.\U000026D4  Please uninstall it. \U000026D4 \n")
        return True
    else:
        print(f"- {service_name} is not installed. No action is needed.\n")
        return False


def purge_service(service_name):
    if check_service(service_name):
        if ask(service_name):
            print(f"Uninstallation of {service_name}...\n")
            line = f"Uninstallation of {service_name}..."
            log_changes(line, "services")
            os.system(f"apt purge {service_name}* > /dev/null 2>&1")
        else:
            print(f"{service_name} uninstallation bypassed.\n")
            line = f"{service_name} uninstallation bypassed.\n"
            log_changes(line, "services")
    # else:
    #     print(f"- {service_name} is not installed.\n")
    #     line = f"{service_name} is not installed.\n"
    #     log_changes(line, "services")


# Example usage
services_to_check = ["xserver-xorg", "avahi", "dhcp", "ldap", "nfs", "dns", "vsftpd", "apache2", "samba", "squid",
                     "snmpd", "nis", "rsync", "rsh-client", "talk", "telnet", "ldap-utils", "rpcbind", "dovecot-imapd",
                     "dovecot-pop3d", "dnsmasq-base"]

for service in services_to_check:
    check_service(service)
    scan_service(service)
    purge_service(service)
# http	apache2
# imap	dovecot-impad
# pop3	dovecot-pop3d
# samba	samba
# squid	squid
# snmp	snmpd
# nis	nis
# dnsmasq	dnsmasq-base
# rsync	rsync
# rsh	rsh-client
# talk	talk
# telnet	telnet
# ldap_utils	ldap-utils
# rpcbind	rpcbind
