#!/usr/bin/python
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


def banner():
    #\033[94m blue ansi
    print("""
        |  ____  _              _______ _     _                |
        | |  _ \| |            |__   __| |   (_)               |
        | | |_) | |_   _  ___     | |  | |__  _ _ __   __ _    |
        | |  _ <| | | | |/ _ \    | |  | '_ \| | '_ \ / _` |   |
        \ | |_) | | |_| |  __/    | |  | | | | | | | | (_| |   /
        | |____/|_|\__,_|\___|    |_|  |_| |_|_|_| |_|\__, |   |
        |                                               __/|   |
        |                                              |___/   |
        
            Welcome to the CIS Compliance Suite Script
    
    Description:
    This script is designed to help you ensure compliance with the 
    Center for Internet Security (CIS) benchmarks for
    Ubuntu Linux 20.04 v2.0.1 - 06-29-2023
    It provides options for system scanning and direct configurations, 
    allowing you to assess and enhance the security posture of your system.
    
    Features:
    - System scanning for CIS benchmarks.
    - Direct configurations to address compliance issues.
    - Logging of configuration changes and scan results.
    
    Usage:
    1. Run the script and choose between scanning for compliance or conducting direct configurations.
    2. Select specific benchmarks or services to scan or configure.
    3. Follow the prompts to complete the selected actions.
    4. View logs for a detailed record of configuration changes and scan results.
    
    Note: Make sure to review the documentation for detailed instructions and best practices.
    
    Authors: CB010695, CB010736, CB010830, CB010837   
    Version: 2.2.3
    """)
    #\033[91m
    input("\n Press Enter to continue...")


def clear_screen():
    time.sleep(1)
    os.system('clear')


def y_n_choice():
    while True:
        try:
            user_input = input("Enter 'yes' to continue or 'no' to skip: ")

            if user_input is None:
                print("Error: Result is None.")
                return

            user_input = user_input.lower()
            if user_input not in ['yes', 'y', 'no', 'n', '']:
                raise ValueError("Invalid input, please enter 'yes' or 'no'.")

            return user_input
        except ValueError as ve:
            print("Error:", ve)
        except TypeError as ve:
            print("Error:", ve)
        except AttributeError as ve:
            print("Error:", ve)


log_ufw = []
log_services = []
log_passwords = []
log_patching = []
current_date = ""
current_datetime = ""


def log_setup():
    global current_date
    global current_datetime
    log_file_path = "script_log.log"
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
    elif control == "passwords":
        log_passwords.append(changes)
    elif control == "patching":
        log_patching.append(changes)


def log_category(control):
    log_file_path = "script_log.log"
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


def control_or_date_log():
    try:
        print("""
    Do you want to generate a log report?
        """)
        choice = y_n_choice().lower()
        if choice == 'y' or choice == 'yes' or choice == '':
            choice = input("""
    \033[91m|======================== Log Options ========================|\033[0m
    Enter your choice as an integer:
    1) Log by date
    2) Log by control

    Please enter the index of your choice: """)
            choice = int(choice)
            if choice == 1:
                output_filepath = f"{current_date}.log"
                with open(output_filepath, 'w') as output_file:
                    for lines in enumerate(log_ufw):
                        output_file.writelines(f"{str(lines)}\n")
                    for lines in enumerate(log_services):
                        output_file.writelines(f"{str(lines)}\n")
                    for lines in enumerate(log_passwords):
                        output_file.writelines(f"{str(lines)}\n")
                    for lines in enumerate(log_patching):
                        output_file.writelines(f"{str(lines)}\n")
            elif choice == 2:
                flag = False
                log_mapping = {
                    "UFW CONFIGURATIONS": log_ufw,
                    "SERVICES CONFIGURATIONS": log_services,
                    "PASSWORD CONFIGURATION": log_passwords,
                    "PATCHING CONFIGURATIONS": log_patching
                }
                for control, log_list in log_mapping.items():
                    output_filepath = f"{control}.log"
                    with open(output_filepath, 'a') as output_file:
                        for lines in log_list:
                            output_file.writelines(f"{str(lines)}\n")
                    flag = True

                if flag:
                    print("Log generated successfully")
                else:
                    print("Log not generated")
            else:
                print("Invalid choice. Please enter either 1 or 2.")

        elif choice == 'n' or choice == 'no':
            print("No log generated")
            input("Enter to continue")
            home_main()
            return True  # without this true the function will keep on doing configurations which is also a good thing.
        else:
            print("Invalid choice. Please enter either 'yes' or 'no'.")

    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)
    except AttributeError as ve:
        print("Error:", ve)


# ================================= Services =================================== Services ===========================
# Services =================================== Services ========== Services ===================================
# Services ====
colorama_init()


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


# ======================================= Service Check Functions =================================

def check_xserver():
    try:
        subprocess.check_output(["pgrep", "xserver-xorg*"])
        return True
    except subprocess.CalledProcessError:
        return False


def check_avahi():
    result = os.system("dpkg -l | grep avahi-daemon > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_dhcp():
    result = os.system("dpkg -l | grep isc-dhcp-server > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_ldap():
    result = os.system("dpkg -l | grep slapd > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_nfs():
    result = os.system("dpkg -l | grep nfs-kernel-server > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_dns():
    try:
        subprocess.check_output(["dpkg", "-l", "bind9"], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


def check_vsftpd():
    result = os.system("dpkg -l | grep vsftpd > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_http():
    try:
        subprocess.check_output(["dpkg", "-l", "apache2"], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


def check_imap_pop3():
    result = os.system("dpkg -l | grep dovecot-imapd dovecot-pop3d > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_samba():
    result = os.system("dpkg -l | grep samba > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_squid():
    result = os.system("dpkg -l | grep squid > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_snmp():
    result = os.system("dpkg -l | grep snmpd > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_nis():
    result = os.system("dpkg -l | grep -w nis > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_dnsmasq():
    result = os.system("dpkg -l | grep dnsmasq > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_rsync():
    result = os.system("dpkg -l | grep rsync > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


# ======================================= Service Scan Functions =================================
def scan_xserver():
    if check_xserver():
        print(f"- X Windows System is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "X Windows System is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- X Windows System is not installed. No action is needed.\n")
        line = "X Windows System is not install. No action is needed.\n"
        log_changes(line, "services")


def scan_avahi():
    if check_avahi():
        print(f"- Avahi Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "Avahi Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- Avahi Server is not installed. No action is needed.\n")
        line = "Avahi Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_dhcp():
    if check_dhcp():
        print(f"- DHCP Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "DHCP Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- DHCP Server is not installed. No action is needed.\n")
        line = "DHCP Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_ldap():
    if check_ldap():
        print(
            f"- Lightweight Directory Access Protocol is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = (
            f"Lightweight Directory Access Protocol is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        log_changes(line, "services")
    else:
        print("- Lightweight Directory Access Protocol is not installed. No action is needed.\n")
        line = "Lightweight Directory Access Protocol is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_nfs():
    if check_nfs():
        print(f"- Network File System is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = (
            f"Network File System is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        log_changes(line, "services")
    else:
        print("- Network File System is not installed. No action is needed.\n")
        line = "Network File System is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_dns():
    if check_dns():
        print(f"- DNS Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "DNS Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- DNS Server is not installed. No action is needed.\n")
        line = "DNS Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_vsftpd():
    if check_vsftpd():
        print(f"- FTP Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "FTP Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- FTP Server is not installed. No action is needed.\n")
        line = "FTP Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_http():
    if check_http():
        print(f"- HTTP Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "HTTP Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- HTTP Server is not installed. No action is needed.\n")
        line = "HTTP Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_imap_pop3():
    if check_imap_pop3():
        print(f"- IMAP and POP3 is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "IMAP and POP3 is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- IMAP and POP3 is not installed. No action is needed.\n")
        line = "IMAP and POP3 is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_samba():
    if check_samba():
        print(f"- Samba Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "Samba Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- Samba Server is not installed. No action is needed.\n")
        line = "Samba Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_squid():
    if check_squid():
        print(f"- HTTP Proxy Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "HTTP Proxy Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- HTTP Proxy Server is not installed. No action is needed.\n")
        line = "HTTP Proxy Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_snmp():
    if check_snmp():
        print(f"- SNMP Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "SNMP Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- SNMP Server is not installed. No action is needed.\n")
        line = "SNMP Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_nis():
    if check_nis():
        print(f"- NIS Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "NIS Server is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- NIS Server is not installed. No action is needed.\n")
        line = "NIS Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_dnsmasq():
    if check_dnsmasq():
        print(f"- DNSMASQ is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "DNSMASQ is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- DNSMASQ is not installed. No action is needed.\n")
        line = "DNSMASQ is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_rsync():
    if check_rsync():
        print(f"- Rsync is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "Rsync is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- Rsync is not installed. No action is needed.\n")
        line = "Rsync is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_rsh():
    if check_rsh():
        print(f"- Rsh Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "Rsh Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- Rsh Client is not installed. No action is needed.\n")
        line = "Rsh Client is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_talk():
    if check_talk():
        print(f"- Talk Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "Talk Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- Talk Client is not installed. No action is needed.\n")
        line = "Talk Client is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_telnet():
    if check_telnet():
        print(f"- Telnet Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "Telnet Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- Telnet Client is not installed. No action is needed.\n")
        line = "Telnet Client is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_ldap_utils():
    if check_ldap_utils():
        print(f"- LDAP Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "LDAP Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- LDAP Client is not installed. No action is needed.\n")
        line = "LDAP Client is not installed. No action is needed.\n"
        log_changes(line, "services")


def scan_rpcbind():
    if check_rpcbind():
        print(f"- RPC Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n")
        line = "RPC Client is installed.\U000026D4  Please Uninstall it. \U000026D4 \n"
        log_changes(line, "services")
    else:
        print("- RPC Client is not installed. No action is needed.\n")
        line = "RPC Client is not installed. No action is needed.\n"
        log_changes(line, "services")


# ======================================= Service Purge Functions =================================
def purge_xserver():
    if check_xserver():
        if ask("X Windows System"):
            print(f"- X Windows System is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "X Windows System is installed.{Fore.RED} Proceeding to uninstall.{Style.RESET_ALL}\n"
            log_changes(line, "services")

            os.system("apt purge xserver-xorg*")
        else:
            print("X Windows was not removed due to user input.\n")
            line = "X Windows was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- X Windows System is not installed. No action needed.\n")
        line = "X Windows System is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_avahi():
    if check_avahi():
        if ask("Avahi Server"):
            print(f"- Avahi Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "Avahi Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("systemctl stop avahi-daemon.service")
            os.system("systemctl stop avahi-daemon.socket")
            os.system("apt purge avahi-daemon")
        else:
            print("Avahi Server was not removed due to user input.\n")
            line = "Avahi Server was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- Avahi Server is not installed. No action needed.\n")
        line = "Avahi Server is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_dhcp():
    if check_dhcp():
        if ask("DHCP Server"):
            print(f"- DHCP Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "DHCP Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}.\n"
            log_changes(line, "services")
            os.system("apt purge isc-dhcp-server")
        else:
            print("DHCP Server was not removed due to user input.\n")
            line = "DHCP Server was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- DHCP Server is not installed. No action needed.\n")
        line = "DHCP is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_ldap():
    if check_ldap():
        if ask("Lightweight Directory Access Protocol"):
            print(
                f"- Lightweight Directory Access Protocol is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = (
                "Lightweight Directory Access Protocol is installed.{Fore.RED} Proceeding to uninstall...{"
                "Style.RESET_ALL}\n")
            log_changes(line, "services")
            os.system("apt purge slapd")
        else:
            print("Lightweight Directory Access Protocol was not removed due to user input.\n")
            line = "Lightweight Directory Access Protocol was not removed due to user input\n"
            log_changes(line, "services")
    else:
        print("- Lightweight Directory Access Protocol is not installed. No action is needed.\n")
        line = "Lightweight Directory Access Protocol is not installed. No action needed\n"
        log_changes(line, "services")


def purge_nfs():
    if check_nfs():
        if ask("Network File System"):
            print(f"- Network File System is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "Network File System is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge nfs-kernel-server")
        else:
            print("Network File System is installed. Proceeding to uninstall...\n")
            line = "Network File System was not removed due to user input\n"
            log_changes(line, "services")
    else:
        print("- Network File System is not installed. No action needed\n")
        line = "Network File System is not installed. No action needed\n"
        log_changes(line, "services")


def purge_dns():
    if check_dns():
        if ask("DNS Server"):
            print(f"- DNS Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "DNS Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge bind9")
        else:
            print("DNS Server was not removed due to user input.\n")
            line = "DNS Server was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- DNS Server is not installed. No action is needed.\n")
        line = "DNS Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def purge_vsftpd():
    if check_vsftpd():
        if ask("FTP Server"):
            print(f"- FTP Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "FTP Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge vsftpd")
        else:
            print("FTP Server was not removed due to user input.\n")
            line = "FTP Server was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- FTP Server is not installed. No action is needed.\n")
        line = "FTP Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def purge_http():
    if check_http():
        if ask("HTTP Server"):
            print(f"- HTTP Server is installed,{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "HTTP Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge apache2")
        else:
            print("HTTP Server was not removed due to user input.\n")
            line = "HTTP Server was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- HTTP Server is not installed. No action is needed.\n")
        line = "HTTP Server is not installed. No action is needed.\n"
        log_changes(line, "services")


def purge_imap_pop3():
    if check_imap_pop3():
        if ask("IMAP and POP3"):
            print(f"- IMAP and POP3 is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "IMAP and POP3 is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge dovecot-impad dovecot-pop3d")
        else:
            print("IMAP and POP3 was not removed due to user input.\n")
            line = "IMAP and POP3 was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- IMAP and POP3 is not installed. No action needed.\n")
        line = "IMAP and POP3 is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_samba():
    if check_samba():
        if ask("Samba Server"):
            print(f"- Samba Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "Samba Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge samba")
        else:
            print("Samba Server not removed due to user input.\n")
            line = "Samba was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- X Samba Server is not installed. No action needed.\n")
        line = "Samba Server is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_squid():
    if check_squid():
        if ask("HTTP Proxy Server"):
            print(f"- HTTP Proxy Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "HTTP Proxy Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge squid")
        else:
            print("HTTP Proxy Server not removed due to user input.\n")
            line = "HTTP Proxy Server was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- HTTP Proxy Server is not installed. No action needed.\n")
        line = "HTTP Proxy Server is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_snmp():
    if check_snmp():
        if ask("SNMP Server"):
            print(f"- SNMP Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "SNMP Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge snmpd")
        else:
            print("SNMP Server not removed due to user input.\n")
            line = "SNMP Server was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- SNMP Server is not installed. No action needed.\n")
        line = "SNMP Server is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_nis():
    if check_nis():
        if ask("NIS Server"):
            print(f"- NIS Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "NIS Server is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge nis")
        else:
            print("NIS Server not removed due to user input.\n")
            line = "NIS Server was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- NIS Server is not installed. No action needed.\n")
        line = "NIS Server is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_dnsmasq():
    if check_dnsmasq():
        if ask("DNSMASQ"):
            print(f"- DNSMASQ is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "DNSMASQ is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge dnsmasq-base")
        else:
            print("DNSMASQ not removed due to user input.\n")
            line = "DNSMASQ was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- DNSMASQ is not installed. No action needed.\n")
        line = "DNSMASQ is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_rsync():
    if check_rsync():
        if ask("Rsync"):
            print(f"- Rsync is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "Rsync is installed{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge rsync")
        else:
            print("Rsync not removed due to user input.\n")
            line = "Rsync was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- Rsync is not installed. No action needed.\n")
        line = "Rsync is not installed. No action needed.\n"
        log_changes(line, "services")


# ======================================= Service Clients Check Section ================================
def check_rsh():
    result = os.system("dpkg -l | grep rsh-client > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_talk():
    result = os.system("dpkg -s talk > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_telnet():
    result = os.system("dpkg -l | grep telnet > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_ldap_utils():
    result = os.system("dpkg -l | grep ldap-utils > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


def check_rpcbind():
    result = os.system("dpkg -l | grep rpcbind > /dev/null 2>&1")
    if result == 0:
        return True
    else:
        return False


# ======================================= Service Clients Purge Section ================================
def purge_rsh():
    if check_rsh():
        if ask("Rsh Client"):
            print(f"- Rsh Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "Rsh Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge rsh-client")
        else:
            print("Rsh Client not removed due to user input.\n")
            line = "Rsh Client was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- Rsh Client is not installed. No action needed.\n")
        line = "Rsh Client is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_talk():
    if check_talk():
        if ask("Talk Client"):
            print(f"- Talk Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "Talk Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge talk")
        else:
            print("Talk Client not removed due to user input.\n")
            line = "Talk Client was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- Talk Client is not installed. No action needed.\n")
        line = "Talk Client is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_telnet():
    if check_telnet():
        if ask("Telnet Client"):
            print(f"- Telnet Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "Telnet Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge telnet")
        else:
            print("Telnet Client not removed due to user input.\n")
            line = "Telnet Client was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- Telnet Client is not installed. No action needed.\n")
        line = "Telnet Client is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_ldap_utils():
    if check_ldap_utils():
        if ask("LDAP Client"):
            print(f"- LDAP Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "LDAP Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge ldap-utils")
        else:
            print("LDAP Client not removed due to user input.\n")
            line = "LDAP Client was not removed due to user input.\n"
            log_changes(line, "services")

    else:
        print("- LDAP Client is not installed. No action needed.\n")
        line = "LDAP Client is not installed. No action needed.\n"
        log_changes(line, "services")


def purge_rpcbind():
    if check_rpcbind():
        if ask("RPC Client"):
            print(f"- RPC Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n")
            line = "RPC Client is installed.{Fore.RED} Proceeding to uninstall...{Style.RESET_ALL}\n"
            log_changes(line, "services")
            os.system("apt purge rpcbind")
        else:
            print("RPC Client not removed due to user input.\n")
            line = "RPC Client was not removed due to user input.\n"
            log_changes(line, "services")
    else:
        print("- RPC Client is not installed. No action needed.\n")
        line = "RPC Client is not installed. No action needed.\n"
        log_changes(line, "services")


# ======================================= Running Services Check Section ================================
def check_non_services():
    command = "ss -ltr"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)

    if result.returncode == 0:
        lines = result.stdout.splitlines()

        print(lines[0])

        for index, line in enumerate(lines[1:], start=1):
            print(f"Index {index}: {line}")
            line = "Index" + str(index) + ": " + line + "\n"
            log_changes(line, "services")
    else:
        print(f"Error running command: {result.stderr}")
    print("\n")


def check_non_services_scan():
    command = "ss -ltr"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)

    if result.returncode == 0:
        lines = result.stdout.splitlines()

        print(lines[0])

        for index, line in enumerate(lines[1:], start=1):
            print(f"Index {index}: {line}")
            line = "Index {index}: {line}\n"
            log_changes(line, "services")
    else:
        print(f"Error running command: {result.stderr}")
    print("\n")


# ==================================== U F W  =========================== U F W  ============================ U F W
# ================================ U F W  =========================== U F W  ============================ U F W
# ======================================= U F W  =========================== U F W  ============================ U F
# W  ================================ U F W  =========================== U F W  ============================ U F W
# ================================
def noufwbanner():
    print("CIS recommends installing ufw; proceed with the installation in the configure section.")
    return


def is_ufw_installed():
    try:
        return bool(os.system("command -v ufw >/dev/null 2>&1") == 0)
    except FileNotFoundError:
        noufwbanner()


def ensure_ufw_installed():
    print("""
    
    \033[91m|================= Installing Host Firewall ==================|\033[0m
    
    A firewall utility is required to configure the Linux kernel's netfilter framework via the
    iptables or nftables back-end. The Linux kernel's netfilter framework host-based firewall can
    protect against threats originating from within a corporate network, including malicious
    mobile code and poorly configured software on a host.
    
    Note: Only one firewall utility should be installed and configured. UFW is dependent on
    the iptables package.
    """)

    if not is_ufw_installed():
        var = input(
            "This point onwards, the configurations require the installation of UFW. Do you want to install the Host "
            "firewall? (yes/no):").lower()
        var.lower()

        if var == 'y' or var == 'yes' or var == '':
            os.system("apt install ufw")
            line = "\nUFW INSTALLATION: ok"
            log_changes(line, "ufw")
            print("\n", line)
        elif var == 'n' or var == 'no':
            line = "\nUFW INSTALLATION: no"
            log_changes(line, "ufw")
            print("\n", line)
            exit()
        elif var is None:
            print("Error: Result is None.")
            return
    else:
        line = "\nUFW INSTALLATION:Pre-set"
        log_changes(line, "ufw")
        print("\n", line)


def is_iptables_persistent_installed():
    return bool(os.system("dpkg -s iptables-persistent >/dev/null 2>&1") == 0)


def ensure_iptables_persistent_packages_removed():
    print("""
    
    \033[91m|============== Removing IP-Persistent Tables ================|\033[0m
    
    Running both `ufw` and the services included in the `iptables-persistent` package may lead
    to conflicts.
    """)
    if is_iptables_persistent_installed():
        var = input("Do you want to remove the iptables-persistent packages? (yes/no):").lower()
        var.lower()

        if var == 'y' or var == 'yes' or var == '':
            os.system("apt purge iptables-persistent")
            line = "\nIP-PERSISTENT:removed"
            log_changes(line, "ufw")
            print(line)
        elif var == 'n' or var == 'no':
            line = "\nIP-PERSISTENT: not removed"
            log_changes(line, "ufw")
            print("\n", line)
        elif var is None:
            print("Error: Result is None.")
            return
    else:
        line = "\nIP-PERSISTENT:Pre-set"
        log_changes(line, "ufw")
        print("\n", line)


def is_ufw_enabled():
    try:
        # Run the command to check UFW status
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)

        # Check if the output contains 'Status: active'
        return 'Status: active' in result.stdout
    except FileNotFoundError:
        noufwbanner()
        return False
    except subprocess.CalledProcessError as e:
        # If an error occurs while running the command
        print(f"Error: {e}")
        return False
    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)
    except AttributeError as ve:
        print("Error:", ve)


def enable_firewall_sequence():
    print("""
    
    \033[91m|======================= Enabling UFW ========================|\033[0m
    
    When running `ufw enable` or starting `ufw` via its initscript, `ufw` will flush its chains.
    This is required so `ufw` can maintain a consistent state, but it may drop existing
    connections (e.g., SSH). `ufw` does support adding rules before enabling the firewall.
    The rules will still be flushed, but the SSH port will be open after enabling the
    firewall.
    Please note that once `ufw` is 'enabled', it will not flush the chains when
    adding or removing rules (but will when modifying a rule or changing the default policy).
    By default, `ufw` will prompt when enabling the firewall while running under SSH.
    """)
    if not is_ufw_enabled():
        print("\nUFW is not enabled, do you want to enable it, ")
        var = y_n_choice()
        var.lower()
        if var == 'y' or var == 'yes' or var == '':
            print(
                "\nufw will flush its chains.This is good in maintaining a consistent state, but it may drop existing "
                "connections (eg ssh)")
            os.system("ufw allow proto tcp from any to any port 22")
            # Run the following command to verify that the ufw daemon is enabled:
            print(" \nverifying that the ufw daemon is enabled:")
            os.system("systemctl is-enabled ufw.service")
            # following command to verify that the ufw daemon is active:
            print(" \nverifying that the ufw daemon is active:")
            os.system("systemctl is-active ufw")
            # Run the following command to verify ufw is active
            print(" \nverifying ufw is active:")
            os.system("ufw status")
            # following command to unmask the ufw daemon
            print("\nunmasking ufw daemon:")
            os.system("systemctl unmask ufw.service")
            # following command to enable and start the ufw daemon:
            print("\nenabling and starting the ufw daemon:")
            os.system("systemctl --now enable ufw.service")
            # following command to enable ufw:
            print("\nEnabling the firewall...")
            os.system("ufw enable")
            line = """\n
    UFW-ENABLING: ok, below commands were executed:
        ufw allow proto tcp from any to any port 22
        systemctl is-enabled ufw.service
        systemctl is-active ufw
        systemctl unmask ufw.service
        systemctl --now enable ufw.service
        ufw enable """
            log_changes(line, "ufw")
            print("\n", line)
        elif var == 'n' or var == 'no':
            line = "\nUFW-ENABLING: no"
            log_changes(line, "ufw")
            print("\nExiting UFW enabling mode... continuing to next configurations")
        elif var is None:
            print("Error: Result is None.")
            return
    else:
        line = "\nUFW-ENABLING: Pre-set"
        log_changes(line, "ufw")
        print("\n", line)


def is_loopback_interface_configured():
    try:
        # Create a list to store unconfigured rules
        unconfigured_rules = []

        # Concatenate rules and statuses into a 2D array
        ufw_rules_and_status = [
            ["ufw allow in on lo", "Anywhere on lo"],
            ["ufw allow out on lo", "ALLOW OUT   Anywhere on lo"],
            ["ufw deny in from 127.0.0.0/8", "DENY        127.0.0.0/8 "],
            ["ufw deny in from ::1", "DENY        ::1"]
        ]

        # Get UFW status
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)

        # Check for unconfigured rules
        for rule, status in ufw_rules_and_status:
            if status not in result.stdout:
                unconfigured_rules.append(rule)

        # Print results
        if not unconfigured_rules:
            print("All loopback rules are configured.")
            return True
        else:
            print("\033[91m\U000026D4The following Loopback rules are not configured:\U000026D4")
            for unconfigured_rule in unconfigured_rules:
                print("\033[33m", unconfigured_rule, "\033[0m")
            return False
    except FileNotFoundError:
        noufwbanner()
    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)
    except AttributeError as ve:
        print("Error:", ve)


def ensure_loopback_configured():
    try:
        print("""
        
    \033[91m|============ Configuring the Loopback Interface =============|\033[0m
    
    Loopback traffic is generated between processes on the machine and is typically critical to
    the operation of the system. The loopback interface is the only place that loopback network
    (127.0.0.0/8 for IPv4 and ::1/128 for IPv6) traffic should be seen. All other interfaces
    should ignore traffic on this network as an anti-spoofing measure.
    """)
        if not is_loopback_interface_configured():
            print("\nAll loopback interfaces are not configured, do you want to configure them, ")
            var = y_n_choice()
            var.lower()
            if var == 'y' or var == 'yes' or var == '':
                line = """\n
    LOOPBACK-INTERFACE: ok, below commands were executed:
        ufw allow in on lo
        ufw allow out on lo
        ufw deny in from 127.0.0.0/8
        ufw deny in from ::1
                    
                """
                log_changes(line, "ufw")
                print("\nEnabling configurations on lo interfaces...")
                os.system("ufw allow in on lo")
                os.system("ufw allow out on lo")
                os.system("ufw deny in from 127.0.0.0/8")
                os.system("ufw deny in from ::1")
            elif var == 'n' or var == 'no':
                line = "\nLOOPBACK-INTERFACE: no"
                log_changes(line, "ufw")
                print("\n", line)
            elif var is None:
                print("Error: Result is None.")
                return
        else:
            line = "\nLOOPBACK-INTERFACE: Pre-set"
            log_changes(line, "ufw")
            print("\n", line)
    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)
    except AttributeError as ve:
        print("Error:", ve)
    except FileNotFoundError:
        noufwbanner()


def is_ufw_outbound_connections_configured():
    try:
        result = subprocess.run("ufw status", shell=True, capture_output=True, text=True)
        if "Anywhere on all" in result.stdout:
            print("The following outbound rule is configured: ufw allow out on all")
            return True
        else:
            print("\033[91m\U000026D4The following outbound rule is not configured: ufw allow out on all\U000026D4")
            return False
    except FileNotFoundError:
        noufwbanner()
    except subprocess.CalledProcessError as e:
        print("Error:", e)
        return False
    except Exception as e:
        print("Error:", e)
        return False


def ensure_ufw_outbound_connections():
    print("""
        
    \033[91m|========= Configuring UFW Outbound Connections ==========|\033[0m
    
    If rules are not in place for new outbound connections, all packets will be dropped by the
    default policy, preventing network usage.
    
    Do you want to configure your ufw outbound connections if this set of rules are not in place 
    for new outbound connections all packets will be dropped by the default policy preventing network usage.,""")
    if not is_ufw_outbound_connections_configured():
        var = y_n_choice()
        var.lower()
        if var == 'y' or var == 'yes' or var == '':
            # var = input("\n PLease verify all the rules whether it matches all the site policies")
            print("\n implementing a policy to allow all outbound connections on all interfaces:")
            line = """\n
    OUTBOUND-RULES: ok, below command was executed:
        ufw allow out on all
            """
            log_changes(line, "ufw")
            os.system("ufw allow out on all")
            print("\nConfiguration successful ...")

        elif var == 'n' or var == 'no':
            line = "\nOUTBOUND-RULES: no"
            log_changes(line, "ufw")
            print(line)
        elif var is None:
            print("Error: Result is None.")
            return
    else:
        line = "\nOUTBOUND-RULES:Pre-set"
        log_changes(line, "ufw")
        print("\n", line)


def get_validate_allow_deny():
    while True:
        try:
            allw_dny = input("Enter rule (allow or deny): ").lower()
            if allw_dny not in ['allow', 'deny']:
                raise ValueError("Invalid rule. Please enter either 'allow' or 'deny'.")
            elif allw_dny is None:
                print("Error: Result is None.")
                return
            return allw_dny
        except ValueError as ve:
            print("Error:", ve)
        except TypeError as ve:
            print("Error:", ve)
        except AttributeError as ve:
            print("Error:", ve)


def validate_octet(value):
    return 0 <= int(value) <= 255


def validate_network_address(address_parts):
    return all(validate_octet(part) for part in address_parts)


def construct_network_address():
    while True:
        try:
            netadd = input("Enter network address (in the format xxx.xxx.xxx.xxx): ")
            address_parts = netadd.split('.')
            # Use a regular expression to check if the input matches the expected format
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', netadd) or not validate_network_address(
                    address_parts):
                raise ValueError(
                    "Invalid network address format or out-of-range values. Please use xxx.xxx.xxx.xxx format.")
            elif netadd is None:
                print("Error: Result is None.")
                return
            return netadd
        except ValueError as ve:
            print("Error:", ve)
        except TypeError as ve:
            print("Error:", ve)
        except AttributeError as ve:
            print("Error:", ve)


def get__validate_protocol():
    while True:
        try:
            proto = input("Enter protocol (tcp or udp): ").lower()
            if proto not in ['tcp', 'udp']:
                raise ValueError("Invalid protocol. Please enter either 'tcp' or 'udp'.")
            elif proto is None:
                print("Error: Result is None.")
                return
            return proto
        except ValueError as ve:
            print("Error:", ve)
        except TypeError as ve:
            print("Error:", ve)
        except AttributeError as ve:
            print("Error:", ve)


def get_validate_address_mask():
    while True:
        try:
            mask = int(input("Enter the whole number value of the subnet mask (16-32): ").lower())
            if 16 <= mask <= 32:
                return str(mask)
            elif mask is None:
                print("Error: Result is None.")
                return
            else:
                raise ValueError("\nInvalid subnet mask. Please enter a value between 16 and 32.")
        except ValueError as ve:
            print("\nError:", ve)


def get_ports_as_a_list(script_path):
    result = subprocess.run(['bash', script_path], capture_output=True, text=True)
    if result.returncode == 0:
        # If the script ran successfully, print the output
        # getting numbers from string
        temp = re.findall(r'\d+', result.stdout)
        ports_list = list(map(int, temp))
        print("Open ports with no FW rule")
        for i in range(0, len(ports_list)):
            print(i, ':', ports_list[i])
        return ports_list

    else:
        # If there was an error, print the error message
        print("Error:")
        print(result.stderr)


def input_port_number(script_path):
    while True:
        try:
            ports_list = get_ports_as_a_list(script_path)
            p_no = int(input("Enter the index number of the port to be configured:"))

            # Check if the user pressed Cancel

            if 0 <= p_no <= len(ports_list) - 1:
                port_number = ports_list[p_no]
                return str(port_number)
            elif p_no is None:
                print("Error: Result is None.")
                return
            else:
                raise ValueError(f"\nInvalid Index Number. Please enter a value between 0 and {len(ports_list) - 1}")
        except ValueError as ve:
            print("Error:", ve)
        except TypeError as ve:
            print("Error:", ve)
        except AttributeError as ve:
            print("Error:", ve)


def ensure_rules_on_ports(script_path):
    print("""
    \033[91m|=== Configuring Firewall Rules for All Open Ports ===|\033[0m
    
    To reduce the attack surface of a system, all services and ports should be blocked unless required.
    Your configuration will follow this format:
        ufw allow from 192.168.1.0/24 to any proto tcp port 443
    
    Do you want to continue configuring firewall rules for a port [Y/n]: """)
    var = y_n_choice()
    if var == 'y' or var == 'yes' or var == '':
        port_number = input_port_number(script_path)
        allow = get_validate_allow_deny()
        netad = construct_network_address()
        mask = get_validate_address_mask()
        proto = get__validate_protocol()
        rule = ("ufw " + allow + " from " + netad + "/" + mask + " to any proto " + proto + " port " + str(port_number))
        line = ("\nPORT-RULES: \n: " + str(rule))
        log_changes(line, "ufw")
        os.system(rule)
        input("\nHit enter to continue [enter]: ")
        ensure_rules_on_ports(script_path)
    elif var == 'n' or var == 'no':
        line = "\nPORT-RULES: no"
        log_changes(line, "ufw")
        print("Skipping firewall rule configuration on ports...")
    elif var is None:
        print("Error: Result is None.")
        return


def is_default_deny_policy():
    # check if to deny policies are Pre-set

    return bool(os.system(
        "ufw status verbose | grep 'Default: deny (incoming), deny (outgoing), deny (routed)' >/dev/null 2>&1") == 0)


def ensure_default_deny_policy():
    try:
        print("""
        
    \033[91m|================= Default Port Deny Policy ==================|\033[0m
    
    Any port and protocol not explicitly allowed will be blocked.
    Do you want to configure the default deny policy? [Y/n]: """)
        is_default_deny_policy()
        var = y_n_choice()
        var.lower()
        if var == 'y' or var == 'yes' or var == '':
            print("remediation process...")
            print("\n allowing Git...")
            os.system("ufw allow git")
            print("\nallowing http in...")
            os.system("ufw allow in http")
            print("\nallowing http out...")
            os.system("ufw allow out http")
            print("\nallowing https in...")
            os.system("ufw allow in https")
            print("\nallowing https out...")
            os.system("ufw allow out https")
            print("\nallowing port 53 out...")
            os.system("ufw allow out 53")
            print("\nallowing ufw logging on...")
            os.system("ufw logging on")
            print("\ndenying incoming by default...")
            os.system("ufw default deny incoming")
            print("\ndenying outgoing by default...")
            os.system("ufw default deny outgoing")
            print("\ndenying default routing...")
            os.system("ufw default deny routed")
            line = """\n
    DEFAULT-DENY-POLICY: ok, below commands were executed,
        ufw allow git
        ufw allow in http
        ufw allow out http
        ufw allow in https
        ufw allow out https
        ufw allow out 53
        ufw logging on
        ufw default deny incoming
        ufw default deny outgoing
        ufw default deny routed
            """
            log_changes(line, "ufw")
        elif var == 'n' or var == 'no':
            line = "\n\U000026D4DEFAULT-DENY-POLICY: no\U000026D4"
            log_changes(line, "ufw")
            print("\nexiting port deny policy...")
        elif var is None:
            print("Error: Result is None.")
            return
    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)
    except AttributeError as ve:
        print("Error:", ve)


def ufw_scan():
    try:
        print("""
        
    \033[91m|================ Scanning UFW on your system ================|\033[0m""")
        # Check if UFW is installed
        # time.sleep(1)
        if is_ufw_installed():
            print("UFW is installed.")
        else:
            print("\033[91m\U000026D4UFW is not installed.\U000026D4\033[0m")
        # time.sleep(1)
        if is_iptables_persistent_installed():
            print("\033[91m\U000026D4Iptables-persistent packages are not removed.\U000026D4\033[0m")
        else:
            print("Iptables-persistent packages are removed.")
        # time.sleep(1)
        if is_ufw_enabled():
            print("UFW is enabled.")
        else:
            print("\033[91m\U000026D4UFW is not enabled.\U000026D4\033[0m")
        # time.sleep(1)
        if is_default_deny_policy():
            print("Default deny policy is configured.")
        else:
            print("\033[91m\U000026D4Default deny policy is not configured.\U000026D4\033[0m")
        # time.sleep(1)
        is_loopback_interface_configured()
        # time.sleep(1)
        if is_default_deny_policy():
            print("Default deny policy is configured.")
        is_ufw_outbound_connections_configured()


    except FileNotFoundError:
        noufwbanner()
    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)
    except AttributeError as ve:
        print("Error:", ve)


def ufw_configure():
    try:
        ensure_ufw_installed()
        # time.sleep(1)
        ensure_iptables_persistent_packages_removed()
        # time.sleep(1)
        enable_firewall_sequence()
        # time.sleep(1)
        # ensure_rules_on_ports_banner()
        script_path = 'ufwropnprts.sh'
        ensure_rules_on_ports(script_path)
        # time.sleep(1)
        ensure_default_deny_policy()
        # time.sleep(1)
        ensure_loopback_configured()
        # time.sleep(1)
        ensure_ufw_outbound_connections()
        # time.sleep(1)
        print("""
        
    \033[91m|============= Firewall configurations Complete ==============|\033[0m""")

    except FileNotFoundError:
        noufwbanner()
    except KeyboardInterrupt:
        print("\n\nExited unexpectedly...")


# ======================= PAM ======================= PAM ============================ PAM =======================
# PAM ============================== PAM ======================= PAM ============================ PAM
# ======================= PAM =======================


def check_package_installed(package_name):
    result = subprocess.run(['dpkg', '-s', package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    package_installed = result.returncode == 0

    if package_installed:
        print(f"{package_name} is already installed.")
        line = f"\n- {package_name} Package is already installed on this machine.\n"
        log_changes(line, "pam")
    else:
        print(f"{package_name} is not installed.")

    return package_installed


def install_package():
    package_name = 'libpam-pwquality'

    if not check_package_installed(package_name):
        while True:
            response = input("libpam-pwquality package needs to be installed. Would you like to proceed (Y/N)? ")
            if response.lower() == 'y':
                print("Installing libpam-pwquality Package now...")
                subprocess.run(['sudo', 'apt', 'install', package_name], check=True)
                print("Installation of libpam-pwquality is complete.")
                line = "\n1- libpam-pwquality Package was installed Successfully on this machine.\n"
                log_changes(line, "pam")
                break
            elif response.lower() == 'n':
                print("libpam-pwquality Package was not installed.")
                line = "\n1- libpam-pwquality Package was NOT installed on this machine.\n"
                log_changes(line, "pam")
                break
            else:
                print("Invalid Choice, Please try again")


def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except IOError as e:
        return []


def write_file(file_path, lines):
    try:
        with open(file_path, 'w') as file:
            file.writelines(lines)
    except IOError as e:
        print(f"Error writing to {file_path}: {e}")
        exit(1)


def check_pwquality_config():
    lines = read_file('/etc/security/pwquality.conf')
    minlen_value = 0
    minclass_value = 0

    for line in lines:
        if 'minlen' in line and not line.startswith('#'):
            try:
                minlen_value = int(line.split('=')[1].strip())
            except ValueError:
                pass
        elif 'minclass' in line and not line.startswith('#'):
            try:
                minclass_value = int(line.split('=')[1].strip())
            except ValueError:
                pass

    if minlen_value < 14 or minclass_value < 4:
        print("=== Warning: the current minimum length and password complexity do NOT meet requirements ===")
        return False
    else:
        print("The current password length and complexity meet requirements. No changes are needed.")
        return True


def apply_pwquality_config():
    need_to_change = not check_pwquality_config()

    if need_to_change:
        while True:
            response = input("Would you like to apply the recommended changes (Y/N)? ")
            if response.lower() == 'y':
                apply_pwquality(14, 4)
                print("Updated pwquality.conf with minimum length=14 and complexity=4.")
                line = "\n2- The password length and complexity were updated to meet the requirements.\n"
                log_changes(line, "pam")
                break
            elif response.lower() == 'n':
                print("Password requirements were not changed. No changes were made.")
                line = "\n2- The password length and complexity were NOT updated to meet the requirements.\n"
                log_changes(line, "pam")
                break
            else:
                print("Invalid Choice, Please try again")


def apply_pwquality(minlen, minclass):
    lines = read_file('/etc/security/pwquality.conf')
    with open('/etc/security/pwquality.conf', 'w') as file:
        for line in lines:
            if 'minlen' in line:
                file.write(f"minlen = {minlen}\n")
            elif 'minclass' in line:
                file.write(f"minclass = {minclass}\n")
            else:
                file.write(line)


def check_common_password():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pam_pwquality_line = "password requisite pam_pwquality.so retry=3"

    if pam_pwquality_line.strip() in [line.strip() for line in lines]:
        print("Password Checking module pam_pwquality.so is already enabled.")
        line = "\n3- The Password checking module was already enabled on this machine.\n"
        log_changes(line, "pam")
        return False
    else:
        print("Password Checking module pam_pwquality.so is NOT enabled.")
        line = "\n3- The Password checking module pam_pwquality.so is NOT enabled for this machine.\n"
        log_changes(line, "pam")
        return True


def apply_common_password():
    need_update = check_common_password()

    if need_update:
        response = input("Would you like to enable the password checking module pam_pwquality.so? Y/N: ")
        if response.lower() == 'y':
            common_password_path = '/etc/pam.d/common-password'
            lines = read_file(common_password_path)
            pam_pwquality_line = "password requisite pam_pwquality.so retry=3\n"

            insert_position = 25
            if len(lines) >= insert_position:
                lines.insert(insert_position, pam_pwquality_line)
            else:
                lines.append(pam_pwquality_line)

            write_file(common_password_path, lines)
            print("Password checking module has been enabled successfully.")
            line = "\n3- The password checking module pam_pwquality.so was enabled.\n"
            log_changes(line, "pam")
        elif response.lower() == 'n':
            print("Password checking module was NOT enabled.")
            line = '\n3- The password checking module pam_pwquality.so was NOT enabled after the prompt.\n'
            log_changes(line, "pam")
        else:
            print("Invalid Choice, Please try again")


def check_faillock_config():
    common_auth_path = '/etc/pam.d/common-auth'
    lines = read_file(common_auth_path)

    if any('pam_faillock.so' in line for line in lines):
        print("Password lockouts are already configured. No changes are needed.")
        line = "\n4- Password Lockouts were already configured on this machine. No changes were made.\n"
        log_changes(line, "pam")
        return True
    else:
        print("== Warning: Password Lockouts are currently NOT configured.==")
        line = "\n4- Password lockouts are NOT configured for this machine.\n"
        log_changes(line, "pam")
        return False


def apply_faillock_config():
    common_auth_path = '/etc/pam.d/common-auth'
    lines = read_file(common_auth_path)

    while True:
        response = input("Would you like to configure password lockouts for your machine? Y/N: ")
        if response.lower() == 'y':
            configure_faillock(common_auth_path, lines)
            print("Password lockouts have been configured successfully.")
            line = '\n4- Password lockouts were configured for this machine.\n'
            log_changes(line, "pam")
            break
        elif response.lower() == 'n':
            print("Password Lockouts were NOT configured. No changes were made.")
            line = "\n4- Password lockouts were NOT configured for this machine.\n"
            log_changes(line, "pam")
            break
        else:
            print("Invalid Choice, Please try again")


def configure_faillock(file_path, lines):
    faillock_line = "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900\n"
    lines.append(faillock_line)
    write_file(file_path, lines)


def check_pwhistory_config():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pwhistory_line = "password required pam_pwhistory.so remember=5\n"

    if pwhistory_line.strip() in [line.strip() for line in lines]:
        print("Password Reuse Limit is already configured. No changes are needed.")
        line = (
            "\n5- The Required password reuse limit was already configured on this machine. No changes were made.\n")
        log_changes(line, "pam")
        return False
    else:
        print("== Warning: Password Reuse Limit is currently NOT configured ==")
        line = "\n5- Password reuse limit is NOT configured for this machine.\n"
        log_changes(line, "pam")
        return True


# changes made in /etc/pam.d/common-password
def apply_pwhistory_config():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pwhistory_line = "password required pam_pwhistory.so remember=5\n"

    need_update = check_pwhistory_config()
    if need_update:
        while True:
            response = input("Would you like to configure a Password Reuse Limit ? Y/N: ")
            if response.lower() == 'y':
                insert_position = 25
                if len(lines) >= insert_position:
                    lines.insert(insert_position, pwhistory_line + "\n")
                else:
                    lines.append(pwhistory_line + "\n")
                write_file(common_password_path, lines)
                print("Password Reuse limit is configured to refuse the past 5 passwords.")
                line = (
                    "\n5- Password reuse limit has been configured on this machine to reject the last 5 passwords of "
                    "a user.\n")
                log_changes(line, "pam")
                break
            elif response.lower() == 'n':
                print("Password Reuse limit was NOT configured. No changes were made.")
                line = "\n5- Password reuse limit was NOT configured on this machine.\n"
                log_changes(line, "pam")
                break
            else:
                print("Invalid Choice, Please try again")


# Changes are made in the /etc/pam.d/common-password file
def check_hashing_config():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    sha512_line = "password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512\n"

    sha512_present = any("pam_unix.so" in line and "sha512" in line for line in lines)

    if sha512_present:
        print("The current password hashing algorithm meets requirements. No changes are needed.")
        line = "\n6- The current password hashing algorithm meets standards. No changes were made.\n"
        log_changes(line, "pam")
        return False
    else:
        print("== Warning: The current password hashing algorithm does NOT meet the requirements. ==")
        line = "\n6- The current password hashing algorithm does NOT meet standards.\n"
        log_changes(line, "pam")
        return True


def apply_hashing_config():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    sha512_line = "password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512\n"

    need_update = check_hashing_config()
    current_line_index = next((index for index, line in enumerate(lines) if "pam_unix.so" in line), None)

    if need_update:
        while True:
            response = input("Would you like to apply SHA512 hashing? Y/N: ")
            if response.lower() == 'y':
                if current_line_index is not None:
                    lines[current_line_index] = sha512_line
                    write_file(common_password_path, lines)
                    print("Password hashing algorithm has been changed successfully.")
                    line = "\n6- Password hashing algorithm was changed to SHA512 to meet standards.\n"
                    log_changes(line, "pam")
                    break
                else:
                    print("Line not found in the file")
                    break
            elif response.lower() == 'n':
                print("Password hashing algorithm did NOT change. No changes were made.")
                line = ("\n6- Password hashing algorithm was NOT changed to SHA512 and currently does not meet "
                        "standards.\n")
                log_changes(line, "pam")
                break
            else:
                print("Invalid Choice, Please try again")


def check_encrypt_method():
    login_defs_path = '/etc/login.defs'
    lines = read_file(login_defs_path)
    encrypt_method_line_prefix = "ENCRYPT_METHOD"
    sha512_line = f"{encrypt_method_line_prefix} SHA512"

    if any(sha512_line in line for line in lines):
        print("The default password encryption algorithm meets requirements.")
        line = "\n7- The Default password encryption algorithm meets standards. No changes were made.\n"
        log_changes(line, "pam")
        return False
    else:
        print("== Warning: the default password encryption algorithm does NOT meet requirements. ==")
        return True


# changes are made in the /etc/login.defs file
def apply_encrypt_method():
    login_defs_path = '/etc/login.defs'
    lines = read_file(login_defs_path)
    encrypt_method_line_prefix = "ENCRYPT_METHOD"
    sha512_line = f"{encrypt_method_line_prefix} SHA512"

    need_update = check_encrypt_method()

    if need_update:
        while True:
            response = input("Would you like to change it to SHA512? Y/N: ")
            if response.lower() == 'y':
                lines = [line.replace(line, sha512_line + "\n") if encrypt_method_line_prefix in line else line for line
                         in lines]
                write_file(login_defs_path, lines)
                print("Default password encryption method has been updated successfully.")
                line = "\n7- Password encryption method was updated on this machine to meet standards.\n"
                log_changes(line, "pam")
                break
            elif response.lower() == 'n':
                print("Password encryption method was NOT updated. No changes were made.")
                line = (
                    "\n7- Password encryption method was NOT updated on this machine and currently does not meet "
                    "standards.\n")
                log_changes(line, "pam")
                break
            else:
                print("Invalid Choice, Please try again")


def check_users_hashing():
    shadow_path = '/etc/shadow'
    lines = read_file(shadow_path)

    users_without_sha512 = []
    for line in lines:
        if re.match(r'^[^:]+:\$6\$', line):
            continue
        user = line.split(':')[0]
        if re.match(r'^[^:]+:[!*]', line):
            continue
        users_without_sha512.append(user)

    if not users_without_sha512:
        print("All users have SHA512 password hashing algorithm. No changes are needed.")
    else:
        print("== Warning: the following Users are Using OUTDATED Password Hashing Algorithms ==")
        for user in users_without_sha512:
            print(user)

    return users_without_sha512


def apply_hashing_changes(users_without_sha512):
    if users_without_sha512:
        response = input("Would you like to expire the passwords for the users listed above? (Recommended) Y/N? ")
        while response.lower() not in ['y', 'n']:
            print("Invalid Choice, Please try again")
            response = input("Would you like to expire the passwords for the users listed above? (Recommended) Y/N? ")

        if response.lower() == 'y':
            for user in users_without_sha512:
                subprocess.run(['sudo', 'passwd', '-e', user])
            print("All Passwords for the listed users have been expired Successfully.")
        elif response.lower() == 'n':
            print("User Passwords were NOT expired. No changes were made.")
    else:
        print("No users with outdated password hashing algorithms. No action required.")


def pam_scan():
    try:
        print("""
        
    \033[91m|=============== Scanning PAM on your system ==============|\033[0m""")

        package_name = 'libpam-pwquality'
        print("\n***// Verifying if libpam-pwquality Package is Installed //***")
        check_package_installed(package_name)
        # time.sleep(5)
        print("\n***// Checking Current Password Requirements //***")
        check_pwquality_config()
        # time.sleep(5)
        print("\n***// Verifying if Password Checking Module is Enabled //***")
        check_common_password()
        # time.sleep(5)
        print("\n***// Checking if Password Lockout Policy is Enforced //***")
        check_faillock_config()
        # time.sleep(5
        print("\n***// Configuring a Password Reuse Limit //***")
        check_pwhistory_config()
        # time.sleep(5)
        print("\n***// Verifying & Updating Password Hashing Algorithm //***")
        check_hashing_config()
        # time.sleep(5)
        print("\n***// Verifying & Updating Default Password Encryption Method //***")
        check_encrypt_method()
        # time.sleep(5)
        print("\n***// Auditing for Outdated Password Hashing Algorithms //***")
        check_users_hashing()

    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)


def pam_configure():
    try:
        print("""
    
        \033[91m|================ Configuring PAM on your system ================|\033[0m""")

        print("\n***// Verifying if libpam-pwquality Package is Installed //***")
        install_package()
        # time.sleep(5)

        print("\n***// Checking Current Password Requirements //***")

        apply_pwquality_config()
        # time.sleep(5)

        print("\n***// Verifying if Password Checking Module is Enabled //***")

        apply_common_password()
        # time.sleep(5)

        if not check_faillock_config():
            apply_faillock_config()
        # time.sleep(5)

        print("\n***// Configuring a Password Reuse Limit //***")

        apply_pwhistory_config()
        # time.sleep(5)

        print("\n***// Verifying & Updating Password Hashing Algorithm //***")

        apply_hashing_config()
        # time.sleep(5)

        print("\n***// Verifying & Updating Default Password Encryption Method //***")

        apply_encrypt_method()
        # time.sleep(5)

        print("\n***// Auditing for Outdated Password Hashing Algorithms //***")

        users_with_outdated_hashing = check_users_hashing()
        apply_hashing_changes(users_with_outdated_hashing)
        # time.sleep(5)

    # print("\n***// PAM Audit has been Completed Successfully! A copy of the audit results will be generated to a
    # .log file //***") line=("\n") report_file.close()

    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)


# ======================= Patches & Updates ================================================ Patches & Updates
# ================================================ Patches & Updates ================================================
# Patches & Updates ================================================ Patches & Updates =========================


def patches_configure():
    try:
        print("""
            
    \033[91m|====== Configuring Patches & Updates on your system =========|\033[0m""")
        os.system('python3 patches.py')

    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)


def patches_scan():
    try:
        print("""
            
    \033[91m|====== Scanning Patches & Updates on your system =========|\033[0m""")

    except ValueError as ve:
        print("Error:", ve)
    except TypeError as ve:
        print("Error:", ve)


# ============================================ Main Functions ======================================

def services_scan():
    print("""
        
    \033[91m|============= Scanning Services on your system ==============|\033[0m""")
    # time.sleep(1)
    scan_xserver()
    # time.sleep(1)
    scan_avahi()
    # time.sleep(1)
    scan_dhcp()
    # time.sleep(1)
    scan_ldap()
    # time.sleep(1)
    scan_nfs()
    # time.sleep(1)
    scan_dns()
    # time.sleep(1)
    scan_vsftpd()
    # time.sleep(1)
    scan_http()
    # time.sleep(1)
    scan_imap_pop3()
    # time.sleep(1)
    scan_samba()
    # time.sleep(1)
    scan_squid()
    # time.sleep(1)
    scan_snmp()
    # time.sleep(1)
    scan_nis()
    # time.sleep(1)
    scan_dnsmasq()
    # time.sleep(1)
    scan_rsync()
    # time.sleep(1)
    scan_rsh()
    # time.sleep(1)
    scan_talk()
    # time.sleep(1)
    scan_telnet()
    # time.sleep(1)
    scan_ldap_utils()
    # time.sleep(1)
    scan_rpcbind()
    # time.sleep(1)


def services_configure():
    # time.sleep(1)
    purge_xserver()
    # time.sleep(1)
    purge_avahi()
    # time.sleep(1)
    purge_dhcp()
    # time.sleep(1)
    purge_ldap()
    # time.sleep(1)
    purge_nfs()
    # time.sleep(1)
    purge_dns()
    # time.sleep(1)
    purge_vsftpd()
    # time.sleep(1)
    purge_http()
    # time.sleep(1)
    purge_imap_pop3()
    # time.sleep(1)
    purge_samba()
    # time.sleep(1)
    purge_squid()
    # time.sleep(1)
    purge_snmp()
    # time.sleep(1)
    purge_nis()
    # time.sleep(1)
    purge_dnsmasq()
    # time.sleep(1)
    purge_rsync()
    # time.sleep(1)
    purge_rsh()
    # time.sleep(1)
    purge_talk()
    # time.sleep(1)
    purge_telnet()
    # time.sleep(1)
    purge_ldap_utils()
    # time.sleep(1)
    purge_rpcbind()
    # time.sleep(1)


def running_services_action():
    # runningservices_output_head()
    # time.sleep(1)
    check_non_services()


def scan_running_services_action():
    # scan_runningservices_output_head()
    # time.sleep(1)
    check_non_services_scan()


def services_purge_main():
    services_configure()
    running_services_action()


def services_scan_main():
    services_scan()
    scan_running_services_action()


def scan_all_benchmarks():
    services_scan_main()
    ufw_scan()
    pam_scan()
    patches_scan()
    # time.sleep(1)


def configure_all_benchmarks():
    services_purge_main()
    log_category("services")
    ufw_configure()
    log_category("ufw")
    pam_configure()
    log_category("pam")
    patches_configure()
    log_category("patches")
    time.sleep(1)
    # time.sleep(1)


def home_banner():
    #clear_screen()
    choice = input("""
    |==\U0001F3E0======= CIS Compliance Suite ====================|

    Please choose one of the following options:
    1 - Scan for compliance.
    2 - Conduct Direct Configurations.
    e - Exit the Script
    
    Enter your choice: """)
    if choice.lower() == "e":
        print("\nYou have exited the script :( \n")
        exit()

    else:
        return choice


def home_main():
    while True:
        try:
            choice = home_banner()
            if choice == "1":
                if get_confirmation("\nYou have chosen System Scanning. Are you Sure?"):
                    scan_option()
                    return True
            elif choice == "2":
                if get_confirmation("\nYou have chosen to Configure the system. Are you Sure?"):
                    configure_option()
                    return True
            elif choice.lower() == "e":
                print("\nYou have exited the script :( \n")
                exit()
            else:
                print(f"{Fore.RED}PLEASE ENTER A VALID INPUT.{Style.RESET_ALL}\n")
        except Exception as e:
            print("Error:", e)


# def configure_option():
#     while True:
#         try:
#             choice = options_for_scanning_or_configuration("configuration")
#             if choice in ("1", "2", "3", "4", "5"):
#                 configure_type = {
#                     "1": "All Benchmarks",
#                     "2": "Special Services",
#                     "3": "Firewall",
#                     "4": "Password Authentication Management",
#                     "5": "Patches & Updates"
#                 }[choice]
#                 if get_confirmation(f"\nYou have chosen {configure_type}. Are you sure?"):
#                     if choice == "1":
#                         configure_all_benchmarks()
#                         control_or_date_log()
#                     elif choice == "2":
#                         services_purge_main()
#                         control_or_date_log()
#                     elif choice == "3":
#                         ufw_configure()
#                         control_or_date_log()
#                     elif choice == "4":
#                         pam_configure()
#                         control_or_date_log()
#                     elif choice == "5":
#                         patches_configure()
#                         control_or_date_log()
#                     elif choice.lower() == "b":
#                         print("\nYou have canceled your action.\n")
#                         return False
#                     input("\nHit enter to continue to the home page: ")
#                     home_main()
#                     return True
#                 else:
#                     print("\nYou have canceled your action.\n")
#                     return False
#             elif choice.lower() == "e":
#                 print("\nYou have exited the script :( \n")
#                 return True
#             else:
#                 print(f"{Fore.RED}PLEASE ENTER A VALID INPUT.{Style.RESET_ALL}\n")
#         except KeyboardInterrupt:
#             print("\n\nExited unexpectedly...")
#         except Exception as e:
#             print("Error:", e)
def configure_option():
    while True:
        try:
            choice = options_for_scanning_or_configuration("configuration")
            if choice in ("1", "2", "3", "4", "5"):
                configure_type = {
                    "1": "All Benchmarks",
                    "2": "Special Services",
                    "3": "Firewall",
                    "4": "Password Authentication Management",
                    "5": "Patches & Updates"
                }[choice]
                if get_confirmation(f"\nYou have chosen {configure_type}. Are you sure?"):
                    if choice == "1":
                        configure_all_benchmarks()
                        # clear_screen()
                        control_or_date_log()
                    elif choice == "2":
                        services_purge_main()
                        log_category("services")
                        # clear_screen()
                        control_or_date_log()
                    elif choice == "3":
                        ufw_configure()
                        log_category("ufw")
                        # clear_screen()
                        control_or_date_log()
                    elif choice == "4":
                        pam_configure()
                        log_category("pam")
                        time.sleep(1)
                        # clear_screen()
                        control_or_date_log()
                    elif choice == "5":
                        patches_configure()
                        log_category("patches")
                        # clear_screen()
                        control_or_date_log()
            elif choice.lower() == "e":
                print("\nYou have exited the script :( \n")
                exit()
            elif choice.lower() == "b":
                print("\nYou have canceled your action.\n")
                home_main()
                return
            else:
                print(
                    f"{Fore.RED}PLEASE ENTER A VALID NUMBER, 'e' to exit, or 'b' to go back to the home page.{Style.RESET_ALL}\n")
        except KeyboardInterrupt:
            print("\n\nExited unexpectedly...")
        except Exception as e:
            print("Error:", e)


#
#
def scan_log(prompt):
    output_filepath = f"scan_log.log"
    with open(output_filepath, 'w') as output_file:
        output_file.writelines(f"{prompt}\n")


def capture_function_output(func):
    output_variable = io.StringIO()

    with redirect_stdout(output_variable):
        result = func()

    printed_output = output_variable.getvalue()

    return result, printed_output


def scan_option():
    while True:
        try:
            choice = options_for_scanning_or_configuration("scan")
            if choice.isdigit() and choice in ("1", "2", "3", "4"):
                scan_functions = {
                    "1": scan_all_benchmarks,
                    "2": services_scan_main,
                    "3": ufw_scan,
                    "4": pam_scan,
                    #"5": patches_scan
                }
                scan_type = {
                    "1": "All Benchmarks",
                    "2": "Special Services",
                    "3": "Firewall",
                    "4": "Password Authentication Management",
                    #"5": "Patches & Updates"
                }[choice]
                if get_confirmation(f"\nYou have chosen {scan_type}. Are you sure?"):
                    captured_result, captured_output = capture_function_output(scan_functions[choice])
                    scan_log(captured_output)
                    print("\nScan successfully completed saved in scan_log.log file !.\n")
                    time.sleep(1)
                    home_main()

            elif choice.lower() == "e":
                print("\nYou have exited the script :( \n")
                exit()
            elif choice.lower() == "b":
                print("\nYou have canceled your action.\n")
                home_main()
                return
            else:
                print(
                    f"{Fore.RED}PLEASE ENTER A VALID NUMBER, 'e' to exit, or 'b' to go back to the home page.{Style.RESET_ALL}\n")
        except KeyboardInterrupt:
            print("\n\nExited unexpectedly...")
        except Exception as e:
            print("Error:", e)


def options_for_scanning_or_configuration(option):
    while True:
        try:
            #clear_screen()
            choice = input(f""" 
    \033[91m|================ Choose an option for {option} ==============|\033[0m
    1 - All Benchmarks
    2 - Special Services
    3 - Firewall
    4 - Password Authentication Management
    5 - Patches & Updates
    b - Go Back
    e - Exit Scan

    Please enter the number of the Scan you wish to conduct: """)
            if choice not in ("1", "2", "3", "4", "5", "b", "e"):
                raise ValueError("Invalid Choice, Please try again")
            else:
                return choice

        except ValueError as ve:
            print(f"Error: {ve}")
        except TypeError as ve:
            print(f"Error: {ve}")
        except AttributeError as ve:
            print(f"Error: {ve}")


def get_confirmation(prompt):
    while True:
        conf_choice = input(f"{prompt} (y/n): ").lower()
        if conf_choice == "y":
            return True
        elif conf_choice == "n":
            print("\nYou have canceled your action.\n")
            return False
        else:
            print("\nPLEASE ENTER A VALID INPUT\n")


def main():
    try:
        banner()
        log_setup()
        home_main()
    except KeyboardInterrupt:
        print("\n\nExited unexpectedly...")
        exit()
    except Exception as e:
        print("Error:", e)


main()

# ============================================ End of Script ======================================
