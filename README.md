# Debian 20.04 Compliance

## Project Description

The **Debian 20.04 Compliance** application is designed to harden the Ubuntu 20.04 live server according to the CIS Ubuntu Linux 20.04 benchmark (version 2.0.1 - 06-29-2023). The application focuses on hardening services, UFW (Uncomplicated Firewall), PAM (Pluggable Authentication Modules), software patching, and CLI warning banners.

## Features

- Hardening of system services
- Configuration of UFW
- Strengthening of PAM configurations
- Automated software patching
- CLI warning banners

## Execution

To execute the application, run the following command on the terminal with sudo privilege:

```bash
python3 bluething.py
```

## Usage

- Users interact with the application through the terminal or CLI.
- For Ubuntu 20.04 workstations, a GUI prototype is available and under testing.

## Dependencies

The application requires Dos2unix, which is automatically installed during the application execution.

## Configuration

Users have both automatic and manual configuration options within the script, aligning with the CIS benchmark.

## Examples

Use cases for running the application include hardening company-used Ubuntu live servers for specific purposes, with the flexibility for clients to bypass controls to maintain business operations.

## Testing

To test the application, deploy it on a Ubuntu 20.04 live server using a virtualization platform such as VMware Workstation.

## Contributing

Currently, the project is not open to external contributions.

## License

This project is not released under any specific license.

## Support

For support or bug reporting, there are no specified channels at the moment.

## Acknowledgments

Special thanks to the following projects:

- fernandonaime/debian20.04compliance
- AvinashRa1/ccproject
- shenalsw/script
- Heshan316/CC-Assign2

## Additional Notes

The project is under constant development, addressing identified issues through thorough testing.
