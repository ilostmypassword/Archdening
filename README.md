# Archdening
## A basic hardening script for Arch Linux

### Description 

This script is designed to enhance the security of an Arch Linux system by applying various security configurations and parameters. It has been inspired by this article : https://theprivacyguide1.github.io/linux_hardening_guide

Not all the features described in this article have yet been implemented in the script, but will probably be in the future.

If you need more information on the features of this script, or if you'd like to delve deeper into the subject, I strongly advise you to refer to the article.

### Features

- **Kernel Security:**
    - Prevent kernel pointer leaks.
    - Restrict access to kernel logs.
    - Harden BPF JIT compiler.
    - Restrict ptrace usage.
    - Disable kexec.
    - Improve ASLR effectiveness.
    - Disable SysRq key.
    - Restrict unprivileged user namespaces.

- **Network Security:**
    - Blacklist uncommon network protocols.
    - Harden TCP/IP stack.
	   - Enable TCP SYN cookies to protect against SYN flood attacks.
		- Enable RFC 1337 to protect against time-wait assassination.
		- Enable reverse path filtering to prevent IP spoofing.
		- Disable ICMP redirects to prevent malicious redirections.
		- Disable sending ICMP redirects on non-routers.
		- Ignore ICMP echo requests to avoid ping attacks.
	- Disable TCP SACK.

- **PAM Settings:**
    - Restrict `su` to the `wheel` group.
    - Increase password hashing rounds.

- **SSH Configuration:**
    - Disable password authentication, root login and sshd service.

### Important Notes

  - **Backup:** It is highly recommended to backup your system configurations before running the script, because if you encounter issues after applying the changes, you may need to manually revert some configurations or restore from backups.
  - **Passwords:** After the script execution, you should change users's passwords to apply the modifications on the hashing rounds.

### Installation & Usage
  - Clone the repository.
  - `cd Archdening`
  - `chmod +x archdening.sh`
  - `sudo ./archdening.sh`
  - Reboot your system when prompted.
  - After the reboot, change your users's passwords.
