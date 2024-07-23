#!/bin/bash

echo "⧼A⧽⧼r⧽⧼c⧽⧼h⧽⧼d⧽⧼e⧽⧼n⧽⧼i⧽⧼n⧽⧼g⧽"
echo "Created by H3ik0"

separator() {
    echo "------------"
}

apply_config() {
    local file=$1
    local content=$2
    local description=$3

    separator
    echo "[*] Action: $description"
    echo -n "[?] Do you want to apply this configuration? (y/n) "
    read -r response
    if [[ $response == "y" ]]; then
        if echo -e "$content" | sudo tee "$file" > /dev/null; then
            echo "[*] Configuration applied for: $file"
        else
            echo "[!] Error applying configuration for: $file"
        fi
    else
        echo "[->] Configuration skipped for: $file"
    fi
}

apply_sysctl_config() {
    local file=$1
    local content=$2
    local description=$3

    apply_config "/etc/sysctl.d/$file" "$content" "$description"
}

apply_modprobe_config() {
    local file=$1
    local content=$2
    local description=$3

    apply_config "/etc/modprobe.d/$file" "$content" "$description"
}

separator
echo "[*] Starting hardening process..."

# kptr_restrict
apply_sysctl_config "kptr_restrict.conf" "kernel.kptr_restrict=2" \
    "Prevent kernel pointer leaks. This setting helps prevent kernel address leaks via /proc/kallsyms or dmesg."

separator

# dmesg_restrict
apply_sysctl_config "dmesg_restrict.conf" "kernel.dmesg_restrict=1" \
    "Restrict access to kernel logs. This setting blocks users other than root from viewing kernel logs."

separator

# harden_bpf
apply_sysctl_config "harden_bpf.conf" "kernel.unprivileged_bpf_disabled=1\nnet.core.bpf_jit_harden=2" \
    "Harden BPF JIT compiler. This restricts BPF JIT compiler usage to root and enhances its security."

separator

# ptrace_scope
apply_sysctl_config "ptrace_scope.conf" "kernel.yama.ptrace_scope=2" \
    "Restrict ptrace usage. This setting ensures that only processes with CAP_SYS_PTRACE capability can use ptrace, limiting potential attacks."

separator

# kexec
apply_sysctl_config "kexec.conf" "kernel.kexec_load_disabled=1" \
    "Disable kexec. This prevents the replacement of the running kernel, reducing security risks."

separator

# tcp_hardening
apply_sysctl_config "tcp_hardening.conf" "net.ipv4.tcp_syncookies=1\nnet.ipv4.tcp_rfc1337=1\nnet.ipv4.conf.default.rp_filter=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.default.accept_redirects=0\nnet.ipv4.conf.all.secure_redirects=0\nnet.ipv4.conf.default.secure_redirects=0\nnet.ipv6.conf.all.accept_redirects=0\nnet.ipv6.conf.default.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.default.send_redirects=0\nnet.ipv4.icmp_echo_ignore_all=1" \
    "Harden TCP/IP stack and tighten network security options:
    - Enable TCP SYN cookies to protect against SYN flood attacks.
    - Enable RFC 1337 to protect against time-wait assassination.
    - Enable reverse path filtering to prevent IP spoofing.
    - Disable ICMP redirects to prevent malicious redirections.
    - Disable sending ICMP redirects on non-routers.
    - Ignore ICMP echo requests to avoid ping attacks."

separator

# mmap_aslr
apply_sysctl_config "mmap_aslr.conf" "vm.mmap_rnd_bits=32\nvm.mmap_rnd_compat_bits=16" \
    "Improve ASLR effectiveness. This enhances the randomization of memory addresses for mmap."

separator

# sysrq
apply_sysctl_config "sysrq.conf" "kernel.sysrq=0" \
    "Disable the SysRq key. This prevents unprivileged users from accessing dangerous debugging functionalities."

separator

# unprivileged_users_clone
apply_sysctl_config "unprivileged_userns_clone.conf" "kernel.unprivileged_userns_clone=0" \
    "Disable unprivileged user namespaces. This reduces the attack surface for privilege escalation."

separator

# tcp_sack
apply_sysctl_config "tcp_sack.conf" "net.ipv4.tcp_sack=0" \
    "Disable TCP SACK. TCP SACK is commonly exploited and not always necessary."

separator

# Blacklist Uncommon Network Protocols
apply_modprobe_config "uncommon-network-protocols.conf" "install dccp /bin/true\ninstall sctp /bin/true\ninstall rds /bin/true\ninstall tipc /bin/true\ninstall n-hdlc /bin/true\ninstall ax25 /bin/true\ninstall netrom /bin/true\ninstall x25 /bin/true\ninstall rose /bin/true\ninstall decnet /bin/true\ninstall econet /bin/true\ninstall af_802154 /bin/true\ninstall ipx /bin/true\ninstall appletalk /bin/true\ninstall psnap /bin/true\ninstall p8023 /bin/true\ninstall llc /bin/true\ninstall p8022 /bin/true" \
    "Blacklist uncommon network protocols to reduce attack surface by preventing loading of unused and potentially vulnerable network modules."

separator

# Restricting su
echo "[*] Action: Restrict the use of 'su' to users within the 'wheel' group."
echo -n "[?] Do you want to apply this configuration? (y/n) "
read -r response
if [[ $response == "y" ]]; then
    sudo sed -i '/^#auth.*required.*pam_wheel.so use_uid/s/^#//' /etc/pam.d/su /etc/pam.d/su-l
    echo "[*] Configuration applied: Restricting 'su' to 'wheel' group."
else
    echo "[->] Configuration skipped: Restricting 'su' to 'wheel' group."
fi

separator

# Increase the Number of Hashing Rounds
echo "[*] Action: Increase the number of hashing rounds for password security."
echo -n "[?] Do you want to apply this configuration? (y/n) "
read -r response
if [[ $response == "y" ]]; then
    echo "password required pam_unix.so sha512 shadow nullok rounds=65536" | sudo tee -a /etc/pam.d/passwd > /dev/null
    echo "[*] Configuration applied: Increased hashing rounds."
    echo "[*] You should reset the password for each user to apply the new hashing rounds. Use the command: passwd <username>"
else
    echo "[->] Configuration skipped: Increasing hashing rounds."
fi

separator

# Harden SSH configuration
if [[ -f /etc/ssh/sshd_config ]]; then
    echo "[*] Action: Harden SSH configuration by modifying and disabling the SSH service."
    echo -n "[?] Do you want to apply this configuration? (y/n) "
    read -r response
    if [[ $response == "y" ]]; then
        sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

        sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sudo sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

        sudo systemctl stop sshd
        sudo systemctl disable sshd

        echo "[*] Configuration applied: SSH service has been hardened and disabled."
        echo "[*] To re-enable SSH, use the following commands:"
        echo "    sudo systemctl enable sshd"
        echo "    sudo systemctl start sshd"
    else
        echo "[->] Configuration skipped: SSH hardening."
    fi
else
    echo "[->] SSH configuration file /etc/ssh/sshd_config not found. Skipping SSH hardening."
fi

separator

echo "[*] Reloading sysctl configurations..."
sudo sysctl --system

echo "[*] All configurations have been reloaded. Hardening complete."

separator

echo "[*] After the reboot, you should reset the password for each user to apply the new hashing rounds. Use the command: passwd <username>"
echo "[*] It's recommended to reboot your system to apply all changes."
echo -n "[?] Do you want to reboot now? (y/n) "
read -r response
if [[ $response == "y" ]]; then
    echo "[*] Rebooting now..."
    sudo reboot
else
    echo "[->] Reboot skipped. Please remember to reboot your system later to apply all changes."
fi

separator
