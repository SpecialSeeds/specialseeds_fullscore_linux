SPECIALSEEDS FULLSCORE LINUX - SPECIALSEEDS 2025
                                                                                                     

(`-')  _  
(OO ).-/  
/ DESCRIPTION
this script hardens a linux system following cis-benchmark style guidelines, with extra measures for 
competition/ctf defense. it modifies kernel params, user accounts, services, permissions, firewalls, 
auditing, and security tooling. 

WARNING: highly invasive — only run on a controlled vm/clone. 


(`-')  _  
(OO ).-/  
/ BACKUPS
- /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow
- /etc/sudoers, /etc/sudoers.d/*
- /etc/ssh/sshd_config, /etc/ssh/ssh_config
- /etc/gdm3/daemon.conf, /etc/lightdm/lightdm.conf
- /etc/audit/auditd.conf, /etc/audit/rules.d/*
- /etc/apt/apt.conf.d/*, /etc/apt/sources.list


(`-')  _  
(OO ).-/  
/ USER & ACCOUNT SECURITY
- prompts for authorized users, admins, and sudoers
- prints unauthorized accounts (manual removal recommended)
- checks and resets weak/default passwords with secure random values
- disables GDM guest and autologin sessions
- locks system accounts and assigns /usr/sbin/nologin
- sets umask in /etc/profile and /etc/bash.bashrc
- enforces in /etc/login.defs:
  * PASS_MAX_DAYS=90
  * PASS_MIN_DAYS=7
  * PASS_WARN_AGE=14
  * FAILLOG_ENAB=yes
  * LOG_OK_LOGINS=yes
  * UMASK=027


(`-')  _  
(OO ).-/  
/ FILESYSTEM & KERNEL MODULES
- blacklists unnecessary filesystems: cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf
- blacklists insecure/removable modules: usb-storage, firewire-sbp2
- blacklists insecure network protocols: dccp, sctp, rds, tipc
- sysctl hardening:
  * kernel.randomize_va_space=2
  * kernel.kptr_restrict=2
  * kernel.dmesg_restrict=1
  * fs.protected_symlinks=1
  * fs.protected_hardlinks=1
  * net.ipv4.conf.all.rp_filter=1
  * net.ipv6.conf.all.disable_ipv6=0
- grub default set with: audit=1, ipv6.enable=1


(`-')  _  
(OO ).-/  
/ APPARMOR
- installs apparmor and apparmor-utils
- enforces all profiles in /etc/apparmor.d
- ensures apparmor=1 security=apparmor kernel boot params


(`-')  _  
(OO ).-/  
/ CRON & AT
- sets 600 perms on /etc/crontab, /etc/cron.*, /etc/anacrontab
- only root in /etc/cron.allow and /etc/at.allow
- deletes /etc/cron.deny and /etc/at.deny


(`-')  _  
(OO ).-/  
/ PAM CONFIG
- configures faillock in /etc/pam.d/common-auth and common-account:
  * deny=5 unlock_time=900
- configures pwquality in /etc/security/pwquality.conf:
  * minlen=14
  * minclass=4
  * maxrepeat=3
  * maxclassrepeat=3
  * maxsequence=3
  * dictcheck=1
  * usercheck=1
- configures pwhistory in /etc/pam.d/common-password:
  * remember=5
  * enforce_for_root
- removes all "nullok" entries
- cracklib fallback settings included
- configures pam faillock (removes deprecated pam_tally2)


(`-')  _  
(OO ).-/  
/ AIDE INTEGRITY
- installs aide
- initializes aide.db
- daily cron job runs "aide check" with logs to /var/log/aide.log


(`-')  _  
(OO ).-/  
/ SYSTEM LIMITS
- /etc/security/limits.conf:
  * * hard core 0
  * * hard nproc 100
  * * hard nofile 100
  * * hard rss 5000
  * * hard cpu 10000
  * * hard fsize 100000
  * * hard maxlogins 10
- disables coredumps in /etc/systemd/coredump.conf


(`-')  _  
(OO ).-/  
/ SERVICES
- disables: avahi, cups, rpcbind, telnet, rsh, vsftpd, bind9, dovecot, postfix, nginx, apache2
- disables bluetooth.service
- enables ufw, fail2ban, auditd, apparmor
- secures chrony (restricts default, disables stepping, enables authentication)
- dbus system.conf tightened


(`-')  _  
(OO ).-/  
/ GDM SECURITY
- login banner text placed in /etc/gdm3/greeter.dconf-defaults
- disables user list in greeter
- locks after 15m idle
- lock delay = 0
- disables removable media automount
- gsettings override locked


(`-')  _  
(OO ).-/  
/ AUDITD
- installs auditd, augenrules
- /etc/audit/auditd.conf:
  * max_log_file=20
  * max_log_file_action=keep_logs
  * space_left_action=email
  * admin_space_left_action=halt
- audit rules:
  * watches /etc/sudoers, /etc/sudoers.d/*
  * watches /var/log/sudo.log
  * execve on chmod, chown, mount, setfacl, usermod, chcon
  * identity: /etc/passwd, shadow, group, gshadow
  * privileged commands: /usr/bin/passwd, su, sudo, etc.
  * network changes: /etc/hosts, /etc/hostname, /etc/resolv.conf
  * login events, session starts
  * file deletion (unlink, rename, rmdir, unlinkat)
  * kernel module load/unload
  * apparmor policy changes
- immutable flag set with -e 2


(`-')  _  
(OO ).-/  
/ SUDO HARDENING
- all sudo I/O logged to /var/log/sudo.log
- Defaults requiretty
- restricts /bin/su to wheel or suusers group


(`-')  _  
(OO ).-/  
/ FIREWALL
- ufw reset
- ufw default deny incoming, deny outgoing
- ufw allow out dns, http, https, ntp
- ufw allow in ssh
- ufw logging high


(`-')  _  
(OO ).-/  
/ SSH HARDENING
- Protocol 2 only
- PermitRootLogin no
- MaxAuthTries 4
- MaxSessions 2
- IgnoreRhosts yes
- HostbasedAuthentication no
- PermitEmptyPasswords no
- ClientAliveInterval 300, ClientAliveCountMax 0
- LoginGraceTime 30
- Ciphers aes256-ctr,aes192-ctr,aes128-ctr
- MACs hmac-sha2-512,hmac-sha2-256
- KexAlgorithms diffie-hellman-group-exchange-sha256
- DisableAgentForwarding yes
- X11Forwarding no
- Banner /etc/issue.net


(`-')  _  
(OO ).-/  
/ MAIL SERVICES
- postfix: 
  * smtpd_helo_required = yes
  * disable_vrfy_command = yes
  * smtpd_recipient_restrictions = reject_invalid_hostname, reject_non_fqdn_sender, reject_unknown_sender_domain
- dovecot:
  * disable_plaintext_auth = yes


(`-')  _  
(OO ).-/  
/ REMOVABLE MEDIA
- blacklist usb-storage in /etc/modprobe.d/blacklist.conf
- /etc/udev/rules.d/99-disable-usb.rules blocks new usb devices


(`-')  _  
(OO ).-/  
/ MEDIA FILE HANDLING
- option to remove mp3, mp4, mkv, avi, wav, mov, flac
- option to remove jpg/jpeg/bmp/tiff > 500kb
- keeps ico/png/svg/gif and small system jpgs


(`-')  _  
(OO ).-/  
/ FILE PERMISSIONS
- chmod 644 /etc/passwd
- chmod 640 /etc/shadow
- chmod 440 /etc/sudoers
- chmod 600 /etc/ssh/sshd_config
- fixes grub.cfg perms
- finds world-writable files and removes +w
- finds suid/sgid binaries and reports
- removes .rhosts, .netrc in all home dirs
- secures hidden files and dirs in home (700 perms)


(`-')  _  
(OO ).-/  
/ AUTOMATIC UPDATES
- installs unattended-upgrades
- /etc/apt/apt.conf.d/20auto-upgrades → check=1, download=1, install=1
- logs at /var/log/unattended-upgrades/unattended-upgrades.log


(`-')  _  
(OO ).-/  
/ DANGEROUS PACKAGES REMOVED
- removes: hydra, john, nmap, netcat, nc, hping3, wireshark, tcpdump, aircrack-ng, ophcrack, dsniff, ettercap, kismet, sqlmap, nikto, wpscan, metasploit


(`-')  _  
(OO ).-/  
/ SECURITY TOOLS INSTALLED
- fail2ban
- chkrootkit
- rkhunter
- lynis
- clamav
- aide
- auditd
- apparmor
- ufw
- default-jre (for cis-cat lite)


(`-')  _  
(OO ).-/  
/ SYSTEM MAINTENANCE
- removes world-writable perms recursively
- logs unowned files in /var/log/security_hardening.log
- checks for duplicate user and group ids
- chmod 700 on home directories
- cleans temp files


(`-')  _  
(OO ).-/  
/ USAGE
- run as root: bash v3_linux_script.sh
- review forensic questions before launch
- configure interactive prompts carefully
- monitor logs: /var/log/security_hardening.log


(`-')  _  
(OO ).-/  
/ CREDITS
© specialseeds 2025


