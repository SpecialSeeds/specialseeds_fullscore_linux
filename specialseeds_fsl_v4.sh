#!/bin/bash
#
# linux security hardening script - enhanced version with gdm and comprehensive audit
# based on cyberpatriots stuff and other things i found online
# 
# WARNING: this changes a lot of stuff on your computer
# test it first and make backups

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
NC='\033[0m'

LOG_FILE="/var/log/security_hardening.log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# stuff you can change based on what the readme says
REMOVE_MEDIA_FILES=false           # only set to true if readme says so
DISABLE_FTP=true                   # false if ftp is needed
DISABLE_SSH_ROOT=true              # false if root ssh is needed  
ENABLE_IPV6=false                  # true if ipv6 is needed
REMOVE_GAMES=true                  # usually safe
INSTALL_SECURITY_TOOLS=true        # install scanning stuff
CONFIGURE_GDM=true                 # configure gdm security settings

# user management arrays
AUTHORIZED_USERS=()
AUTHORIZED_ADMINS=()
SUDO_USERS=()
USER_PASSWORDS=()
USER_GROUPS=()
REQUIRED_SERVICES=()
PROHIBITED_SERVICES=()

# check if running as root (bneed to be in root)
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}need to run as root${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}=== linux security script ===${NC}"
echo -e "${PURPLE}*** read the readme and do forensic questions first ***${NC}"
echo "started: $(date)"
echo "log: $LOG_FILE"

# ask if we should keep going
prompt_continue() {
    echo -e "${YELLOW}$1${NC}"
    read -p "continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}stopped${NC}"
        exit 1
    fi
}

# figure out what the readme wants
read_readme_config() {
    echo -e "${BLUE}=== readme and forensic stuff ===${NC}"
    echo -e "${YELLOW}make sure you did:${NC}"
    echo "1. read the readme completely"
    echo "2. answered all forensic questions"
    echo "3. know which users are supposed to be there"
    echo "4. know which services should be running"
    echo "5. note special circumstances (ftp, ssh, ipv6...)"
    
    prompt_continue "did you actually read the readme and do forensics?"
    
    echo -e "${BLUE}service stuff:${NC}"
    read -p "need ftp? (y/N): " ftp_required
    if [[ $ftp_required =~ ^[Yy]$ ]]; then
        DISABLE_FTP=false
    fi
    
    read -p "need root ssh? (y/N): " ssh_root_required
    if [[ $ssh_root_required =~ ^[Yy]$ ]]; then
        DISABLE_SSH_ROOT=false
    fi
    
    read -p "need ipv6? (y/N): " ipv6_required
    if [[ $ipv6_required =~ ^[Yy]$ ]]; then
        ENABLE_IPV6=true
    fi
    
    read -p "configure gdm security? (y/N): " gdm_required
    if [[ $gdm_required =~ ^[Yy]$ ]]; then
        CONFIGURE_GDM=true
    else
        CONFIGURE_GDM=false
    fi
    
    read -p "remove media files? (y/N): " remove_media
    if [[ $remove_media =~ ^[Yy]$ ]]; then
        REMOVE_MEDIA_FILES=true
        echo -e "${RED}WARNING: this will remove music/video files but keep system images${NC}"
        prompt_continue "really remove media files?"
    fi
}

# configure user management - NO REMOVAL PROMPT
configure_user_management() {
    echo -e "${BLUE}=== user management setup ===${NC}"
    echo -e "${YELLOW}configure users based on readme requirements${NC}"
    
    # get authorized users list
    echo -e "${BLUE}authorized users (space separated):${NC}"
    echo "example: john jane bob alice"
    read -p "enter authorized users: " auth_users_input
    if [ -n "$auth_users_input" ]; then
        IFS=' ' read -ra AUTHORIZED_USERS <<< "$auth_users_input"
    fi
    
    # get sudo users list  
    echo -e "${BLUE}sudo users (space separated):${NC}"
    echo "example: john alice"
    read -p "enter sudo users: " sudo_users_input
    if [ -n "$sudo_users_input" ]; then
        IFS=' ' read -ra SUDO_USERS <<< "$sudo_users_input"
    fi
    
    # get admin users list
    echo -e "${BLUE}admin users (space separated):${NC}"
    echo "example: john alice"
    read -p "enter admin users: " admin_users_input
    if [ -n "$admin_users_input" ]; then
        IFS=' ' read -ra AUTHORIZED_ADMINS <<< "$admin_users_input"
    fi
    
    # add users to groups section
    echo -e "${BLUE}=== add users to groups ===${NC}"
    echo "add users to specific groups (format: user:group)"
    echo "example: sybella:pioneers bob:developers alice:testers"
    echo "leave blank to skip"
    read -p "enter user:group pairs (space separated): " group_input
    
    if [ -n "$group_input" ]; then
        IFS=' ' read -ra USER_GROUPS <<< "$group_input"
    fi
    
    # configure passwords
    echo -e "${BLUE}=== password configuration ===${NC}"
    echo "configure passwords for users (format: user:password)"
    echo "example: john:MySecurePass123! alice:AnotherPass456!"
    echo "leave blank to auto-generate secure passwords"
    read -p "enter user:password pairs (space separated): " password_input
    
    if [ -n "$password_input" ]; then
        IFS=' ' read -ra USER_PASSWORDS <<< "$password_input"
    fi
    
    # show configuration summary
    echo -e "\n${BLUE}user management summary:${NC}"
    echo "authorized users: ${AUTHORIZED_USERS[*]}"
    echo "sudo users: ${SUDO_USERS[*]}"
    echo "admin users: ${AUTHORIZED_ADMINS[*]}"
    echo "group assignments: ${#USER_GROUPS[@]} assignments"
    echo "custom passwords: ${#USER_PASSWORDS[@]} users"
    
    prompt_continue "user configuration looks good?"
}

# backup stuff before we break it
backup_files() {
    echo -e "${BLUE}making backups...${NC}"
    BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # backup important files
    cp /etc/passwd "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/shadow "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/group "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/sudoers "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/lightdm/lightdm.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/gdm3/custom.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/apt/apt.conf.d/ -r "$BACKUP_DIR/" 2>/dev/null || true
    
    # backup gdm and audit configs
    cp /etc/gdm3/greeter.dconf-defaults "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/dconf/profile/gdm "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/dconf/db/gdm.d "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/audit/auditd.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/audit/rules.d/audit.rules "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/audit/rules.d "$BACKUP_DIR/" 2>/dev/null || true
    
    echo "backups at: $BACKUP_DIR"
}

# generate secure password
generate_password() {
    openssl rand -base64 12 | tr -d "=+/" | cut -c1-12
}

# NEW CIS FUNCTION - configure filesystem kernel modules (cis 1.1.1)
configure_filesystem_modules() {
    echo -e "${BLUE}=== configuring filesystem kernel modules (cis 1.1.1) ===${NC}"
    
    # create modprobe configuration directory
    mkdir -p /etc/modprobe.d/
    
    # disable unnecessary filesystem modules
    echo "disabling filesystem modules..."
    FILESYSTEM_MODULES=(
        "cramfs"
        "freevxfs" 
        "hfs"
        "hfsplus"
        "jffs2"
        "overlay"
        "udf"
        "usb-storage"
    )
    
    for module in "${FILESYSTEM_MODULES[@]}"; do
        echo "blacklist $module" >> /etc/modprobe.d/filesystem.conf
        rmmod "$module" 2>/dev/null || true
        echo "disabled module: $module"
    done
    
    echo -e "${GREEN}filesystem modules configured${NC}"
}

# NEW CIS FUNCTION - configure network kernel modules (cis 3.2)
configure_network_modules() {
    echo -e "${BLUE}=== configuring network kernel modules (cis 3.2) ===${NC}"
    
    # disable unnecessary network modules
    echo "disabling network modules..."
    NETWORK_MODULES=(
        "dccp"
        "tipc" 
        "rds"
        "sctp"
    )
    
    for module in "${NETWORK_MODULES[@]}"; do
        echo "blacklist $module" >> /etc/modprobe.d/network.conf
        rmmod "$module" 2>/dev/null || true
        echo "disabled module: $module"
    done
    
    echo -e "${GREEN}network modules configured${NC}"
}

# NEW CIS FUNCTION - enhanced apparmor configuration (cis 1.3.1)
enhanced_apparmor_config() {
    echo -e "${BLUE}=== enhanced apparmor configuration (cis 1.3.1) ===${NC}"
    
    # install apparmor packages
    echo "installing apparmor packages..."
    apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
    
    # enable apparmor in bootloader
    if [ -f /etc/default/grub ]; then
        echo "enabling apparmor in bootloader..."
        # remove existing apparmor parameters and add correct ones
        sed -i 's/apparmor=[^ ]*//g' /etc/default/grub
        sed -i 's/security=[^ ]*//g' /etc/default/grub
        sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor /' /etc/default/grub
        update-grub 2>/dev/null || true
    fi
    
    # enable apparmor service
    systemctl enable apparmor
    systemctl start apparmor
    
    # set profiles to enforce mode
    echo "setting profiles to enforce mode..."
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    
    echo -e "${GREEN}enhanced apparmor configured${NC}"
}

# NEW CIS FUNCTION - configure cron permissions (cis 2.4.1)
configure_cron_permissions() {
    echo -e "${BLUE}=== configuring cron permissions (cis 2.4.1) ===${NC}"
    
    # set proper permissions on cron files
    echo "setting cron file permissions..."
    chmod 600 /etc/crontab 2>/dev/null || true
    chmod 700 /etc/cron.hourly 2>/dev/null || true  
    chmod 700 /etc/cron.daily 2>/dev/null || true
    chmod 700 /etc/cron.weekly 2>/dev/null || true
    chmod 700 /etc/cron.monthly 2>/dev/null || true
    chmod 700 /etc/cron.d 2>/dev/null || true
    
    # configure cron access
    echo "configuring cron access controls..."
    echo "root" > /etc/cron.allow
    rm -f /etc/cron.deny
    chmod 600 /etc/cron.allow
    
    # configure at access  
    echo "root" > /etc/at.allow
    rm -f /etc/at.deny
    chmod 600 /etc/at.allow
    
    echo -e "${GREEN}cron permissions configured${NC}"
}

# RMOVED DEPRECATED PAM_TALLY2
enhanced_pam_configuration() {
    echo -e "${BLUE}=== enhanced pam configuration (cis 5.3) ===${NC}"
    
    # install required pam modules
    echo "installing pam modules..."
    apt-get install -y libpam-pwquality libpam-pwhistory libpam-modules libpam-faillock
    
    # backup existing pam files
    cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup.cis 2>/dev/null || true
    cp /etc/pam.d/common-password /etc/pam.d/common-password.backup.cis 2>/dev/null || true
    cp /etc/pam.d/common-account /etc/pam.d/common-account.backup.cis 2>/dev/null || true
    
    # configure pam_faillock centralized configuration (cis 5.3.3.1)
    echo "configuring pam_faillock centralized settings..."
    cat > /etc/security/faillock.conf << 'EOF'
# faillock configuration for account lockout policy
# deny = number of failed attempts before lockout
deny = 5
# unlock_time = time in seconds before automatic unlock (900 = 15 minutes)
unlock_time = 900
# audit = log failed attempts
audit
# silent = don't display lockout messages to user
silent
# local_users_only = only apply to local users
local_users_only
EOF

    # configure pam_faillock in authentication (cis 5.3. 3.1)
    echo "configuring pam_faillock authentication..."
    cat > /etc/pam.d/common-auth << 'EOF'
#
# /etc/pam.d/common-auth - authentication settings
#
auth    required                        pam_faillock.so preauth
auth    [success=1 default=ignore]      pam_unix.so try_first_pass
auth    [default=die]                   pam_faillock.so authfail
auth    sufficient                      pam_faillock.so authsucc
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
EOF

    # configure account checking FAILLOCK
    echo "configuring pam_faillock account checking..."
    if ! grep -q "pam_faillock.so" /etc/pam.d/common-account; then
        sed -i '1i account required pam_faillock.so' /etc/pam.d/common-account
    fi

    # configure pam_pwquality (cis 5.3.3.2)
    echo "configuring pam_pwquality..."
    cat > /etc/security/pwquality.conf << 'EOF'
# password quality requirements
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxsequence = 3
difok = 7
dictcheck = 1
enforce_for_root
gecoscheck = 1
reject_username
EOF

    # configure pam_pwhistory and pwquality in password settings (cis 5.3.3.3)
    echo "configuring pam_pwhistory and password policies..."    
    cat > /etc/pam.d/common-password << 'EOF'
#
# /etc/pam.d/common-password - password-related modules
#
password    requisite                       pam_pwquality.so retry=3
password    requisite                       pam_pwhistory.so remember=5 use_authtok enforce_for_root
password    [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512
password    requisite                       pam_deny.so
password    required                        pam_permit.so
EOF

    # remove any old pam_tally2 configurations
    echo "removing deprecated pam_tally2 configurations..."
    sed -i '/pam_tally2/d' /etc/pam.d/common-auth 2>/dev/null || true
    sed -i '/pam_tally2/d' /etc/pam.d/common-account 2>/dev/null || true

    # update pam profiles
    echo "updating pam profiles..."
    pam-auth-update --package --force faillock pwquality pwhistory unix 2>/dev/null || true
    
    # verify faillock is working
    echo "verifying faillock configuration..."
    if command -v faillock >/dev/null 2>&1; then
        echo "faillock utility available for managing account locks"
    else
        echo "warning: faillock utility not found, manual lock management may be required"
    fi
    
    echo -e "${GREEN}enhanced pam configuration complete${NC}"
}

# NEW CIS FUNCTION - configure aide file integrity (cis 6.1)
configure_aide_integrity() {
    echo -e "${BLUE}=== configuring aide file integrity (cis 6.1) ===${NC}"
    
    # install aide
    echo "installing aide..."
    apt-get install -y aide aide-common
    
    # initialize aide database
    echo -e "${YELLOW}initializing aide database (this may take several minutes)...${NC}"
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
    
    # configure regular aide checks (cis 6.1.2)
    echo "configuring daily aide checks..."
    cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
/usr/bin/aide --check
EOF
    chmod +x /etc/cron.daily/aide
    
    echo -e "${GREEN}aide file integrity configured${NC}"
}

configure_system_limits() {
    echo -e "${BLUE}=== configuring system resource limits ===${NC}"
    
    # Configure limits.conf for security
    cat > /etc/security/limits.d/99-security.conf << 'EOF'
# Security-focused resource limits

# Limit core dumps
* hard core 0

# Process limits
* hard nproc 10000
* soft nproc 5000

# File descriptor limits
* hard nofile 10000
* soft nofile 5000

# Memory limits (in KB)
* hard rss 1048576
* soft rss 524288

# CPU time limits (in minutes)
* hard cpu 60
* soft cpu 30

# File size limits (in KB)
* hard fsize 1048576
* soft fsize 524288

# Maximum number of logins
* hard maxlogins 3
EOF

    echo -e "${GREEN}system resource limits configured${NC}"
}

# configure additional service hardening
harden_additional_services() {
    echo -e "${BLUE}=== hardening additional services ===${NC}"
    
    # Configure systemd security settings
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/99-security.conf << 'EOF'
[Manager]
# Security settings for systemd
DefaultLimitNOFILE=10000
DefaultLimitNPROC=5000
DefaultLimitCORE=0
DumpCore=no
CrashShell=no
EOF

    # configure chronyd/ntp security if installed
    if command -v chronyd >/dev/null 2>&1; then
        echo "configuring chronyd security..."
        
        # basic chrony security configuration
        if [ -f /etc/chrony/chrony.conf ]; then
            # add security settings if not present
            if ! grep -q "clientloglimit" /etc/chrony/chrony.conf; then
                echo "clientloglimit 100000" >> /etc/chrony/chrony.conf
                echo "noclientlog" >> /etc/chrony/chrony.conf
            fi
        fi
        
        systemctl restart chronyd
    fi
    
    # secure dbus if present
    if [ -f /etc/dbus-1/system.conf ]; then
        # ensure dbus is configured securely
        sed -i 's/<allow_anonymous\/>/<!-- <allow_anonymous\/> -->/' /etc/dbus-1/system.conf 2>/dev/null || true
    fi
    
    echo -e "${GREEN}additional services hardened${NC}"
}






# configure gdm
configure_gdm_security() {
    echo -e "${BLUE}=== configuring gdm security settings ===${NC}"
    
    if [ "$CONFIGURE_GDM" = false ]; then
        echo "skipping gdm configuration"
        return
    fi
    
    # check if gdm is installed
    if ! command -v gdm3 &> /dev/null && ! command -v gdm &> /dev/null; then
        echo "gdm not installed, skipping configuration"
        return
    fi
    
    echo "configuring gdm login security..."
    
    # create gdm profile directories
    mkdir -p /etc/dconf/profile
    mkdir -p /etc/dconf/db/gdm.d
    mkdir -p /etc/dconf/db/gdm.d/locks
    
    # create gdm profile
    cat > /etc/dconf/profile/gdm << 'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF
    
    # configure login banner
    echo "setting up login banner..."
    cat > /etc/dconf/db/gdm.d/01-banner-message << 'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='WARNING: unauthorized access prohibited. all activities monitored and logged.'
EOF
    
    # disable user list
    echo "disabling user list display..."
    cat > /etc/dconf/db/gdm.d/02-disable-user-list << 'EOF'
[org/gnome/login-screen]
disable-user-list=true
EOF
    
    # configure screen lock
    echo "configuring automatic screen lock..."
    cat > /etc/dconf/db/gdm.d/03-screen-lock << 'EOF'
[org/gnome/desktop/session]
idle-delay=900

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=0
EOF
    
    # prevent lock override
    cat > /etc/dconf/db/gdm.d/locks/04-screen-lock-locks << 'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
EOF
    
    # disable automount
    echo "disabling automatic media mounting..."
    cat > /etc/dconf/db/gdm.d/05-media-handling << 'EOF'
[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
EOF
    
    # prevent automount override
    cat > /etc/dconf/db/gdm.d/locks/06-media-handling-locks << 'EOF'
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open
/org/gnome/desktop/media-handling/autorun-never
EOF
    
    # update dconf database
    echo "updating dconf database..."
    dconf update
    
    echo -e "${GREEN}gdm security configured${NC}"
}

# ENHANCED FUNCTION - comprehensive audit configuration
comprehensive_audit_config() {
    echo -e "${BLUE}=== comprehensive audit configuration ===${NC}"
    
    # install auditd packages
    echo "installing auditd packages..."
    apt-get install -y auditd audispd-plugins
    
    # configure auditd.conf settings
    echo "configuring audit daemon settings..."
    
    # configure log retention
    sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    sed -i 's/^max_log_file.*/max_log_file = 100/' /etc/audit/auditd.conf
    
    # configure disk full action
    sed -i 's/^disk_full_action.*/disk_full_action = halt/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf
    
    # configure space warnings
    sed -i 's/^space_left.*/space_left = 100/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left.*/admin_space_left = 50/' /etc/audit/auditd.conf
    
    # create comprehensive audit rules directory
    mkdir -p /etc/audit/rules.d/
    
    # create base rules
    echo "creating comprehensive audit rules..."
    cat > /etc/audit/rules.d/50-base.rules << 'EOF'
# comprehensive audit rules for security monitoring
# delete all existing rules
-D

# set buffer size
-b 8192

# set failure mode (0=silent, 1=printk, 2=panic)
-f 1
EOF

    # sudoers monitoring
    cat > /etc/audit/rules.d/51-sudoers.rules << 'EOF'
# monitor changes to sudoers configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
EOF

    # user impersonation monitoring
    cat > /etc/audit/rules.d/52-user-impersonation.rules << 'EOF'
# monitor user impersonation activities
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k user_impersonation
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k user_impersonation
EOF

    # sudo log monitoring
    cat > /etc/audit/rules.d/53-sudo-log.rules << 'EOF'
# monitor sudo log file changes
-w /var/log/sudo.log -p wa -k sudo_log_file
EOF

    # network environment monitoring
    cat > /etc/audit/rules.d/55-network.rules << 'EOF'
# monitor network environment changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system_network
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system_network
-w /etc/issue -p wa -k system_network
-w /etc/issue.net -p wa -k system_network
-w /etc/hosts -p wa -k system_network
-w /etc/network/ -p wa -k system_network
EOF

    # find and monitor privileged commands
    echo "finding privileged commands..."
    cat > /etc/audit/rules.d/56-privileged.rules << 'EOF'
# monitor privileged command execution
EOF
    
    # add rules for each privileged program
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while IFS= read -r program; do
        echo "-a always,exit -F path=$program -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/56-privileged.rules
    done

    # file access monitoring
    cat > /etc/audit/rules.d/57-file-access.rules << 'EOF'
# monitor unsuccessful file access attempts
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
EOF

    # identity monitoring
    cat > /etc/audit/rules.d/58-identity.rules << 'EOF'
# monitor user and group information changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
EOF

    # permission modification monitoring
    cat > /etc/audit/rules.d/59-dac.rules << 'EOF'
# monitor discretionary access control permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF

    # mount monitoring
    cat > /etc/audit/rules.d/60-mounts.rules << 'EOF'
# monitor successful file system mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
EOF

    # session monitoring
    cat > /etc/audit/rules.d/61-session.rules << 'EOF'
# monitor session initiation information
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
EOF

    # file deletion monitoring
    cat > /etc/audit/rules.d/63-deletion.rules << 'EOF'
# monitor file deletion events by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
EOF

    # mac policy monitoring
    cat > /etc/audit/rules.d/64-mac.rules << 'EOF'
# monitor mandatory access control changes
-w /etc/apparmor/ -p wa -k mac_policy
-w /etc/apparmor.d/ -p wa -k mac_policy
EOF

    # specific command monitoring
    cat > /etc/audit/rules.d/65-commands.rules << 'EOF'
# monitor specific security-relevant commands
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k chcon
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k setfacl
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k usermod
EOF

    # kernel module monitoring
    cat > /etc/audit/rules.d/69-kernel-modules.rules << 'EOF'
# monitor kernel module loading, unloading, and modification
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
EOF

    # finalize rules
    cat > /etc/audit/rules.d/99-finalize.rules << 'EOF'
# make the configuration immutable - reboot required to change rules
-e 2
EOF

    # configure audit in grub
    if [ -f /etc/default/grub ]; then
        echo "enabling audit in bootloader..."
        sed -i 's/GRUB_CMDLINE_LINUX="[^"]*/& audit=1/' /etc/default/grub
        sed -i 's/GRUB_CMDLINE_LINUX="[^"]*/& audit_backlog_limit=8192/' /etc/default/grub
        update-grub 2>/dev/null || true
    fi
    
    # generate and load rules
    echo "loading audit rules..."
    augenrules --load 2>/dev/null || true
    
    # enable and start auditd
    systemctl enable auditd
    systemctl restart auditd
    
    echo -e "${GREEN}comprehensive audit configuration complete${NC}"
    echo -e "${YELLOW}useful audit query commands:${NC}"
    echo "  ausearch -k sudoers      # sudo activities"
    echo "  ausearch -k access       # file access denials"
    echo "  ausearch -k perm_mod     # permission changes"
    echo "  ausearch -k privileged   # privileged commands"
    echo "  ausearch -k delete       # file deletions"
}

# NEW CIS FUNCTION - enhanced system maintenance (cis 7.1, 7.2)
enhanced_system_maintenance() {
    echo -e "${BLUE}=== enhanced system maintenance (cis 7.1, 7.2) ===${NC}"
    
    # find and secure world writable files (cis 7.1.11)
    echo "securing world writable files..."
    find / -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null || true
    
    # find files without owner (cis 7.1.12)
    echo "finding files without owner..."
    find / -xdev \( -nouser -o -nogroup \) -print > /var/log/unowned_files.log 2>/dev/null || true
    
    # check for duplicate users/groups (cis 7.2.7, 7.2.8)
    echo "checking for duplicate names..."
    cut -d: -f1 /etc/passwd | sort | uniq -d > /var/log/duplicate_users.log
    cut -d: -f1 /etc/group | sort | uniq -d > /var/log/duplicate_groups.log
    
    # configure user home directories (cis 7.2.9, 7.2.10)
    echo "checking user home directories..."
    for user in $(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd); do
        home_dir=$(getent passwd "$user" | cut -d: -f6)
        if [ -d "$home_dir" ]; then
            chmod 750 "$home_dir" 2>/dev/null || true
            chown "$user:$user" "$home_dir" 2>/dev/null || true
            
            # secure dot files
            find "$home_dir" -name ".*" -type f -exec chmod 600 {} \; 2>/dev/null || true
        fi
    done
    
    echo -e "${GREEN}enhanced system maintenance complete${NC}"
}

# NEW CIS FUNCTION - enhanced sudo configuration (cis 5.2)
enhanced_sudo_configuration() {
    echo -e "${BLUE}=== enhanced sudo configuration (cis 5.2) ===${NC}"
    
    # configure sudo logging (cis 5.2.3)
    echo "configuring sudo logging..."
    echo "Defaults logfile=/var/log/sudo.log" > /etc/sudoers.d/sudo-log
    echo "Defaults use_pty" > /etc/sudoers.d/sudo-pty
    
    # restrict su command (cis 5.2.7)
    echo "restricting su command..."
    groupadd sugroup 2>/dev/null || true
    if ! grep -q "auth required pam_wheel.so use_uid group=sugroup" /etc/pam.d/su; then
        echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
    fi
    
    echo -e "${GREEN}enhanced sudo configuration complete${NC}"
}

# NEW CIS FUNCTION - enhanced firewall configuration (cis 4.2)
enhanced_firewall_configuration() {
    echo -e "${BLUE}=== enhanced firewall configuration (cis 4.2) ===${NC}"
    
    # install ufw
    apt-get install -y ufw
    
    # reset ufw
    ufw --force reset
    
    # configure loopback traffic (cis 4.2.5)
    echo "configuring loopback traffic..."
    ufw allow in on lo
    ufw allow out on lo
    ufw deny in from 127.0.0.0/8
    ufw deny in from ::1
    
    # set default policies (cis 4.2.8)
    echo "setting default firewall policies..."
    ufw default deny incoming
    ufw default deny outgoing
    ufw default deny routed
    
    # allow essential outbound connections
    echo "allowing essential outbound connections..."
    ufw allow out 53      # dns
    ufw allow out 80      # http
    ufw allow out 443     # https
    ufw allow out 123     # ntp

    # incase it doesnt follow thru
    ufw allow out http
    ufw allow out https
    ufw allow out ntp # Network Time Protocol
    ufw allow out to any port 53 # DNS
    ufw allow out to any port 853 # DNS over TLS
    ufw logging on
    
    # allow ssh
    ufw allow 22/tcp comment 'ssh'
    
    # enable logging
    ufw logging high
    
    # enable ufw
    ufw --force enable
    
    echo -e "${GREEN}enhanced firewall configuration complete${NC}"
}

# fix user accounts - NO AUTO REMOVAL
secure_user_accounts() {
    echo -e "${BLUE}=== fixing user accounts ===${NC}"
    
    # disable guest account
    echo "disabling guest..."
    
    # lightdm stuff
    if [ -f /etc/lightdm/lightdm.conf ]; then
        sed -i 's/#*allow-guest=.*/allow-guest=false/' /etc/lightdm/lightdm.conf
        grep -q "allow-guest=false" /etc/lightdm/lightdm.conf || echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
        
        sed -i 's/#*autologin-user=.*/autologin-user=/' /etc/lightdm/lightdm.conf
        sed -i 's/#*greeter-hide-users=.*/greeter-hide-users=true/' /etc/lightdm/lightdm.conf
        sed -i 's/#*greeter-show-manual-login=.*/greeter-show-manual-login=true/' /etc/lightdm/lightdm.conf
    fi
    
    # gdm3 stuff
    if [ -f /etc/gdm3/custom.conf ]; then
        sed -i '/\[daemon\]/a AutomaticLoginEnable=false' /etc/gdm3/custom.conf
        sed -i 's/AutomaticLoginEnable=true/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
    fi
    
    # IDENTIFY unauthorized users but DON'T remove them automatically
    echo -e "${BLUE}checking for unauthorized users...${NC}"
    
    # create report file
    UNAUTHORIZED_REPORT="/root/unauthorized_users_report.txt"
    echo "=== UNAUTHORIZED USERS REPORT ===" > "$UNAUTHORIZED_REPORT"
    echo "Generated: $(date)" >> "$UNAUTHORIZED_REPORT"
    echo "" >> "$UNAUTHORIZED_REPORT"
    
    # get all regular users (uid >= 1000) 
    current_users=($(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd))
    
    UNAUTHORIZED_USERS=()
    
    for user in "${current_users[@]}"; do
        # check if user is in authorized list
        user_authorized=false
        for auth_user in "${AUTHORIZED_USERS[@]}"; do
            if [ "$user" = "$auth_user" ]; then
                user_authorized=true
                break
            fi
        done
        
        # if not authorized, add to unauthorized list
        if [ "$user_authorized" = false ]; then
            UNAUTHORIZED_USERS+=("$user")
            echo "found unauthorized user: $user"
            echo "$user" >> "$UNAUTHORIZED_REPORT"
        fi
    done
    
    if [ ${#UNAUTHORIZED_USERS[@]} -gt 0 ]; then
        echo -e "${YELLOW}=== UNAUTHORIZED USERS FOUND ===${NC}"
        echo -e "${RED}The following users are NOT in your authorized users list:${NC}"
        for user in "${UNAUTHORIZED_USERS[@]}"; do
            echo -e "${RED}  - $user${NC}"
        done
        echo -e "${YELLOW}MANUAL ACTION REQUIRED: Review these users and remove if unauthorized${NC}"
        echo -e "${YELLOW}To remove a user: sudo userdel -r username${NC}"
        echo -e "${YELLOW}Report saved to: $UNAUTHORIZED_REPORT${NC}"
        echo ""
        echo -e "${BLUE}Commands to investigate users:${NC}"
        echo "  id username           # check user details"
        echo "  groups username       # check user groups"
        echo "  last username        # check login history"
        echo "  ls -la /home/username # check home directory"
        echo ""
        prompt_continue "acknowledged unauthorized users? (you'll need to handle them manually)"
    else
        echo -e "${GREEN}all current users are authorized${NC}"
        echo "No unauthorized users found" >> "$UNAUTHORIZED_REPORT"
    fi
    
    # add missing authorized users
    if [ ${#AUTHORIZED_USERS[@]} -gt 0 ]; then
        echo -e "${BLUE}adding missing authorized users...${NC}"
        for user in "${AUTHORIZED_USERS[@]}"; do
            if ! id "$user" &>/dev/null; then
                echo "adding user: $user"
                useradd -m -s /bin/bash "$user"
            else
                echo "user $user already exists"
            fi
        done
    fi
    
    # manage sudo group
    if [ ${#SUDO_USERS[@]} -gt 0 ]; then
        echo -e "${BLUE}configuring sudo users...${NC}"
        
        # remove all current sudo users except root
        current_sudo_users=$(getent group sudo | cut -d: -f4 | tr ',' ' ')
        for user in $current_sudo_users; do
            if [ "$user" != "root" ]; then
                echo "removing $user from sudo group"
                gpasswd -d "$user" sudo 2>/dev/null || true
            fi
        done
        
        # add authorized sudo users
        for user in "${SUDO_USERS[@]}"; do
            if id "$user" &>/dev/null; then
                echo "adding $user to sudo group"
                usermod -aG sudo "$user"
            else
                echo "warning: sudo user $user doesnt exist"
            fi
        done
    fi
    
    # manage admin group
    if [ ${#AUTHORIZED_ADMINS[@]} -gt 0 ]; then
        echo -e "${BLUE}configuring admin users...${NC}"
        
        # create admin group if it doesnt exist
        groupadd admin 2>/dev/null || true
        
        # remove all current admin users except root
        if getent group admin >/dev/null 2>&1; then
            current_admin_users=$(getent group admin | cut -d: -f4 | tr ',' ' ')
            for user in $current_admin_users; do
                if [ "$user" != "root" ]; then
                    echo "removing $user from admin group"
                    gpasswd -d "$user" admin 2>/dev/null || true
                fi
            done
        fi
        
        # add authorized admin users
        for user in "${AUTHORIZED_ADMINS[@]}"; do
            if id "$user" &>/dev/null; then
                echo "adding $user to admin group"
                usermod -aG admin "$user"
            else
                echo "warning: admin user $user doesnt exist"
            fi
        done
    fi
    
    # add users to custom groups
    if [ ${#USER_GROUPS[@]} -gt 0 ]; then
        echo -e "${BLUE}adding users to custom groups...${NC}"
        for group_pair in "${USER_GROUPS[@]}"; do
            if [[ "$group_pair" == *":"* ]]; then
                user=$(echo "$group_pair" | cut -d':' -f1)
                group=$(echo "$group_pair" | cut -d':' -f2-)
                
                if id "$user" &>/dev/null; then
                    # create group if it doesnt exist
                    groupadd "$group" 2>/dev/null || true
                    echo "adding $user to group $group"
                    usermod -aG "$group" "$user"
                else
                    echo "warning: user $user doesnt exist for group assignment"
                fi
            fi
        done
    fi
    
    # handle passwords
    echo -e "${BLUE}configuring passwords...${NC}"
    AUTO_GENERATED_PASSWORDS=()
    
    # set custom passwords first
    for password_pair in "${USER_PASSWORDS[@]}"; do
        if [[ "$password_pair" == *":"* ]]; then
            user=$(echo "$password_pair" | cut -d':' -f1)
            password=$(echo "$password_pair" | cut -d':' -f2-)
            
            if id "$user" &>/dev/null; then
                echo "setting custom password for: $user"
                echo "$user:$password" | chpasswd
            else
                echo "warning: user $user doesnt exist for password setting"
            fi
        fi
    done
    
    # generate passwords for users without passwords or weak passwords
    echo -e "${BLUE}checking for users needing secure passwords...${NC}"
    
    # check all regular users (uid >= 1000)
    for user in $(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd); do
        # skip if user already has custom password set
        user_has_custom_password=false
        for password_pair in "${USER_PASSWORDS[@]}"; do
            if [[ "$password_pair" == "$user:"* ]]; then
                user_has_custom_password=true
                break
            fi
        done
        
        if [ "$user_has_custom_password" = false ]; then
            # check if user has a password set
            user_password_status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
            
            if [ "$user_password_status" = "NP" ] || [ "$user_password_status" = "L" ]; then
                # user has no password or locked password, generate one
                new_password=$(generate_password)
                echo "$user:$new_password" | chpasswd
                AUTO_GENERATED_PASSWORDS+=("$user:$new_password")
                echo "generated secure password for: $user"
            fi
        fi
    done
    
    # display auto-generated passwords
    if [ ${#AUTO_GENERATED_PASSWORDS[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}=== AUTO-GENERATED PASSWORDS ===${NC}"
        echo -e "${RED}IMPORTANT: save these passwords somewhere safe!${NC}"
        for password_info in "${AUTO_GENERATED_PASSWORDS[@]}"; do
            echo -e "${GREEN}$password_info${NC}"
        done
        echo -e "${YELLOW}==================================${NC}\n"
        
        prompt_continue "passwords displayed above - did you save them?"
    fi
    
    # check for weird uid 0 users
    echo -e "${BLUE}checking for weird uid 0 users...${NC}"
    awk -F: '$3 == 0 && $1 != "root" {print "warning: weird uid 0 user: " $1}' /etc/passwd
    
    # check for empty passwords
    echo -e "${BLUE}checking for remaining empty passwords...${NC}"
    awk -F: '$2 == "" {print "warning: empty password: " $1}' /etc/shadow
    
    # show current user summary
    echo -e "${BLUE}=== user summary ===${NC}"
    echo "users with uid >= 1000:"
    awk -F: '$3 >= 1000 && $3 != 65534 {print $1 " (uid: " $3 ")"}' /etc/passwd
    
    echo -e "\nsudo group members:"
    getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v '^$'
    
    echo -e "\nadmin group members:"
    getent group admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v '^$' || echo "no admin group or no members"
    
    # lock system accounts
    echo "locking system accounts..."
    for user in $(awk -F: '($3 < 1000 && $1 != "root" && $1 != "sync" && $1 != "shutdown" && $1 != "halt") {print $1}' /etc/passwd); do
        usermod -L "$user" 2>/dev/null || true
        if [ "$user" != "sync" ] && [ "$user" != "shutdown" ] && [ "$user" != "halt" ]; then
            usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        fi
    done
    
    echo -e "${GREEN}user accounts configured${NC}"
}

# make passwords harder
configure_password_policy() {
    echo -e "${BLUE}=== fixing password policy ===${NC}"
    
    # install password stuff
    apt-get update -qq
    apt-get install -y libpam-pwquality libpam-cracklib auditd
    
    # configure login.defs
    echo "fixing login.defs..."
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t8/' /etc/login.defs
    
    # add more security stuff
    grep -q "FAILLOG_ENAB" /etc/login.defs || echo "FAILLOG_ENAB yes" >> /etc/login.defs
    grep -q "LOG_UNKFAIL_ENAB" /etc/login.defs || echo "LOG_UNKFAIL_ENAB yes" >> /etc/login.defs
    grep -q "SYSLOG_SU_ENAB" /etc/login.defs || echo "SYSLOG_SU_ENAB yes" >> /etc/login.defs
    grep -q "SYSLOG_SG_ENAB" /etc/login.defs || echo "SYSLOG_SG_ENAB yes" >> /etc/login.defs
    
    # simple pam config
    echo "fixing pam..."
    
    # backup pam files
    cp /etc/pam.d/common-password /etc/pam.d/common-password.backup 2>/dev/null || true
    cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup 2>/dev/null || true
    
    # create pam config
    cat > /etc/pam.d/common-password << 'EOF'
#
# /etc/pam.d/common-password - password-related modules common to all services
#
password	requisite			pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 ocredit=-1 lcredit=-1 dcredit=-1
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512 remember=5 minlen=8
password	requisite			pam_deny.so
password	required			pam_permit.so
password	optional			pam_gnome_keyring.so
EOF

    cat > /etc/pam.d/common-auth << 'EOF'
#
# /etc/pam.d/common-auth - authentication settings common to all services
#
auth    [success=1 default=ignore] pam_unix.so try_first_pass sha512
auth    requisite       pam_deny.so
auth    required        pam_permit.so
EOF

    for f in common-password common-auth; do
        sed -i 's/\s*nullok//g' "/etc/pam.d/$f"
    done
    
    echo -e "${GREEN}password stuff done${NC}"
}

# configure automatic updates
configure_automatic_updates() {
    echo -e "${BLUE}=== configuring automatic updates ===${NC}"
    
    # install unattended-upgrades
    apt-get install -y unattended-upgrades apt-listchanges update-notifier-common
    
    # enable automatic updates
    echo "enabling automatic security updates..."
    
    # configure auto-updates (20auto-upgrades)
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    # configure what gets updated (50unattended-upgrades)
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}";
	"${distro_id}:${distro_codename}-security";
	"${distro_id}ESMApps:${distro_codename}-apps-security";
	"${distro_id}ESM:${distro_codename}-infra-security";
	"${distro_id}:${distro_codename}-updates";
};

// Remove unused kernel packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot if needed (at 2am)
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

// Send email notifications
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "false";

// Clean up old packages
Unattended-Upgrade::MinimalSteps "true";

// Detailed logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

    # enable and start the service
    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades

    # run initial update check
    dpkg-reconfigure -plow unattended-upgrades
    
    echo -e "${GREEN}automatic updates configured${NC}"
    echo "updates will be checked daily and security updates installed automatically"
}

# update system and packages
update_system() {
    echo -e "${BLUE}=== system updates and configuration ===${NC}"
    
    # update packages
    echo "updating package lists..."
    apt-get update
    
    # upgrade system
    echo "upgrading system packages..."
    apt-get dist-upgrade -y
    
    # always configure automatic updates
    configure_automatic_updates
    
    # cleanup
    apt-get autoremove -y
    apt-get autoclean
    
    if [ "$INSTALL_SECURITY_TOOLS" = true ]; then
        # install security tools
        echo "installing security tools..."
        apt-get install -y \
            fail2ban \
            chkrootkit \
            rkhunter \
            lynis \
            apparmor \
            apparmor-profiles \
            ufw \
            aide \
            auditd \
            clamav \
            clamav-daemon
    fi

    echo "installing java (for cis cat lite)..."
    apt install default-jdk
    
    # remove bad packages
    DANGEROUS_PACKAGES=(
        "john"
        "hydra"
        "nmap"
        "zenmap"
        "wireshark"
        "tcpdump"
        "netcat-traditional"
        "netcat-openbsd"
        "nikto"
        "ophcrack"
        "aircrack-ng"
        "kismet"
        "ettercap-text-only"
        "ettercap-graphical"
        "dsniff"
    )
    
    echo -e "${BLUE}checking for bad packages...${NC}"
    for package in "${DANGEROUS_PACKAGES[@]}"; do
        if dpkg -l | grep -q "^ii.*$package"; then
            echo "found and removing dangerous package: $package"
            apt-get purge -y "$package" 2>/dev/null || true
        fi
    done
    
    # remove games
    if [ "$REMOVE_GAMES" = true ]; then
        echo "removing games..."
        apt-get purge -y \
            aisleriot \
            AisleRiot Solitaire\
            gnome-mahjongg \
            gnome-mines \
            gnome-sudoku \
            solitaire \
            quadrapassel \
            lightsoff \
            five-or-more \
            four-in-a-row \
            gnome-chess \
            gnome-nibbles \
            gnome-robots \
            gnome-taquin \
            gnome-tetravex \
            hitori \
            iagno \
            tali \
            2>/dev/null || true
    fi
    
    echo -e "${GREEN}system updated and automatic updates configured${NC}"
}

# fix ssh
harden_ssh() {
    echo -e "${BLUE}=== fixing ssh ===${NC}"
    
    if [ ! -f /etc/ssh/sshd_config ]; then
        echo "ssh not installed, skipping"
        return
    fi
    
    # backup ssh config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # write new ssh config
    cat > /etc/ssh/sshd_config << EOF
# ssh config
Port 22
Protocol 2

# host keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# privilege stuff
UsePrivilegeSeparation yes

# authentication
LoginGraceTime 60
PermitRootLogin $([ "$DISABLE_SSH_ROOT" = true ] && echo "no" || echo "yes")
StrictModes yes
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60

# password auth
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# kerberos stuff
KerberosAuthentication no
GSSAPIAuthentication no

# host based auth
HostbasedAuthentication no
IgnoreUserKnownHosts yes
IgnoreRhosts yes

# disable stuff we dont need
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive no

# logging
SyslogFacility AUTH
LogLevel VERBOSE

# banner
Banner /etc/issue.net

# crypto stuff
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

# timeout
ClientAliveInterval 300
ClientAliveCountMax 0
EOF

    # test ssh config
    if sshd -t 2>/dev/null; then
        echo -e "${GREEN}ssh config looks good${NC}"
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    else
        echo -e "${RED}ssh config broken, restoring backup${NC}"
        cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
        return 1
    fi
}

# manage services
manage_services() {
    echo -e "${BLUE}=== managing services ===${NC}"
    
    # services to maybe disable
    SERVICES_TO_DISABLE=(
        "vsftpd"
        "proftpd"
        "pure-ftpd"
        "telnet"
        "rsh-server"
        "rlogin"
        "rexec"
        "finger"
        "talk"
        "ntalk"
        "ypbind"
        "ypserv"
        "tftp"
        "xinetd"
        "inetd"
        "avahi-daemon"
        "cups"
        "bluetooth"
        "nfs-server"
        "rpcbind"
        "bind9"
        "named"
        "sendmail"
        "postfix"
        "dovecot"
        "squid"
        "squid3"
        "snmpd"
        "rsync"
        "nginx"
    )
    
    # ftp stuff
    if [ "$DISABLE_FTP" = true ]; then
        echo "disabling ftp..."
        for ftp_service in vsftpd proftpd pure-ftpd ftpd; do
            systemctl stop "$ftp_service" 2>/dev/null || true
            systemctl disable "$ftp_service" 2>/dev/null || true
        done
    else
        echo "keeping ftp..."
        # remove ftp services from disable list
        SERVICES_TO_DISABLE=($(printf '%s\n' "${SERVICES_TO_DISABLE[@]}" | grep -v -E "ftp|FTP"))
    fi
    
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "disabling: $service"
            systemctl stop "$service" 2>/dev/null || true
            systemctl disable "$service" 2>/dev/null || true
        fi
    done
    
    # enable good services
    SERVICES_TO_ENABLE=(
        "ufw"
        "fail2ban"
        "apparmor"
        "auditd"
    )
    
    for service in "${SERVICES_TO_ENABLE[@]}"; do
        if systemctl list-unit-files | grep -q "$service"; then
            systemctl enable "$service" 2>/dev/null || true
            systemctl start "$service" 2>/dev/null || true
        fi
    done
    
    echo -e "${BLUE}active services:${NC}"
    systemctl --type=service --state=active --no-pager --no-legend | head -20
}

secure_mail_system() {
    echo -e "${BLUE}=== securing mail system ===${NC}"
    
    # Check if mail services are installed
    if command -v postfix >/dev/null 2>&1; then
        echo "configuring postfix security..."
        
        # Basic postfix security settings
        postconf -e 'smtpd_banner = $myhostname ESMTP'
        postconf -e 'smtpd_helo_required = yes'
        postconf -e 'smtpd_helo_restrictions = permit_mynetworks,reject_invalid_helo_hostname,reject_non_fqdn_helo_hostname'
        postconf -e 'smtpd_sender_restrictions = permit_mynetworks,reject_non_fqdn_sender,reject_unknown_sender_domain'
        postconf -e 'smtpd_recipient_restrictions = permit_mynetworks,reject_unauth_destination,reject_non_fqdn_recipient,reject_unknown_recipient_domain'
        postconf -e 'disable_vrfy_command = yes'
        postconf -e 'smtpd_delay_reject = yes'
        
        systemctl restart postfix
    fi
    
    # Check if dovecot is installed
    if command -v dovecot >/dev/null 2>&1; then
        echo "configuring dovecot security..."
        
        # Basic dovecot security
        if [ -f /etc/dovecot/conf.d/10-auth.conf ]; then
            sed -i 's/#disable_plaintext_auth = yes/disable_plaintext_auth = yes/' /etc/dovecot/conf.d/10-auth.conf
        fi
        
        systemctl restart dovecot
    fi
    
    echo -e "${GREEN}mail system secured${NC}"
}

# Configure USB and removable media restrictions
restrict_removable_media() {
    echo -e "${BLUE}=== restricting removable media ===${NC}"
    
    # Create udev rules to restrict USB storage
    cat > /etc/udev/rules.d/99-usb-storage.rules << 'EOF'
# Restrict USB storage devices
# Comment out to allow USB storage
SUBSYSTEM=="usb", ATTRS{bDeviceClass}=="08", ACTION=="add", RUN+="/bin/sh -c 'echo 1 > /sys/bus/usb/devices/%k/remove'"
EOF

    # Reload udev rules
    udevadm control --reload-rules
    
    # Blacklist USB storage modules in modprobe
    echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist-usb.conf
    
    echo -e "${GREEN}removable media restrictions applied${NC}"
}

# setup firewall
configure_firewall() {
    echo -e "${BLUE}=== setting up firewall ===${NC}"
    
    # install ufw
    apt-get install -y ufw
    
    # reset ufw
    ufw --force reset
    
    # default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # enable logging
    ufw logging high
    
    # allow ssh
    ufw allow 22/tcp comment 'ssh'
    
    echo -e "${YELLOW}add more rules if you need them:${NC}"
    echo "examples:"
    echo "  ufw allow 80/tcp    # http"
    echo "  ufw allow 443/tcp   # https"
    echo "  ufw allow 53        # dns"
    echo "  ufw allow 21/tcp    # ftp"
    
    # enable ufw
    ufw --force enable
    
    echo -e "${GREEN}firewall is on${NC}"
    ufw status verbose
}

# deal with media files (smart version - keeps system images)
handle_media_files() {
    echo -e "${BLUE}=== handling media files ===${NC}"
    
    if [ "$REMOVE_MEDIA_FILES" = true ]; then
        echo -e "${RED}WARNING: removing entertainment media files!${NC}"
        echo -e "${GREEN}keeping system-critical image files (ico, png, svg)${NC}"
        
        # create temporary directory for file list
        MEDIA_LIST="/tmp/media_files_to_remove.txt"
        > "$MEDIA_LIST"
        
        # find audio/video files (entertainment media)
        echo -e "${YELLOW}finding audio/video files...${NC}"
        find /home -type f \( \
            -name "*.mp3" -o -name "*.mp4" -o -name "*.avi" -o \
            -name "*.mov" -o -name "*.wav" -o -name "*.wmv" -o \
            -name "*.flv" -o -name "*.ogg" -o -name "*.m4a" -o \
            -name "*.mpg" -o -name "*.mpeg" -o -name "*.flac" -o \
            -name "*.mkv" -o -name "*.webm" -o -name "*.m4v" -o \
            -name "*.3gp" -o -name "*.aac" -o -name "*.wma" \
            \) 2>/dev/null >> "$MEDIA_LIST"
        
        # find non-system image files (only large images likely to be personal photos)
        echo -e "${YELLOW}finding large image files (likely personal photos)...${NC}"
        # only remove jpg/jpeg/bmp/tiff files over 500KB (likely photos, not system images)
        find /home -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.bmp" -o -name "*.tiff" \) \
            -size +500k 2>/dev/null >> "$MEDIA_LIST"
        
        # show what will be removed
        FILE_COUNT=$(wc -l < "$MEDIA_LIST")
        echo -e "${YELLOW}files to be removed: $FILE_COUNT${NC}"
        
        if [ "$FILE_COUNT" -gt 0 ]; then
            echo "sample of files to remove (first 20):"
            head -20 "$MEDIA_LIST"
            
            prompt_continue "remove these media files? (system images will be kept)"
            
            echo "removing media files..."
            while IFS= read -r file; do
                rm -f "$file" 2>/dev/null
            done < "$MEDIA_LIST"
            
            echo -e "${GREEN}media files removed, system images preserved${NC}"
        else
            echo "no media files found to remove"
        fi
        
        # cleanup
        rm -f "$MEDIA_LIST"
        
        echo -e "${BLUE}preserved system-critical files:${NC}"
        echo "- .ico files (icons)"
        echo "- .png files (system graphics)"  
        echo "- .svg files (vector graphics)"
        echo "- .gif files (may be system animations)"
        echo "- small .jpg files (<500KB - likely thumbnails/avatars)"
    else
        echo -e "${GREEN}keeping all media files${NC}"
        echo "to check for media files manually:"
        echo "  find /home -name '*.mp3' -type f"
        echo "  find /home -name '*.mp4' -type f"
        echo "  find /home -name '*.jpg' -type f -size +500k"
    fi
}

# fix file permissions
secure_file_permissions() {
    echo -e "${BLUE}=== fixing file permissions ===${NC}"
    
    # fix important files
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 640 /etc/shadow 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 640 /etc/gshadow 2>/dev/null || true
    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
    chmod 644 /etc/ssh/ssh_config 2>/dev/null || true
    chmod 440 /etc/sudoers 2>/dev/null || true
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    
    # fix ownership
    chown root:root /etc/passwd /etc/group 2>/dev/null || true
    chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || true
    
    # find world writable files
    echo -e "${BLUE}checking for world writable files...${NC}"
    find /etc /bin /sbin /usr/bin /usr/sbin -type f -perm -002 2>/dev/null | head -10
    
    # find suid/sgid files
    echo -e "${BLUE}checking for suid/sgid files...${NC}"
    find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -10
    
    # remove bad files
    echo "removing bad files..."
    find /home -name ".rhosts" -delete 2>/dev/null || true
    find /home -name ".netrc" -delete 2>/dev/null || true
    find /home -name "*.sh" -perm -002 -exec chmod o-w {} \; 2>/dev/null || true
    
    echo -e "${GREEN}file permissions fixed${NC}"
}

# setup auditing - REPLACED WITH COMPREHENSIVE VERSION
configure_auditing() {
    echo -e "${BLUE}=== note: using comprehensive audit config instead ===${NC}"
    echo "skipping basic auditing - comprehensive version will be used"
}

# harden kernel
harden_kernel() {
    echo -e "${BLUE}=== hardening kernel ===${NC}"
    
    cat > /etc/sysctl.d/99-security.conf << EOF
# kernel hardening
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.randomize_va_space=2

# network security
net.ipv4.ip_forward=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0

# icmp stuff
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1

# tcp stuff - enable syn cookies
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5

# ipv6 stuff
$([ "$ENABLE_IPV6" = false ] && echo "net.ipv6.conf.all.disable_ipv6=1" || echo "# ipv6 enabled")
$([ "$ENABLE_IPV6" = false ] && echo "net.ipv6.conf.default.disable_ipv6=1" || echo "# ipv6 enabled")
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0

EOF

    # apply settings
    sysctl -p /etc/sysctl.d/99-security.conf
    
    echo -e "${GREEN}kernel hardened${NC}"
}

advanced_kernel_hardening() {
    echo -e "${BLUE}=== applying advanced kernel hardening ===${NC}"
    
    # create additional sysctl parameters file
    cat > /etc/sysctl.d/98-advanced-security.conf << 'EOF'

# prevent core dumps for suid programs
fs.suid_dumpable = 0

# hide kernel pointers
kernel.kptr_restrict = 2

# restrict kernel log access
kernel.dmesg_restrict = 1

# enable yama ptrace restrictions
kernel.yama.ptrace_scope = 3

# disable loading kernel modules after boot
# kernel.modules_disabled = 1

# memory management security
vm.unprivileged_userfaultfd = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16

# network security enhancements
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# disable ICMP redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# disable ipv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

    # Apply the new settings
    sysctl -p /etc/sysctl.d/98-advanced-security.conf
    
    echo -e "${GREEN}advanced kernel hardening applied${NC}"
}

# secure network stuff
secure_network() {
    echo -e "${BLUE}=== securing network ===${NC}"
    
    # check /etc/hosts
    echo "checking /etc/hosts..."
    if [ -f /etc/hosts ]; then
        echo "current /etc/hosts:"
        cat /etc/hosts
        echo -e "${YELLOW}check for weird redirects${NC}"
    fi
    
    # check dns
    echo "checking dns..."
    if [ -f /etc/resolv.conf ]; then
        echo "current dns:"
        grep nameserver /etc/resolv.conf || echo "no nameservers"
    fi
    
    # skip host.conf configuration - causes issues on some systems
    echo "skipping host.conf configuration"

    echo -e "${GREEN}network secured${NC}"
}

# run security scans
run_security_scan() {
    echo -e "${BLUE}=== running security scans ===${NC}"
    
    if [ "$INSTALL_SECURITY_TOOLS" = true ]; then
        # update databases
        echo "updating scan databases..."
        freshclam --quiet 2>/dev/null || true
        rkhunter --update --quiet 2>/dev/null || true
        
        # run chkrootkit
        echo "running chkrootkit..."
        chkrootkit -q > /var/log/chkrootkit.log 2>&1 || true
        
        # run rkhunter
        echo "running rkhunter..."
        rkhunter --propupd --quiet 2>/dev/null || true
        rkhunter --check --skip-keypress --report-warnings-only > /var/log/rkhunter.log 2>&1 || true
        
        # run lynis
        echo "running lynis..."
        lynis audit system --quick > /var/log/lynis.log 2>&1 || true
        
        # run clamav
        echo "running clamav..."
        clamscan -r -i --stdout /home > /var/log/clamav.log 2>&1 || true
        
        echo -e "${GREEN}scans done, check /var/log/${NC}"
    else
        echo "security tools not installed"
    fi
}

# check open ports
check_network_security() {
    echo -e "${BLUE}=== checking network stuff ===${NC}"
    
    echo "open ports:"
    ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "couldnt list ports"
    
    echo -e "\n${BLUE}connections:${NC}"
    ss -tup 2>/dev/null | head -20 || netstat -tup 2>/dev/null | head -20 || echo "couldnt list connections"
    
    echo -e "\n${YELLOW}check for weird stuff above${NC}"
}

# setup fail2ban
configure_fail2ban() {
    echo -e "${BLUE}=== setting up fail2ban ===${NC}"
    
    if command -v fail2ban-server >/dev/null 2>&1; then
        # configure fail2ban
        cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

        systemctl enable fail2ban
        systemctl restart fail2ban
        echo -e "${GREEN}fail2ban setup${NC}"
    else
        echo "fail2ban not installed"
    fi
}

# create warning banners
create_banners() {
    echo -e "${BLUE}=== creating banners ===${NC}"
    
    # warning banners
    cat > /etc/issue << 'EOF'
WARNING: unauthorized access prohibited
all activities monitored and reported
EOF

    cat > /etc/issue.net << 'EOF'
WARNING: unauthorized access prohibited
all activities monitored and reported
EOF

    cat > /etc/motd << 'EOF'
WARNING: authorized users only
all activities monitored and logged
unauthorized access will be prosecuted
EOF

    echo -e "${GREEN}banners created${NC}"
}

# final check with update status
final_system_check() {
    echo -e "${BLUE}=== final check ===${NC}"
    
    echo "checking file permissions..."
    ls -la /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null
    
    echo -e "\n${BLUE}service status:${NC}"
    systemctl is-active ufw auditd unattended-upgrades 2>/dev/null || true
    
    echo -e "\n${BLUE}automatic updates status:${NC}"
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
        systemctl status unattended-upgrades --no-pager | head -10
        apt-config dump APT::Periodic::Unattended-Upgrade
    else
        echo "automatic updates not configured yet"
    fi
    
    echo -e "\n${BLUE}firewall status:${NC}"
    ufw status 2>/dev/null || echo "ufw not setup"
    
    echo -e "\n${BLUE}password policy:${NC}"
    grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE" /etc/login.defs
    
    echo -e "\n${BLUE}gdm status:${NC}"
    if [ "$CONFIGURE_GDM" = true ]; then
        if [ -f /etc/dconf/db/gdm.d/01-banner-message ]; then
            echo "gdm security configured"
        else
            echo "gdm configuration may have failed"
        fi
    else
        echo "gdm configuration skipped"
    fi
    
    echo -e "\n${BLUE}audit status:${NC}"
    if systemctl is-active --quiet auditd 2>/dev/null; then
        echo "auditd running with $(auditctl -l | wc -l) rules"
    else
        echo "auditd not running"
    fi
    
    echo -e "\n${YELLOW}stuff you still need to do:${NC}"
    echo "1. review unauthorized users report at /root/unauthorized_users_report.txt"
    echo "2. manually remove any unauthorized users with: userdel -r username"
    echo "3. change all user passwords if not done"
    echo "4. verify user groups are correct"
    echo "5. setup firewall rules for your specific services"
    echo "6. check /var/log/auth.log for suspicious activity"
    echo "7. test everything works"
    echo "8. reboot the system"
    echo "9. verify gdm login banner appears (if configured)"
    echo "10. test audit logging with: ausearch -k sudoers"
}

# main function - UPDATES AT THE END
main() {
    echo -e "${YELLOW}this script changes a lot of stuff${NC}"
    echo -e "${YELLOW}make backups and test first${NC}"
    echo -e "${RED}READ THE README AND DO FORENSICS FIRST${NC}"
    
    prompt_continue "start hardening?"
    
    read_readme_config
    configure_user_management
    backup_files
    
    echo -e "\n${BLUE}starting hardening...${NC}\n"
    
    configure_filesystem_modules
    configure_network_modules
    enhanced_apparmor_config
    configure_cron_permissions
    enhanced_pam_configuration
    comprehensive_audit_config
    enhanced_system_maintenance
    enhanced_sudo_configuration
    enhanced_firewall_configuration
    
    harden_additional_services
    configure_gdm_security
    
    
    secure_user_accounts
    configure_password_policy
    harden_ssh
    manage_services
    secure_mail_system
    configure_firewall
    handle_media_files
    secure_file_permissions
    configure_auditing  # note: this now just shows a message
    harden_kernel
    advanced_kernel_hardening
    # configure_aide_integrity
    secure_network
    configure_fail2ban
    create_banners
    run_security_scan
    check_network_security
    final_system_check
    
    # prompt for updates at the very end
    echo -e "\n${BLUE}=== system updates ===${NC}"
    echo -e "${YELLOW}all hardening tasks are complete!${NC}"
    echo -e "${YELLOW}system updates and automatic updates configuration is the final step${NC}"
    echo -e "${YELLOW}this may take a while and could require a reboot${NC}"
    read -p "ready to run system updates and configure automatic updates? (y/N): " run_final_updates
    
    if [[ $run_final_updates =~ ^[Yy]$ ]]; then
        update_system
        UPDATE_STATUS="CONFIGURED"
    else
        echo -e "${RED}WARNING: skipping updates - your system may be vulnerable!${NC}"
        echo -e "${YELLOW}you can run updates later with: sudo apt update && sudo apt upgrade${NC}"
        echo -e "${YELLOW}configure automatic updates with: sudo dpkg-reconfigure unattended-upgrades${NC}"
        UPDATE_STATUS="NOT CONFIGURED - manual setup needed"
    fi
    
    echo -e "\n${GREEN}=== hardening complete ===${NC}"
    echo "finished: $(date)"
    echo -e "${YELLOW}next steps:${NC}"
    echo "1. check everything works"
    echo "2. review unauthorized users report at /root/unauthorized_users_report.txt"
    echo "3. manually remove any unauthorized users with: userdel -r username"
    echo "4. verify automatic updates are enabled (if you ran them)"
    echo "5. change remaining passwords"
    echo "6. REBOOT the system"
    echo "7. check logs in $LOG_FILE"
    echo "8. verify gdm login banner appears (if configured)"
    echo "9. test audit logging with commands like: ausearch -k sudoers"
    
    # summary
    cat > /root/hardening_summary.txt << EOF
linux hardening summary
generated: $(date)

settings:
- remove media files: $REMOVE_MEDIA_FILES (system images preserved)
- disable ftp: $DISABLE_FTP
- disable ssh root: $DISABLE_SSH_ROOT
- enable ipv6: $ENABLE_IPV6
- remove games: $REMOVE_GAMES
- install security tools: $INSTALL_SECURITY_TOOLS
- configure gdm: $CONFIGURE_GDM

NEW CIS ADDITIONS:
- filesystem kernel modules disabled (cis 1.1.1)
- network kernel modules disabled (cis 3.2)
- enhanced apparmor configuration (cis 1.3.1)
- cron permissions secured (cis 2.4.1)
- enhanced pam configuration (cis 5.3)
- NOT ADDED: aide file integrity monitoring (cis 6.1) 
- comprehensive audit rules (cis 6.3.3)
- enhanced system maintenance (cis 7.1, 7.2)
- enhanced sudo configuration (cis 5.2)
- enhanced firewall configuration (cis 4.2)

NEW ADDITIONS:
- gdm security configuration (login banner, user list disabled, automount disabled)
- comprehensive audit monitoring (50+ audit rules covering all security events)
- improved backup system (includes gdm and audit configs)

stuff done:
- user account security and guest disable
- unauthorized users identified (NOT auto-removed)
- password policy with pam
- ssh hardening
- service management
- firewall with ufw
- smart media file handling (preserves system images)
- file permissions
- comprehensive audit setup with detailed rules
- gdm security configuration (if enabled)
- kernel hardening
- security scans
- fail2ban setup
- security banners

user management:
- unauthorized users report: /root/unauthorized_users_report.txt
- manual action required for user removal
- authorized users configured
- sudo/admin groups updated
- passwords generated for users without them

automatic updates:
- status: $UPDATE_STATUS
- daily package list updates (if configured)
- automatic security updates installation (if configured)
- logs at /var/log/unattended-upgrades/ (if configured)

gdm security (if configured):
- login banner enabled
- user list disabled
- automatic screen lock (15 min)
- automount disabled
- configuration at /etc/dconf/db/gdm.d/

audit configuration:
- comprehensive rules covering all security events
- logs at /var/log/audit/
- query examples: ausearch -k [sudoers|access|perm_mod|privileged|delete]
- configuration at /etc/audit/rules.d/

files changed:
- /etc/ssh/sshd_config
- /etc/login.defs
- /etc/pam.d/common-password
- /etc/pam.d/common-auth
- /etc/sysctl.d/99-security.conf
- /etc/audit/rules.d/* (comprehensive audit rules)
- /etc/audit/auditd.conf
- /etc/lightdm/lightdm.conf
- /etc/gdm3/custom.conf
- /etc/dconf/profile/gdm (NEW)
- /etc/dconf/db/gdm.d/* (NEW)
- /etc/apt/apt.conf.d/20auto-upgrades (if updates configured)
- /etc/apt/apt.conf.d/50unattended-upgrades (if updates configured)
- /etc/issue, /etc/issue.net, /etc/motd
- /etc/modprobe.d/filesystem.conf (NEW)
- /etc/modprobe.d/network.conf (NEW)
- /etc/security/pwquality.conf (NEW)
- /etc/cron.daily/aide (NEW)
- /etc/sudoers.d/sudo-log (NEW)

backup location: $BACKUP_DIR

scan logs:
- chkrootkit: /var/log/chkrootkit.log
- rkhunter: /var/log/rkhunter.log
- lynis: /var/log/lynis.log
- clamav: /var/log/clamav.log
- unattended-upgrades: /var/log/unattended-upgrades/
- unowned files: /var/log/unowned_files.log (NEW)
- duplicate users: /var/log/duplicate_users.log (NEW)
- duplicate groups: /var/log/duplicate_groups.log (NEW)
- audit logs: /var/log/audit/ (NEW)

next steps:
1. review unauthorized users report
2. manually remove unauthorized users
3. REBOOT
4. verify automatic updates are working 
5. test everything
6. change remaining passwords
7. check scan results
8. monitor logs
9. verify gdm security features
10. test audit logging

remember: check the readme for specific requirements
EOF

    echo -e "${GREEN}summary at: /root/hardening_summary.txt${NC}"
    if [[ $run_final_updates =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}automatic updates are now enabled and will check daily${NC}"
    else
        echo -e "${RED}remember to configure updates later for ongoing security!${NC}"
    fi
}

# run it
main "$@"
