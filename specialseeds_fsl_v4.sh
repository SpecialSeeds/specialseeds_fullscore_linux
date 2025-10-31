#!/bin/bash
#
# enhanced linux security hardening script - based on cyberpatriots answer key
# incorporates all vulnerabilities from training round 2
# 
# warning: this changes a lot of stuff on your computer
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

# configuration - change based on readme
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

# check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}need to run as root${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}=== enhanced linux security script ===${NC}"
echo -e "${PURPLE}*** read the readme and do forensic questions first ***${NC}"
echo "started: $(date)"
echo "log: $LOG_FILE"

# prompt for continuation
prompt_continue() {
    echo -e "${YELLOW}$1${NC}"
    read -p "continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}stopped${NC}"
        exit 1
    fi
}

# generate secure password
generate_password() {
    openssl rand -base64 12 | tr -d "=+/" | cut -c1-12
}

# read readme configuration
read_readme_config() {
    echo -e "${BLUE}=== readme and forensic setup ===${NC}"
    echo -e "${YELLOW}make sure you did:${NC}"
    echo "1. read the readme completely"
    echo "2. answered all forensic questions"
    echo "3. know which users are supposed to be there"
    echo "4. know which services should be running"
    echo "5. note special circumstances (ftp, ssh, ipv6...)"
    
    prompt_continue "did you actually read the readme and do forensics?"
    
    echo -e "${BLUE}service configuration:${NC}"
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
    
    read -p "configure gdm security? (Y/n): " gdm_required
    if [[ ! $gdm_required =~ ^[Nn]$ ]]; then
        CONFIGURE_GDM=true
    fi
    
    read -p "remove media files? (y/N): " remove_media
    if [[ $remove_media =~ ^[Yy]$ ]]; then
        REMOVE_MEDIA_FILES=true
        echo -e "${RED}warning: this will remove music/video files but keep system images${NC}"
        prompt_continue "really remove media files?"
    fi
}

# configure user management
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
    
    # add users to groups
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

# backup important files
backup_files() {
    echo -e "${BLUE}making backups...${NC}"
    BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # backup critical files
    cp /etc/passwd "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/shadow "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/group "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/sudoers "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/lightdm/lightdm.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/gdm3/custom.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/pam.d/common-password "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/pam.d/common-auth "$BACKUP_DIR/" 2>/dev/null || true
    
    echo "backups at: $BACKUP_DIR"
}

# configure filesystem kernel modules (cis 1.1.1)
configure_filesystem_modules() {
    echo -e "${BLUE}=== configuring filesystem kernel modules ===${NC}"
    
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

# configure network kernel modules (cis 3.2)
configure_network_modules() {
    echo -e "${BLUE}=== configuring network kernel modules ===${NC}"
    
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

# enhanced apparmor configuration (cis 1.3.1)
enhanced_apparmor_config() {
    echo -e "${BLUE}=== enhanced apparmor configuration ===${NC}"
    
    # install apparmor packages
    echo "installing apparmor packages..."
    apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
    
    # enable apparmor in bootloader
    if [ -f /etc/default/grub ]; then
        echo "enabling apparmor in bootloader..."
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

# configure cron permissions (cis 2.4.1)
configure_cron_permissions() {
    echo -e "${BLUE}=== configuring cron permissions ===${NC}"
    
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

# enhanced pam configuration based on answer key
enhanced_pam_configuration() {
    echo -e "${BLUE}=== enhanced pam configuration ===${NC}"
    
    # install required pam modules
    echo "installing pam modules..."
    apt-get install -y libpam-pwquality libpam-cracklib libpam-modules
    
    # backup existing pam files
    cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup.security 2>/dev/null || true
    cp /etc/pam.d/common-password /etc/pam.d/common-password.backup.security 2>/dev/null || true
    cp /etc/pam.d/common-account /etc/pam.d/common-account.backup.security 2>/dev/null || true
    
    # configure account lockout based on answer key methodology
    echo "configuring account lockout policy..."
    
    # create faillock configuration files
    mkdir -p /usr/share/pam-configs
    
    cat > /usr/share/pam-configs/faillock << 'EOF'
Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
EOF
    
    cat > /usr/share/pam-configs/faillock_reset << 'EOF'
Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
	required pam_faillock.so authsucc
EOF
    
    cat > /usr/share/pam-configs/faillock_notify << 'EOF'
Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
EOF
    
    # configure password policy using cracklib as in answer key
    cat > /etc/pam.d/common-password << 'EOF'
#
# /etc/pam.d/common-password - password-related modules common to all services
#
password	requisite			pam_cracklib.so retry=3 minlen=10 difok=3 ucredit=-1 ocredit=-1 lcredit=-1 dcredit=-1
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512 remember=3 minlen=10
password	requisite			pam_deny.so
password	required			pam_permit.so
password	optional			pam_gnome_keyring.so
EOF

    # configure authentication without nullok
    cat > /etc/pam.d/common-auth << 'EOF'
#
# /etc/pam.d/common-auth - authentication settings common to all services
#
auth    requisite       pam_faillock.so preauth
auth    [success=2 default=ignore] pam_unix.so try_first_pass
auth    [default=die]   pam_faillock.so authfail
auth    sufficient     pam_faillock.so authsucc
auth    requisite       pam_deny.so
auth    required        pam_permit.so
EOF
    
    echo -e "${GREEN}enhanced pam configuration complete${NC}"
}

# comprehensive audit configuration
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

    # identity monitoring
    cat > /etc/audit/rules.d/58-identity.rules << 'EOF'
# monitor user and group information changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
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
}

# install security tools and remove dangerous packages
install_security_tools() {
    echo -e "${BLUE}=== installing security tools ===${NC}"
    
    # update package lists
    apt-get update -qq
    
    if [ "$INSTALL_SECURITY_TOOLS" = true ]; then
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
            clamav-daemon \
            libpam-pwquality \
            libpam-cracklib \
            default-jdk \
            tshark
    fi
    
    # remove dangerous packages from answer key
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
        "doona"
        "xprobe"
    )
    
    echo -e "${BLUE}removing dangerous packages...${NC}"
    for package in "${DANGEROUS_PACKAGES[@]}"; do
        if dpkg -l | grep -q "^ii.*$package"; then
            echo "removing dangerous package: $package"
            apt-get purge -y "$package" 2>/dev/null || true
        fi
    done
    
    # remove games if specified
    if [ "$REMOVE_GAMES" = true ]; then
        echo "removing games..."
        apt-get purge -y \
            aisleriot \
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
    
    # cleanup
    apt-get autoremove -y
    apt-get autoclean
    
    echo -e "${GREEN}security tools installed and dangerous packages removed${NC}"
}

# configure gdm security
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

# secure user accounts - enhanced with answer key requirements
secure_user_accounts() {
    echo -e "${BLUE}=== fixing user accounts ===${NC}"
    
    # disable guest account
    echo "disabling guest..."
    
    # lightdm configuration
    if [ -f /etc/lightdm/lightdm.conf ]; then
        sed -i 's/#*allow-guest=.*/allow-guest=false/' /etc/lightdm/lightdm.conf
        grep -q "allow-guest=false" /etc/lightdm/lightdm.conf || echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
        
        sed -i 's/#*autologin-user=.*/autologin-user=/' /etc/lightdm/lightdm.conf
        sed -i 's/#*greeter-hide-users=.*/greeter-hide-users=true/' /etc/lightdm/lightdm.conf
        sed -i 's/#*greeter-show-manual-login=.*/greeter-show-manual-login=true/' /etc/lightdm/lightdm.conf
    fi
    
    # gdm3 configuration
    if [ -f /etc/gdm3/custom.conf ]; then
        sed -i '/\[daemon\]/a AutomaticLoginEnable=false' /etc/gdm3/custom.conf
        sed -i 's/AutomaticLoginEnable=true/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
    fi
    
    # identify unauthorized users but don't remove them automatically
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
        echo -e "${RED}the following users are not in your authorized users list:${NC}"
        for user in "${UNAUTHORIZED_USERS[@]}"; do
            echo -e "${RED}  - $user${NC}"
        done
        echo -e "${YELLOW}manual action required: review these users and remove if unauthorized${NC}"
        echo -e "${YELLOW}to remove a user: sudo deluser --remove-home username${NC}"
        echo -e "${YELLOW}report saved to: $UNAUTHORIZED_REPORT${NC}"
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
        echo -e "${RED}important: save these passwords somewhere safe!${NC}"
        for password_info in "${AUTO_GENERATED_PASSWORDS[@]}"; do
            echo -e "${GREEN}$password_info${NC}"
        done
        echo -e "${YELLOW}==================================${NC}\n"
        
        prompt_continue "passwords displayed above - did you save them?"
    fi
    
    # lock root password as per answer key
    echo -e "${BLUE}locking root password...${NC}"
    passwd -l root
    
    # set password aging for users as per answer key
    echo -e "${BLUE}setting password aging policies...${NC}"
    for user in $(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd); do
        chage -M 90 "$user" 2>/dev/null || true
        chage -m 7 "$user" 2>/dev/null || true
        chage -W 14 "$user" 2>/dev/null || true
        echo "set password aging for: $user"
    done
    
    # check for weird uid 0 users
    echo -e "${BLUE}checking for weird uid 0 users...${NC}"
    awk -F: '$3 == 0 && $1 != "root" {print "warning: weird uid 0 user: " $1}' /etc/passwd
    
    # check for empty passwords
    echo -e "${BLUE}checking for remaining empty passwords...${NC}"
    awk -F: '$2 == "" {print "warning: empty password: " $1}' /etc/shadow
    
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

# enhanced password policy based on answer key
configure_password_policy() {
    echo -e "${BLUE}=== fixing password policy ===${NC}"
    
    # configure login.defs with answer key requirements
    echo "configuring login.defs..."
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t10/' /etc/login.defs
    
    # add more security settings
    grep -q "FAILLOG_ENAB" /etc/login.defs || echo "FAILLOG_ENAB yes" >> /etc/login.defs
    grep -q "LOG_UNKFAIL_ENAB" /etc/login.defs || echo "LOG_UNKFAIL_ENAB yes" >> /etc/login.defs
    grep -q "SYSLOG_SU_ENAB" /etc/login.defs || echo "SYSLOG_SU_ENAB yes" >> /etc/login.defs
    grep -q "SYSLOG_SG_ENAB" /etc/login.defs || echo "SYSLOG_SG_ENAB yes" >> /etc/login.defs
    
    # apply password aging to all existing users
    echo "applying password aging to all users..."
    for user in $(awk -F: '$3 >= 0 {print $1}' /etc/passwd); do
        if [ "$user" != "root" ]; then
            chage -M 90 "$user" 2>/dev/null || true
            chage -m 7 "$user" 2>/dev/null || true
            chage -W 14 "$user" 2>/dev/null || true
        fi
    done
    
    echo -e "${GREEN}password policy configured${NC}"
}

# enhanced ssh hardening
harden_ssh() {
    echo -e "${BLUE}=== hardening ssh ===${NC}"
    
    if [ ! -f /etc/ssh/sshd_config ]; then
        echo "ssh not installed, skipping"
        return
    fi
    
    # backup ssh config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # configure ssh based on best practices
    cat > /etc/ssh/sshd_config << EOF
# ssh configuration
Port 22
Protocol 2

# host keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# privilege separation
UsePrivilegeSeparation yes

# authentication
LoginGraceTime 60
PermitRootLogin $([ "$DISABLE_SSH_ROOT" = true ] && echo "no" || echo "yes")
StrictModes yes
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60

# password authentication
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# kerberos and gssapi
KerberosAuthentication no
GSSAPIAuthentication no

# host based authentication
HostbasedAuthentication no
IgnoreUserKnownHosts yes
IgnoreRhosts yes

# disable unnecessary features
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

# crypto settings
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

# timeouts
ClientAliveInterval 300
ClientAliveCountMax 0
EOF

    # test ssh config
    if sshd -t 2>/dev/null; then
        echo -e "${GREEN}ssh config valid${NC}"
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    else
        echo -e "${RED}ssh config invalid, restoring backup${NC}"
        cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
        return 1
    fi
}

# manage services based on answer key
manage_services() {
    echo -e "${BLUE}=== managing services ===${NC}"
    
    # services to disable based on answer key
    SERVICES_TO_DISABLE=(
        "nginx"
        "squid"
        "squid3"
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
        "snmpd"
        "rsync"
    )
    
    # handle ftp services
    if [ "$DISABLE_FTP" = true ]; then
        echo "disabling ftp services..."
        for ftp_service in vsftpd proftpd pure-ftpd ftpd; do
            systemctl stop "$ftp_service" 2>/dev/null || true
            systemctl disable "$ftp_service" 2>/dev/null || true
        done
    else
        echo "keeping ftp services..."
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
    
    # enable security services
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

# enhanced firewall configuration
configure_firewall() {
    echo -e "${BLUE}=== setting up firewall ===${NC}"
    
    # install ufw
    apt-get install -y ufw
    
    # reset ufw
    ufw --force reset
    
    # configure loopback traffic
    echo "configuring loopback traffic..."
    ufw allow in on lo
    ufw allow out on lo
    ufw deny in from 127.0.0.0/8
    ufw deny in from ::1
    
    # set default policies
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
    
    # allow ssh
    ufw allow 22/tcp comment 'ssh'
    
    # enable logging
    ufw logging high
    
    # enable ufw
    ufw --force enable
    
    echo -e "${GREEN}firewall configured${NC}"
    ufw status verbose
}

# remove prohibited media files based on answer key
handle_media_files() {
    echo -e "${BLUE}=== handling media files ===${NC}"
    
    if [ "$REMOVE_MEDIA_FILES" = true ]; then
        echo -e "${RED}warning: removing entertainment media files!${NC}"
        echo -e "${GREEN}keeping system-critical image files${NC}"
        
        # remove ogg files as mentioned in answer key
        echo "removing prohibited ogg files..."
        find /home -name "*.ogg" -type f -delete 2>/dev/null || true
        
        # remove other media files
        echo -e "${YELLOW}finding audio/video files...${NC}"
        find /home -type f \( \
            -name "*.mp3" -o -name "*.mp4" -o -name "*.avi" -o \
            -name "*.mov" -o -name "*.wav" -o -name "*.wmv" -o \
            -name "*.flv" -o -name "*.m4a" -o \
            -name "*.mpg" -o -name "*.mpeg" -o -name "*.flac" -o \
            -name "*.mkv" -o -name "*.webm" -o -name "*.m4v" -o \
            -name "*.3gp" -o -name "*.aac" -o -name "*.wma" \
            \) -delete 2>/dev/null || true
        
        # remove large image files (likely personal photos)
        echo -e "${YELLOW}removing large image files (likely personal photos)...${NC}"
        find /home -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.bmp" -o -name "*.tiff" \) \
            -size +500k -delete 2>/dev/null || true
        
        echo -e "${GREEN}media files removed, system images preserved${NC}"
    else
        echo -e "${GREEN}keeping all media files${NC}"
    fi
}

# remove prohibited software archives
remove_prohibited_files() {
    echo -e "${BLUE}=== removing prohibited files and software ===${NC}"
    
    # remove pyrdp archive as mentioned in answer key
    echo "looking for prohibited archives..."
    find /usr -name "*.zip" -type f 2>/dev/null | while read -r zipfile; do
        if [[ "$zipfile" == *"pyrdp"* ]]; then
            echo "removing prohibited archive: $zipfile"
            rm -f "$zipfile"
        fi
    done
    
    # check for and remove backdoors
    echo "checking for backdoors..."
    if [ -f "/usr/share/zod/kneelB4zod.py" ]; then
        echo "removing zod backdoor..."
        rm -f /usr/share/zod/kneelB4zod.py
        pkill -f kneelB4zod.py 2>/dev/null || true
        rm -rf /usr/share/zod 2>/dev/null || true
    fi
    
    # remove other prohibited files
    echo "removing other prohibited files..."
    find /home -name ".rhosts" -delete 2>/dev/null || true
    find /home -name ".netrc" -delete 2>/dev/null || true
    
    echo -e "${GREEN}prohibited files removed${NC}"
}

# fix file permissions
secure_file_permissions() {
    echo -e "${BLUE}=== fixing file permissions ===${NC}"
    
    # fix important system files
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
    
    # find and fix world writable files
    echo -e "${BLUE}fixing world writable files...${NC}"
    find /etc /bin /sbin /usr/bin /usr/sbin -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null || true
    
    # find files without owner
    echo -e "${BLUE}finding files without owner...${NC}"
    find / -xdev \( -nouser -o -nogroup \) -print > /var/log/unowned_files.log 2>/dev/null || true
    
    echo -e "${GREEN}file permissions fixed${NC}"
}

# harden kernel based on answer key requirements
harden_kernel() {
    echo -e "${BLUE}=== hardening kernel ===${NC}"
    
    cat > /etc/sysctl.d/99-security.conf << EOF
# kernel hardening
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2

# address space layout randomization - answer key requirement
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

# icmp security
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1

# tcp syn cookies - answer key requirement
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5

# ipv6 configuration
$([ "$ENABLE_IPV6" = false ] && echo "net.ipv6.conf.all.disable_ipv6=1" || echo "# ipv6 enabled")
$([ "$ENABLE_IPV6" = false ] && echo "net.ipv6.conf.default.disable_ipv6=1" || echo "# ipv6 enabled")
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0

EOF

    # apply sysctl settings
    sysctl -p /etc/sysctl.d/99-security.conf
    
    echo -e "${GREEN}kernel hardened${NC}"
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
        echo -e "${GREEN}fail2ban configured${NC}"
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
        
        echo -e "${GREEN}scans complete, check /var/log/${NC}"
    else
        echo "security tools not installed"
    fi
}

# final comprehensive check
final_system_check() {
    echo -e "${BLUE}=== final system check ===${NC}"
    
    echo "checking file permissions..."
    ls -la /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null
    
    echo -e "\n${BLUE}service status:${NC}"
    systemctl is-active ufw auditd fail2ban 2>/dev/null || true
    
    echo -e "\n${BLUE}firewall status:${NC}"
    ufw status 2>/dev/null || echo "ufw not configured"
    
    echo -e "\n${BLUE}password policy:${NC}"
    grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE" /etc/login.defs
    
    echo -e "\n${BLUE}kernel security settings:${NC}"
    sysctl kernel.randomize_va_space 2>/dev/null || true
    sysctl net.ipv4.tcp_syncookies 2>/dev/null || true
    
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
        echo "auditd running with $(auditctl -l 2>/dev/null | wc -l) rules"
    else
        echo "auditd not running"
    fi
    
    echo -e "\n${YELLOW}remaining tasks:${NC}"
    echo "1. review unauthorized users report at /root/unauthorized_users_report.txt"
    echo "2. manually remove any unauthorized users with: deluser --remove-home username"
    echo "3. change all user passwords if not done"
    echo "4. verify user groups are correct"
    echo "5. setup firewall rules for your specific services"
    echo "6. check /var/log/auth.log for suspicious activity"
    echo "7. test everything works"
    echo "8. reboot the system"
    echo "9. verify gdm login banner appears (if configured)"
    echo "10. test audit logging with: ausearch -k sudoers"
}

# main function
main() {
    echo -e "${YELLOW}this script implements cyberpatriots training round 2 fixes${NC}"
    echo -e "${YELLOW}make sure to read the readme and complete forensics first${NC}"
    echo -e "${RED}read the readme and do forensics first!${NC}"
    
    prompt_continue "start hardening?"
    
    read_readme_config
    configure_user_management
    backup_files
    
    echo -e "\n${BLUE}starting enhanced hardening...${NC}\n"
    
    # install tools and remove dangerous packages first
    install_security_tools
    
    # cis compliance configurations
    configure_filesystem_modules
    configure_network_modules
    enhanced_apparmor_config
    configure_cron_permissions
    enhanced_pam_configuration
    comprehensive_audit_config
    
    # gdm security
    configure_gdm_security
    
    # core security configurations
    secure_user_accounts
    configure_password_policy
    harden_ssh
    manage_services
    configure_firewall
    
    # file and media handling
    handle_media_files
    remove_prohibited_files
    secure_file_permissions
    
    # kernel and system hardening
    harden_kernel
    
    # security tools and monitoring
    configure_fail2ban
    create_banners
    run_security_scan
    
    # final verification
    final_system_check
    
    echo -e "\n${GREEN}=== enhanced hardening complete ===${NC}"
    echo "finished: $(date)"
    echo -e "${YELLOW}next steps:${NC}"
    echo "1. check everything works"
    echo "2. review unauthorized users report"
    echo "3. manually remove any unauthorized users"
    echo "4. reboot the system"
    echo "5. verify gdm login banner appears"
    echo "6. test audit logging and other security features"
    echo "7. check logs in $LOG_FILE"
    
    # create summary report
    cat > /root/hardening_summary.txt << EOF
enhanced linux hardening summary
based on cyberpatriots training round 2 answer key
generated: $(date)

key improvements over original script:
- removed automatic updates 
- added all vulnerabilities from answer key
- enhanced password policies (minimum length 10, remember 3, account lockout)
- address space layout randomization enabled
- tcp syn cookies enabled
- comprehensive pam configuration using cracklib
- removed dangerous packages (doona, xprobe, etc)
- gdm security configuration with login banner
- prohibited file removal (ogg files, pyrdp archive, zod backdoor)
- enhanced user account management with password aging
- root password locking
- null password prevention
- firewall with proper default deny policies
- comprehensive audit logging
- cron permission hardening
- network/filesystem kernel module restrictions

configuration applied:
- remove media files: $REMOVE_MEDIA_FILES
- disable ftp: $DISABLE_FTP
- disable ssh root: $DISABLE_SSH_ROOT
- enable ipv6: $ENABLE_IPV6
- remove games: $REMOVE_GAMES
- install security tools: $INSTALL_SECURITY_TOOLS
- configure gdm: $CONFIGURE_GDM

files modified:
- /etc/passwd, /etc/shadow, /etc/group (user management)
- /etc/login.defs (password aging for all users)
- /etc/pam.d/common-password (password policy with cracklib)
- /etc/pam.d/common-auth (no nullok, account lockout)
- /etc/ssh/sshd_config (ssh hardening)
- /etc/sysctl.d/99-security.conf (kernel hardening, aslr, syn cookies)
- /etc/lightdm/lightdm.conf, /etc/gdm3/custom.conf (guest disable)
- /etc/dconf/profile/gdm, /etc/dconf/db/gdm.d/* (gdm security)
- /etc/issue, /etc/issue.net, /etc/motd (banners)
- /etc/audit/rules.d/* (comprehensive audit rules)
- /etc/fail2ban/jail.local (intrusion prevention)
- /etc/modprobe.d/filesystem.conf, /etc/modprobe.d/network.conf (module restrictions)

backup location: $BACKUP_DIR

logs and reports:
- unauthorized users: /root/unauthorized_users_report.txt
- security scans: /var/log/chkrootkit.log, /var/log/rkhunter.log, /var/log/lynis.log
- audit logs: /var/log/audit/
- unowned files: /var/log/unowned_files.log

next steps:
1. manually review and remove unauthorized users
2. reboot system to apply all changes
3. verify gdm login banner appears
4. test audit logging: ausearch -k sudoers
5. monitor logs for security events

this script addresses all vulnerabilities found in cyberpatriots training round 2
EOF

    echo -e "${GREEN}summary saved to: /root/hardening_summary.txt${NC}"
}

# run the enhanced script
main "$@"