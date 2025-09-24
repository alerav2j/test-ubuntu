#!/bin/bash

#############################################################################
# Ubuntu 24.04 LTS STIG Remediation Script - Part 1
# HIGH RISK - SEVERITY I FINDINGS
# 
# This script remediates all Severity I / High Risk STIG findings
# Based on Ubuntu 24.04 STIG requirements
# Run with sudo/root privileges
# 
# Usage: sudo bash ubuntu24_stig_remediation_high.sh
#############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="$HOME/stig_remediation_high_$(date +%Y%m%d_%H%M%S).log"

# Function to log messages
log_message() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

# Function to backup files before modification
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        cp "$file" "${file}.bak.$(date +%Y%m%d_%H%M%S)"
        log_message "${GREEN}Backed up $file${NC}"
    fi
}

# Function to check compliance (matches compliance script checks)
check_compliance() {
    local check_name=$1
    local vid=$2
    
    case $check_name in
        "telnet")
            if dpkg -l | grep -q "^ii.*telnetd"; then
                return 1
            else
                return 0
            fi
            ;;
        "rsh-server")
            if dpkg -l | grep -q "rsh-server\|rsh-client"; then
                return 1
            else
                return 0
            fi
            ;;
        "ssh-installed")
            if dpkg -l | grep -q "openssh-server\|^ii.*ssh[[:space:]]"; then
                return 0
            else
                return 1
            fi
            ;;
        "ssh-service")
            ssh_enabled=$(systemctl is-enabled ssh 2>/dev/null || systemctl is-enabled sshd 2>/dev/null || echo "disabled")
            ssh_active=$(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || echo "inactive")
            if [ "$ssh_enabled" = "enabled" ] && [ "$ssh_active" = "active" ]; then
                return 0
            else
                return 1
            fi
            ;;
        "x11-forwarding")
            x11_forwarding=$(grep -i "^X11Forwarding" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
            if [ "$x11_forwarding" = "no" ] || [ -z "$x11_forwarding" ]; then
                return 0
            else
                return 1
            fi
            ;;
        "blank-passwords")
            blank_pwd=$(awk -F: '!$2 {print $1}' /etc/shadow 2>/dev/null | wc -l)
            if [ "$blank_pwd" -eq 0 ]; then
                return 0
            else
                return 1
            fi
            ;;
        "pam-nullok")
            if grep -q "nullok" /etc/pam.d/common-password 2>/dev/null; then
                return 1
            else
                return 0
            fi
            ;;
        "ssh-empty-passwords")
            permit_empty=$(grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
            if [ "$permit_empty" = "no" ] || [ -z "$permit_empty" ]; then
                return 0
            else
                return 1
            fi
            ;;
        "grub-password")
            if grep -q "^set superusers" /boot/grub/grub.cfg 2>/dev/null || grep -q "^password" /etc/grub.d/* 2>/dev/null; then
                return 0
            else
                return 1
            fi
            ;;
        "auditd")
            if dpkg -l | grep -q "^ii.*auditd"; then
                return 0
            else
                return 1
            fi
            ;;
        *)
            return 2
            ;;
    esac
}

# Check if running as root
check_root

log_message "${GREEN}Starting Ubuntu 24.04 HIGH RISK STIG Remediation - $(date)${NC}"
log_message "Log file: $LOG_FILE"

#############################################################################
# V-270647: TELNET PACKAGE REMOVAL
#############################################################################

log_message "\n${YELLOW}=== V-270647: Removing telnet package [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "telnet" "V-270647"; then
    log_message "${BLUE}V-270647: telnet not installed - already compliant${NC}"
else
    log_message "V-270647: Removing telnet package..."
    apt-get remove -y telnetd telnet 2>/dev/null
    apt-get purge -y telnetd telnet 2>/dev/null
    if check_compliance "telnet" "V-270647"; then
        log_message "${GREEN}V-270647: telnet removed successfully${NC}"
    else
        log_message "${RED}V-270647: Failed to remove telnet${NC}"
    fi
fi

#############################################################################
# V-270648: RSH-SERVER PACKAGE REMOVAL
#############################################################################

log_message "\n${YELLOW}=== V-270648: Removing rsh-server package [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "rsh-server" "V-270648"; then
    log_message "${BLUE}V-270648: rsh-server not installed - already compliant${NC}"
else
    log_message "V-270648: Removing rsh-server and rsh-client packages..."
    apt-get remove -y rsh-server rsh-client rsh-redone-server rsh-redone-client 2>/dev/null
    apt-get purge -y rsh-server rsh-client rsh-redone-server rsh-redone-client 2>/dev/null
    if check_compliance "rsh-server" "V-270648"; then
        log_message "${GREEN}V-270648: rsh-server removed successfully${NC}"
    else
        log_message "${RED}V-270648: Failed to remove rsh-server${NC}"
    fi
fi

#############################################################################
# V-270665: SSH INSTALLATION
#############################################################################

log_message "\n${YELLOW}=== V-270665: Installing SSH [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "ssh-installed" "V-270665"; then
    log_message "${BLUE}V-270665: SSH already installed - already compliant${NC}"
else
    log_message "V-270665: Installing SSH meta-package..."
    apt-get update
    apt-get install -y ssh openssh-server openssh-client
    if check_compliance "ssh-installed" "V-270665"; then
        log_message "${GREEN}V-270665: SSH installed successfully${NC}"
    else
        log_message "${RED}V-270665: Failed to install SSH${NC}"
    fi
fi

#############################################################################
# V-270666: SSH SERVICE ENABLEMENT
#############################################################################

log_message "\n${YELLOW}=== V-270666: Enabling SSH Service [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "ssh-service" "V-270666"; then
    log_message "${BLUE}V-270666: SSH service already enabled and active - already compliant${NC}"
else
    log_message "V-270666: Enabling and starting SSH service..."
    systemctl enable ssh.service
    systemctl start ssh.service
    # Also try sshd if ssh doesn't work
    systemctl enable sshd.service 2>/dev/null
    systemctl start sshd.service 2>/dev/null
    if check_compliance "ssh-service" "V-270666"; then
        log_message "${GREEN}V-270666: SSH service enabled and started successfully${NC}"
    else
        log_message "${RED}V-270666: Failed to enable SSH service${NC}"
    fi
fi

#############################################################################
# V-270675: GRUB PASSWORD CONFIGURATION
#############################################################################

log_message "\n${YELLOW}=== V-270675: GRUB Password Configuration [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "grub-password" "V-270675"; then
    log_message "${BLUE}V-270675: GRUB password already configured - already compliant${NC}"
else
    log_message "${YELLOW}V-270675: GRUB password configuration requires manual setup${NC}"
    log_message "${YELLOW}Run: grub-mkpasswd-pbkdf2 to generate password hash${NC}"
    log_message "${YELLOW}Then add to /etc/grub.d/40_custom:${NC}"
    log_message "${YELLOW}  set superusers=\"root\"${NC}"
    log_message "${YELLOW}  password_pbkdf2 root <hash>${NC}"
    log_message "${YELLOW}Then run: update-grub${NC}"
    
    # Create template file for admin
    cat > /tmp/grub_password_template.txt << 'EOF'
#!/bin/sh
# Add these lines to /etc/grub.d/40_custom after generating password hash
# Run: grub-mkpasswd-pbkdf2
# Then add:
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.HASH_HERE
EOF
    log_message "${GREEN}V-270675: Template saved to /tmp/grub_password_template.txt${NC}"
fi

#############################################################################
# V-270708: DISABLE X11 FORWARDING
#############################################################################

log_message "\n${YELLOW}=== V-270708: Disabling X11 Forwarding [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "x11-forwarding" "V-270708"; then
    log_message "${BLUE}V-270708: X11 forwarding already disabled - already compliant${NC}"
else
    backup_file /etc/ssh/sshd_config
    log_message "V-270708: Disabling X11 forwarding..."
    
    # Remove or comment out existing X11Forwarding lines
    sed -i 's/^X11Forwarding.*/#&/' /etc/ssh/sshd_config
    
    # Add explicit disable
    echo "X11Forwarding no" >> /etc/ssh/sshd_config
    
    # Restart SSH service
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
    
    if check_compliance "x11-forwarding" "V-270708"; then
        log_message "${GREEN}V-270708: X11 forwarding disabled successfully${NC}"
    else
        log_message "${RED}V-270708: Failed to disable X11 forwarding${NC}"
    fi
fi

#############################################################################
# V-270713: NO BLANK PASSWORDS
#############################################################################

log_message "\n${YELLOW}=== V-270713: Checking for Blank Passwords [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "blank-passwords" "V-270713"; then
    log_message "${BLUE}V-270713: No blank passwords found - already compliant${NC}"
else
    log_message "V-270713: Accounts with blank passwords found - locking accounts..."
    
    # Find and lock accounts with blank passwords
    for user in $(awk -F: '!$2 {print $1}' /etc/shadow); do
        log_message "V-270713: Locking account: $user"
        passwd -l "$user"
    done
    
    if check_compliance "blank-passwords" "V-270713"; then
        log_message "${GREEN}V-270713: All blank password accounts locked successfully${NC}"
    else
        log_message "${RED}V-270713: Failed to lock all blank password accounts${NC}"
    fi
fi

#############################################################################
# V-270714: REMOVE PAM NULLOK
#############################################################################

log_message "\n${YELLOW}=== V-270714: Removing PAM nullok Option [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "pam-nullok" "V-270714"; then
    log_message "${BLUE}V-270714: PAM nullok already disabled - already compliant${NC}"
else
    backup_file /etc/pam.d/common-password
    backup_file /etc/pam.d/common-auth
    backup_file /etc/pam.d/common-account
    
    log_message "V-270714: Removing nullok from PAM configuration..."
    
    # Remove nullok from all PAM files
    for pam_file in /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/system-auth; do
        if [ -f "$pam_file" ]; then
            sed -i 's/nullok//g' "$pam_file"
            sed -i 's/  */ /g' "$pam_file"  # Clean up double spaces
        fi
    done
    
    if check_compliance "pam-nullok" "V-270714"; then
        log_message "${GREEN}V-270714: PAM nullok removed successfully${NC}"
    else
        log_message "${RED}V-270714: Failed to remove PAM nullok${NC}"
    fi
fi

#############################################################################
# V-270717: SSH PERMIT EMPTY PASSWORDS
#############################################################################

log_message "\n${YELLOW}=== V-270717: Disabling SSH Empty Passwords [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "ssh-empty-passwords" "V-270717"; then
    log_message "${BLUE}V-270717: SSH empty passwords already disabled - already compliant${NC}"
else
    backup_file /etc/ssh/sshd_config
    log_message "V-270717: Disabling SSH empty passwords..."
    
    # Remove or comment existing PermitEmptyPasswords lines
    sed -i 's/^PermitEmptyPasswords.*/#&/' /etc/ssh/sshd_config
    
    # Add explicit disable
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
    
    # Restart SSH service
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
    
    if check_compliance "ssh-empty-passwords" "V-270717"; then
        log_message "${GREEN}V-270717: SSH empty passwords disabled successfully${NC}"
    else
        log_message "${RED}V-270717: Failed to disable SSH empty passwords${NC}"
    fi
fi

#############################################################################
# V-270676: AUDITD INSTALLATION
#############################################################################

log_message "\n${YELLOW}=== V-270676: Installing auditd [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "auditd" "V-270676"; then
    log_message "${BLUE}V-270676: auditd already installed - already compliant${NC}"
else
    log_message "V-270676: Installing auditd and audispd-plugins..."
    apt-get update
    apt-get install -y auditd audispd-plugins
    
    if check_compliance "auditd" "V-270676"; then
        log_message "${GREEN}V-270676: auditd installed successfully${NC}"
        
        # Enable and start auditd
        systemctl enable auditd
        systemctl start auditd
        log_message "${GREEN}V-270676: auditd service enabled and started${NC}"
    else
        log_message "${RED}V-270676: Failed to install auditd${NC}"
    fi
fi

#############################################################################
# ADDITIONAL HIGH RISK SSH CONFIGURATIONS
#############################################################################

log_message "\n${YELLOW}=== Additional High Risk SSH Configurations [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

needs_ssh_restart=false

# V-270715: Disable HostbasedAuthentication
hostbased=$(grep -i "^HostbasedAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ "$hostbased" = "no" ] || [ -z "$hostbased" ]; then
    log_message "${BLUE}V-270715: HostbasedAuthentication already disabled - compliant${NC}"
else
    sed -i 's/^HostbasedAuthentication.*/#&/' /etc/ssh/sshd_config
    echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
    needs_ssh_restart=true
    log_message "${GREEN}V-270715: HostbasedAuthentication disabled${NC}"
fi

# V-270716: Enable IgnoreRhosts
ignore_rhosts=$(grep -i "^IgnoreRhosts" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ "$ignore_rhosts" = "yes" ] || [ -z "$ignore_rhosts" ]; then
    log_message "${BLUE}V-270716: IgnoreRhosts already enabled - compliant${NC}"
else
    sed -i 's/^IgnoreRhosts.*/#&/' /etc/ssh/sshd_config
    echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
    needs_ssh_restart=true
    log_message "${GREEN}V-270716: IgnoreRhosts enabled${NC}"
fi

# V-270718: Disable PermitUserEnvironment
permit_user_env=$(grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ "$permit_user_env" = "no" ] || [ -z "$permit_user_env" ]; then
    log_message "${BLUE}V-270718: PermitUserEnvironment already disabled - compliant${NC}"
else
    sed -i 's/^PermitUserEnvironment.*/#&/' /etc/ssh/sshd_config
    echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
    needs_ssh_restart=true
    log_message "${GREEN}V-270718: PermitUserEnvironment disabled${NC}"
fi

# V-270719: Disable PermitRootLogin
permit_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ "$permit_root" = "no" ]; then
    log_message "${BLUE}V-270719: PermitRootLogin already disabled - compliant${NC}"
else
    sed -i 's/^PermitRootLogin.*/#&/' /etc/ssh/sshd_config
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    needs_ssh_restart=true
    log_message "${GREEN}V-270719: PermitRootLogin disabled${NC}"
fi

# V-270709: Enable UsePrivilegeSeparation (if applicable for older SSH versions)
priv_sep=$(grep -i "^UsePrivilegeSeparation" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ -n "$priv_sep" ] && [ "$priv_sep" != "yes" ] && [ "$priv_sep" != "sandbox" ]; then
    sed -i 's/^UsePrivilegeSeparation.*/#&/' /etc/ssh/sshd_config
    echo "UsePrivilegeSeparation sandbox" >> /etc/ssh/sshd_config
    needs_ssh_restart=true
    log_message "${GREEN}V-270709: UsePrivilegeSeparation enabled${NC}"
else
    log_message "${BLUE}V-270709: UsePrivilegeSeparation already configured - compliant${NC}"
fi

# V-270710: Enable StrictModes
strict_modes=$(grep -i "^StrictModes" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ "$strict_modes" = "yes" ] || [ -z "$strict_modes" ]; then
    log_message "${BLUE}V-270710: StrictModes already enabled - compliant${NC}"
else
    sed -i 's/^StrictModes.*/#&/' /etc/ssh/sshd_config
    echo "StrictModes yes" >> /etc/ssh/sshd_config
    needs_ssh_restart=true
    log_message "${GREEN}V-270710: StrictModes enabled${NC}"
fi

# Restart SSH if needed
if [ "$needs_ssh_restart" = true ]; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
    log_message "${GREEN}SSH service restarted to apply changes${NC}"
fi

#############################################################################
# V-270711 & V-270712: DISABLE CTRL-ALT-DELETE
#############################################################################

log_message "\n${YELLOW}=== V-270711/V-270712: Disabling Ctrl-Alt-Delete [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if systemctl is-enabled ctrl-alt-del.target 2>/dev/null | grep -q "masked"; then
    log_message "${BLUE}V-270711/V-270712: Ctrl-Alt-Delete already masked - compliant${NC}"
else
    log_message "V-270711/V-270712: Masking Ctrl-Alt-Delete target..."
    systemctl mask ctrl-alt-del.target
    systemctl daemon-reload
    log_message "${GREEN}V-270711/V-270712: Ctrl-Alt-Delete masked successfully${NC}"
fi

#############################################################################
# FINAL SUMMARY
#############################################################################

log_message "\n${GREEN}================================${NC}"
log_message "${GREEN}HIGH RISK STIG Remediation Completed${NC}"
log_message "${GREEN}================================${NC}"

log_message "\n${YELLOW}Summary of HIGH RISK remediations:${NC}"
log_message "• V-270647: telnet package removal"
log_message "• V-270648: rsh-server package removal"
log_message "• V-270665: SSH installation"
log_message "• V-270666: SSH service enablement"
log_message "• V-270675: GRUB password (manual action required)"
log_message "• V-270676: auditd installation"
log_message "• V-270708: X11 forwarding disabled"
log_message "• V-270709-V-270710: SSH privilege separation and strict modes"
log_message "• V-270711-V-270712: Ctrl-Alt-Delete disabled"
log_message "• V-270713: Blank passwords locked"
log_message "• V-270714: PAM nullok removed"
log_message "• V-270715-V-270719: SSH security settings"

log_message "\n${YELLOW}IMPORTANT: Manual actions may be required for:${NC}"
log_message "1. GRUB password configuration (V-270675)"
log_message "2. Review SSH configuration before closing session"
log_message "3. Verify audit rules are properly configured"

log_message "\n${YELLOW}Log file saved to: $LOG_FILE${NC}"
log_message "\n${GREEN}Run the compliance script to verify all fixes were applied successfully${NC}"

exit 0