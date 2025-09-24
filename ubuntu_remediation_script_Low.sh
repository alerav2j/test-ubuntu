#!/bin/bash

#############################################################################
# Ubuntu 24.04 LTS STIG Remediation Script - Part 2
# LOW RISK - SEVERITY III FINDINGS
# 
# This script remediates all Severity III / Low Risk STIG findings
# Based on Ubuntu 24.04 STIG requirements
# Run with sudo/root privileges
# 
# Usage: sudo bash ubuntu24_stig_remediation_low.sh
#############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="$HOME/stig_remediation_low_$(date +%Y%m%d_%H%M%S).log"

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
        "warning-banner")
            if [ -f /etc/issue.net ] && grep -qi "authorized\|warning\|prohibited" /etc/issue.net 2>/dev/null; then
                return 0
            else
                return 1
            fi
            ;;
        "gdm-banner")
            if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "banner-message-enable=true" /etc/gdm3/greeter.dconf-defaults 2>/dev/null; then
                return 0
            else
                return 1
            fi
            ;;
        "vlock")
            if dpkg -l | grep -q "^ii.*vlock"; then
                return 0
            else
                return 1
            fi
            ;;
        "screen-lock")
            if command -v gsettings >/dev/null 2>&1; then
                lock_enabled=$(gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null)
                if [ "$lock_enabled" = "true" ]; then
                    return 0
                else
                    return 1
                fi
            else
                return 2  # Not applicable - no GUI
            fi
            ;;
        "idle-delay")
            if command -v gsettings >/dev/null 2>&1; then
                idle_delay=$(gsettings get org.gnome.desktop.session idle-delay 2>/dev/null | sed 's/[^0-9]//g')
                if [ -n "$idle_delay" ] && [ "$idle_delay" -le 900 ] && [ "$idle_delay" -gt 0 ]; then
                    return 0
                else
                    return 1
                fi
            else
                return 2  # Not applicable - no GUI
            fi
            ;;
        "lock-delay")
            if command -v gsettings >/dev/null 2>&1; then
                lock_delay=$(gsettings get org.gnome.desktop.screensaver lock-delay 2>/dev/null | sed 's/[^0-9]//g')
                if [ -n "$lock_delay" ] && [ "$lock_delay" -le 5 ]; then
                    return 0
                else
                    return 1
                fi
            else
                return 2  # Not applicable - no GUI
            fi
            ;;
        "umask")
            umask_ok=1
            for file in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
                if [ -f "$file" ]; then
                    umask_val=$(grep "^umask" "$file" 2>/dev/null | awk '{print $2}' | head -1)
                    if [ -n "$umask_val" ] && [ "$umask_val" != "077" ] && [ "$umask_val" != "027" ]; then
                        umask_ok=0
                        break
                    fi
                fi
            done
            return $((1 - umask_ok))
            ;;
        *)
            return 2
            ;;
    esac
}

# Check if running as root
check_root

log_message "${GREEN}Starting Ubuntu 24.04 LOW RISK STIG Remediation - $(date)${NC}"
log_message "Log file: $LOG_FILE"

#############################################################################
# V-270733: WARNING BANNER CONFIGURATION
#############################################################################

log_message "\n${YELLOW}=== V-270733: Configuring Warning Banner [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "warning-banner" "V-270733"; then
    log_message "${BLUE}V-270733: Warning banner already configured - already compliant${NC}"
else
    log_message "V-270733: Creating warning banner..."
    
    cat > /etc/issue << 'EOF'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF
    
    # Copy to /etc/issue.net for SSH
    cp /etc/issue /etc/issue.net
    
    # Configure SSH to use the banner
    backup_file /etc/ssh/sshd_config
    if ! grep -q "^Banner /etc/issue.net" /etc/ssh/sshd_config; then
        sed -i 's/^#*Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
        if ! grep -q "^Banner" /etc/ssh/sshd_config; then
            echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
        fi
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
    fi
    
    if check_compliance "warning-banner" "V-270733"; then
        log_message "${GREEN}V-270733: Warning banner configured successfully${NC}"
    else
        log_message "${RED}V-270733: Failed to configure warning banner${NC}"
    fi
fi

#############################################################################
# V-270734: GDM BANNER CONFIGURATION
#############################################################################

log_message "\n${YELLOW}=== V-270734: Configuring GDM Banner [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

# Check if GDM is installed
if dpkg -l | grep -q gdm3; then
    if check_compliance "gdm-banner" "V-270734"; then
        log_message "${BLUE}V-270734: GDM banner already configured - already compliant${NC}"
    else
        backup_file /etc/gdm3/greeter.dconf-defaults
        log_message "V-270734: Configuring GDM banner..."
        
        # Remove old banner configuration if exists
        sed -i '/\[org\/gnome\/login-screen\]/,/^$/d' /etc/gdm3/greeter.dconf-defaults 2>/dev/null
        
        cat >> /etc/gdm3/greeter.dconf-defaults << 'EOF'

[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. At any time, the USG may inspect and seize data stored on this IS. Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
disable-user-list=true
EOF
        
        # Update dconf
        dconf update
        
        if check_compliance "gdm-banner" "V-270734"; then
            log_message "${GREEN}V-270734: GDM banner configured successfully${NC}"
        else
            log_message "${RED}V-270734: Failed to configure GDM banner${NC}"
        fi
    fi
else
    log_message "${YELLOW}V-270734: GDM not installed - skipping GDM banner configuration${NC}"
fi

#############################################################################
# V-270735: VLOCK INSTALLATION
#############################################################################

log_message "\n${YELLOW}=== V-270735: Installing vlock [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "vlock" "V-270735"; then
    log_message "${BLUE}V-270735: vlock already installed - already compliant${NC}"
else
    log_message "V-270735: Installing vlock..."
    apt-get update
    apt-get install -y vlock
    
    if check_compliance "vlock" "V-270735"; then
        log_message "${GREEN}V-270735: vlock installed successfully${NC}"
    else
        log_message "${RED}V-270735: Failed to install vlock${NC}"
    fi
fi

#############################################################################
# V-270737: SCREEN LOCK ON SUSPEND
#############################################################################

log_message "\n${YELLOW}=== V-270737: Configuring Screen Lock on Suspend [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if command -v gsettings >/dev/null 2>&1; then
    if check_compliance "screen-lock" "V-270737"; then
        log_message "${BLUE}V-270737: Screen lock on suspend already enabled - already compliant${NC}"
    else
        log_message "V-270737: Enabling screen lock on suspend..."
        gsettings set org.gnome.desktop.screensaver lock-enabled true
        
        # Also configure via dconf for system-wide setting
        mkdir -p /etc/dconf/db/local.d
        cat > /etc/dconf/db/local.d/00-screensaver << 'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
EOF
        dconf update
        
        if check_compliance "screen-lock" "V-270737"; then
            log_message "${GREEN}V-270737: Screen lock on suspend enabled successfully${NC}"
        else
            log_message "${RED}V-270737: Failed to enable screen lock on suspend${NC}"
        fi
    fi
else
    log_message "${YELLOW}V-270737: GNOME not installed - skipping screen lock configuration${NC}"
fi

#############################################################################
# V-270738: SCREEN LOCK DELAY
#############################################################################

log_message "\n${YELLOW}=== V-270738: Configuring Screen Lock Delay [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if command -v gsettings >/dev/null 2>&1; then
    if check_compliance "lock-delay" "V-270738"; then
        log_message "${BLUE}V-270738: Screen lock delay already configured - already compliant${NC}"
    else
        log_message "V-270738: Setting screen lock delay to 5 seconds..."
        gsettings set org.gnome.desktop.screensaver lock-delay 5
        
        # Also configure via dconf for system-wide setting
        cat >> /etc/dconf/db/local.d/00-screensaver << 'EOF'
lock-delay=5
EOF
        dconf update
        
        if check_compliance "lock-delay" "V-270738"; then
            log_message "${GREEN}V-270738: Screen lock delay configured successfully${NC}"
        else
            log_message "${RED}V-270738: Failed to configure screen lock delay${NC}"
        fi
    fi
else
    log_message "${YELLOW}V-270738: GNOME not installed - skipping screen lock delay configuration${NC}"
fi

#############################################################################
# V-270739: IDLE ACTIVATION
#############################################################################

log_message "\n${YELLOW}=== V-270739: Configuring Idle Activation [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if command -v gsettings >/dev/null 2>&1; then
    idle_enabled=$(gsettings get org.gnome.desktop.screensaver idle-activation-enabled 2>/dev/null)
    if [ "$idle_enabled" = "true" ]; then
        log_message "${BLUE}V-270739: Idle activation already enabled - already compliant${NC}"
    else
        log_message "V-270739: Enabling idle activation..."
        gsettings set org.gnome.desktop.screensaver idle-activation-enabled true
        
        # Also configure via dconf
        cat >> /etc/dconf/db/local.d/00-screensaver << 'EOF'
idle-activation-enabled=true
EOF
        dconf update
        
        log_message "${GREEN}V-270739: Idle activation enabled successfully${NC}"
    fi
else
    log_message "${YELLOW}V-270739: GNOME not installed - skipping idle activation configuration${NC}"
fi

#############################################################################
# V-270740: IDLE DELAY
#############################################################################

log_message "\n${YELLOW}=== V-270740: Configuring Idle Delay [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if command -v gsettings >/dev/null 2>&1; then
    if check_compliance "idle-delay" "V-270740"; then
        log_message "${BLUE}V-270740: Idle delay already configured - already compliant${NC}"
    else
        log_message "V-270740: Setting idle delay to 900 seconds (15 minutes)..."
        gsettings set org.gnome.desktop.session idle-delay 900
        
        # Also configure via dconf for system-wide setting
        mkdir -p /etc/dconf/db/local.d
        cat > /etc/dconf/db/local.d/01-idle << 'EOF'
[org/gnome/desktop/session]
idle-delay=900
EOF
        dconf update
        
        if check_compliance "idle-delay" "V-270740"; then
            log_message "${GREEN}V-270740: Idle delay configured successfully${NC}"
        else
            log_message "${RED}V-270740: Failed to configure idle delay${NC}"
        fi
    fi
else
    log_message "${YELLOW}V-270740: GNOME not installed - skipping idle delay configuration${NC}"
fi

#############################################################################
# V-270825: DEFAULT UMASK CONFIGURATION
#############################################################################

log_message "\n${YELLOW}=== V-270825: Configuring Default umask [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

if check_compliance "umask" "V-270825"; then
    log_message "${BLUE}V-270825: Default umask already configured - already compliant${NC}"
else
    log_message "V-270825: Setting default umask to 077..."
    
    # Set umask in /etc/bash.bashrc
    backup_file /etc/bash.bashrc
    if ! grep -q "^umask 077" /etc/bash.bashrc; then
        sed -i '/^umask/d' /etc/bash.bashrc
        echo "umask 077" >> /etc/bash.bashrc
    fi
    
    # Set umask in /etc/profile
    backup_file /etc/profile
    if ! grep -q "^umask 077" /etc/profile; then
        sed -i '/^umask/d' /etc/profile
        echo "umask 077" >> /etc/profile
    fi
    
    # Set umask in /etc/login.defs
    backup_file /etc/login.defs
    sed -i 's/^UMASK.*/UMASK           077/' /etc/login.defs
    
    # Set umask for all profile.d scripts
    for file in /etc/profile.d/*.sh; do
        if [ -f "$file" ] && grep -q "^umask" "$file"; then
            backup_file "$file"
            sed -i 's/^umask.*/umask 077/' "$file"
        fi
    done
    
    if check_compliance "umask" "V-270825"; then
        log_message "${GREEN}V-270825: Default umask configured successfully${NC}"
    else
        log_message "${RED}V-270825: Failed to configure default umask${NC}"
    fi
fi

#############################################################################
# SSH LOG LEVEL CONFIGURATION (LOW SEVERITY)
#############################################################################

log_message "\n${YELLOW}=== V-270724: Configuring SSH Log Level [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

loglevel=$(grep -i "^LogLevel" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ "$loglevel" = "INFO" ] || [ "$loglevel" = "VERBOSE" ]; then
    log_message "${BLUE}V-270724: SSH LogLevel already configured - already compliant${NC}"
else
    backup_file /etc/ssh/sshd_config
    log_message "V-270724: Setting SSH LogLevel to VERBOSE..."
    
    sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
    if ! grep -q "^LogLevel" /etc/ssh/sshd_config; then
        echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
    fi
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
    log_message "${GREEN}V-270724: SSH LogLevel configured successfully${NC}"
fi

#############################################################################
# ADDITIONAL DISPLAY/GUI SETTINGS (LOW SEVERITY)
#############################################################################

log_message "\n${YELLOW}=== Additional Display Settings [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

# Disable user list in GDM (if installed)
if dpkg -l | grep -q gdm3; then
    if ! grep -q "disable-user-list=true" /etc/gdm3/greeter.dconf-defaults 2>/dev/null; then
        log_message "Disabling user list in GDM login screen..."
        echo "disable-user-list=true" >> /etc/gdm3/greeter.dconf-defaults
        dconf update
        log_message "${GREEN}GDM user list disabled${NC}"
    else
        log_message "${BLUE}GDM user list already disabled${NC}"
    fi
fi

# Configure automatic screen lock for all users
if command -v gsettings >/dev/null 2>&1; then
    # Create a profile for all users
    mkdir -p /etc/dconf/profile
    cat > /etc/dconf/profile/user << 'EOF'
user-db:user
system-db:local
EOF
    
    # Lock down screen saver settings
    mkdir -p /etc/dconf/db/local.d/locks
    cat > /etc/dconf/db/local.d/locks/screensaver << 'EOF'
# Lock screen saver settings
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/session/idle-delay
EOF
    
    dconf update
    log_message "${GREEN}Screen lock settings locked for all users${NC}"
fi

#############################################################################
# MOTD AND ISSUE FILES
#############################################################################

log_message "\n${YELLOW}=== Configuring MOTD Files [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

# Remove default Ubuntu MOTD files that might leak information
for file in /etc/update-motd.d/*; do
    if [ -f "$file" ] && [ "$file" != "/etc/update-motd.d/00-header" ]; then
        chmod -x "$file" 2>/dev/null
    fi
done

# Create a simple MOTD
cat > /etc/motd << 'EOF'
###############################################################################
#                            AUTHORIZED ACCESS ONLY                           #
###############################################################################
# Unauthorized access to this system is prohibited and will be prosecuted     #
# to the fullest extent of the law. All activities are monitored and logged.  #
###############################################################################
EOF

log_message "${GREEN}MOTD files configured${NC}"

#############################################################################
# PERMISSION FIXES FOR LOW SEVERITY FILES
#############################################################################

log_message "\n${YELLOW}=== Setting File Permissions (Low Severity) [$(date +%Y-%m-%d\ %H:%M:%S)] ===${NC}"

# Set proper permissions on initialization files
files_to_check=(
    "/etc/bash.bashrc:644"
    "/etc/profile:644"
    "/etc/environment:644"
    "/etc/motd:644"
    "/etc/issue:644"
    "/etc/issue.net:644"
)

for file_perm in "${files_to_check[@]}"; do
    file="${file_perm%:*}"
    perm="${file_perm#*:}"
    
    if [ -f "$file" ]; then
        current_perm=$(stat -c %a "$file")
        if [ "$current_perm" != "$perm" ]; then
            chmod "$perm" "$file"
            log_message "${GREEN}Set $file permissions to $perm${NC}"
        else
            log_message "${BLUE}$file permissions already $perm${NC}"
        fi
    fi
done

#############################################################################
# FINAL SUMMARY
#############################################################################

log_message "\n${GREEN}================================${NC}"
log_message "${GREEN}LOW RISK STIG Remediation Completed${NC}"
log_message "${GREEN}================================${NC}"

log_message "\n${YELLOW}Summary of LOW RISK remediations:${NC}"
log_message "• V-270733: Warning banner configuration"
log_message "• V-270734: GDM banner configuration"
log_message "• V-270735: vlock installation"
log_message "• V-270737-V-270740: Screen lock and idle settings"
log_message "• V-270724: SSH logging configuration"
log_message "• V-270825: Default umask configuration"
log_message "• MOTD and issue file updates"
log_message "• File permission corrections"

log_message "\n${YELLOW}NOTE:${NC}"
log_message "These are low-risk findings that improve security posture"
log_message "but are not critical to system security."

log_message "\n${YELLOW}Log file saved to: $LOG_FILE${NC}"
log_message "\n${GREEN}Run the compliance script to verify all fixes were applied successfully${NC}"

exit 0