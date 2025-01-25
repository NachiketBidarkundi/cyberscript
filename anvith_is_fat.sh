#!/bin/bash
# Secure Ubuntu/Linux Mint 21 Script for CyberPatriot

set -e  # Exit on errors

# Update system and install necessary packages
echo "Updating system and installing required packages..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y gufw clamav libpam-cracklib gedit nano locate bum

# Configure Updates
echo "Configuring updates..."
sudo sed -i "s/^.*Prompt=.*$/Prompt=never/" /etc/update-manager/release-upgrades
echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"7\";\nAPT::Periodic::Unattended-Upgrade \"1\";" | sudo tee /etc/apt/apt.conf.d/20auto-upgrades

# Enable and configure firewall
echo "Configuring firewall..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable

echo "Firewall configured: Incoming -> Deny, Outgoing -> Allow"

# Configure ClamAV for malware scanning
echo "Updating ClamAV database and running a scan..."
sudo freshclam
sudo clamscan -r /home --bell -i

echo "ClamAV scan completed."

# User management
echo "Checking user accounts..."
# List all users and prompt for removal of unnecessary accounts
awk -F':' '//home/ {print $1}' /etc/passwd | while read user; do
    echo "Checking user: $user"
    read -p "Do you want to remove user $user? (y/n) " choice
    if [ "$choice" == "y" ]; then
        sudo deluser --remove-home "$user"
        echo "Removed user: $user"
    fi
done

# Program Updates
echo "Ensuring all installed programs are up to date..."
sudo apt upgrade -y

echo "Programs updated."

# Firefox security configuration
echo "Configuring Firefox security settings..."
firefox &>/dev/null &
sleep 5
killall firefox
firefox_prefs="$(find ~/.mozilla/firefox -name prefs.js)"
echo 'user_pref("privacy.popups.showBrowserMessage", false);' | tee -a $firefox_prefs

echo "Firefox security configured."

# PAM configuration for password policies
echo "Configuring PAM for password policies..."
sudo sed -i '/pam_unix.so/s/$/ remember=5 minlen=8/' /etc/pam.d/common-password
sudo sed -i '/pam_cracklib.so/s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

# Login settings
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS    90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS    10/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE    7/' /etc/login.defs

# Enable Guest account restriction
echo "Disabling guest account..."
echo -e "allow-guest=false" | sudo tee -a /etc/lightdm/lightdm.conf

# Locate hidden files and suspicious programs
echo "Checking for hidden and media files..."
find / -name ".*" -type f -exec ls -lah {} \;
echo "Checking for suspicious programs..."
sudo locate "*nmap*" "*metasploit*" "*aircrack-ng*" "*wireshark*"

echo "Suspicious file search completed."

# Configure startup programs using BUM (boot-up manager)
echo "Configure startup programs using BUM. Launching BUM..."
bum

echo "Script execution completed. System should now be secure."
