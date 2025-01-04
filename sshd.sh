#!/bin/bash

# Define the SSHD directory
SSHD_DIR="$HOME/.sshd"
CONFIG_FILE="$SSHD_DIR/sshd_config"
LOG_FILE="$SSHD_DIR/sshd.log"

# Ensure the .sshd directory exists
mkdir -p "$SSHD_DIR"

# Generate server keys if they don't exist
generate_key() {
  local key_type=$1
  local key_file="$SSHD_DIR/ssh_host_${key_type}_key"
  if [[ ! -f $key_file ]]; then
    echo "Generating $key_type key..."
    ssh-keygen -t $key_type -f "$key_file" -N "" >/dev/null 2>&1
  fi
}

generate_key rsa
generate_key dsa
generate_key ecdsa
generate_key ed25519

# Create a basic sshd_config if it doesn't exist
if [[ ! -f $CONFIG_FILE ]]; then
  echo "Creating sshd_config..."
  cat > "$CONFIG_FILE" <<EOF
# SSHD Config
Port 2222
HostKey $SSHD_DIR/ssh_host_rsa_key
HostKey $SSHD_DIR/ssh_host_dsa_key
HostKey $SSHD_DIR/ssh_host_ecdsa_key
HostKey $SSHD_DIR/ssh_host_ed25519_key
AuthorizedKeysFile $HOME/.ssh/authorized_keys
PermitRootLogin no
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM no
Subsystem sftp internal-sftp
PidFile $SSHD_DIR/sshd.pid
LogLevel INFO
# Redirect logs to a user-writable location
SyslogFacility AUTH
LogLevel INFO
EOF
fi

# Ensure a writable log file
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

# Start sshd with the specified configuration and log output
echo "Starting sshd..."
/usr/sbin/sshd -f "$CONFIG_FILE" -E "$LOG_FILE"

echo "sshd is running. Logs are being written to $LOG_FILE"
echo "Connect using: ssh -p 2222 <your_username>@localhost"
