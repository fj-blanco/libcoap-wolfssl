#!/bin/bash

# SEE: https://github.com/wolfSSL/wolfssl/blob/master/INSTALL

debug_mode=0

# Parse command-line options
while getopts "d" opt; do
  case $opt in
    d)
      debug_mode=1
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

# Dir for the current script
current_dir=$(pwd)
echo "Current dir: $current_dir"
liboqs_target_dir="/opt/liboqs"

# Prompt user for removal of existing installation
read -p "Do you want to remove existing installation? (y/n): " remove_existing
if [ "$remove_existing" == "y" ]; then
    echo "Removing existing installation..."
    sudo rm -rf /usr/local/include/oqs
    sudo rm -f /usr/local/lib/liboqs.a
    sudo rm -rf ${liboqs_target_dir}
fi

echo "Cloning liboqs..."

sudo mkdir -p ${liboqs_target_dir}
cd ${liboqs_target_dir}                                                                                                                                                                                 
sudo git clone --single-branch https://github.com/open-quantum-safe/liboqs.git
cd liboqs/                                                                          
sudo git checkout 0.8.0

if [ $debug_mode -eq 1 ]; then                                                                                                                                                                              
    # Disabled
fi

sudo mkdir build
cd build
sudo cmake -DOQS_USE_OPENSSL=0 ..
sudo make all
sudo make install