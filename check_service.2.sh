#!/bin/bash

if [ -z "$1" ]
then
     echo "Usage: $0 <service-name>"
     exit 1
fi


if systemctl is-active --quiet "$1"
then
     echo "$1 is already running"
else
     echo "$1 is not running"
     echo " Attempting to restart.."
     
     systemctl restart "$1"
     
     if systemctl is-active --quiet "$1"
     then
          echo "$1"
     else
          echo "Restart failed, sending logs:"
          journalctl -u "$1" -n 20 --no-pager
     fi
fi
