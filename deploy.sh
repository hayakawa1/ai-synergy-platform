#!/bin/bash

# Git commit and push
git add .
git commit -m "Update: $(date +"%Y-%m-%d %H:%M:%S")"
git push origin main

# SSH to server and deploy
sshpass -p "Sy(3iP8iFBCM=rhm" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no root@45.32.39.38 "cd /var/www/ais.bit-co.jp && git fetch origin && git reset --hard origin/main && systemctl restart nginx"
