#!/bin/bash

# Git commit and push
git add .
git commit -m "Update: $(date +"%Y-%m-%d %H:%M:%S")"
git push origin main

# SSH to server and deploy
ssh -t root@45.32.39.38 "cd /var/www/engineer-matching && git pull origin main && systemctl restart nginx"
