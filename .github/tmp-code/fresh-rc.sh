#!/bin/bash
# $1 image tag, $2 recording name. Fresh Rocket.Chat + mongo, setup, Chromium recording.
set -e
cd $SW
${DK:-docker} network create rc >/dev/null 2>&1 || true
${DK:-docker} rm -f rc rc-mongo >/dev/null 2>&1 || true
${DK:-docker} run -d --name rc-mongo --network rc docker.io/library/mongo:8.0 --replSet rs0 --bind_ip_all >/dev/null
for i in $(seq 1 30); do ${DK:-docker} exec rc-mongo mongosh --quiet --eval 'try{rs.initiate({_id:"rs0",members:[{_id:0,host:"rc-mongo:27017"}]}).ok}catch(e){rs.status().ok}' >/dev/null 2>&1 && break; sleep 1; done
${DK:-docker} run -d --name rc --network rc -p 127.0.0.1:3000:3000 \
 -e MONGO_URL='mongodb://rc-mongo:27017/rocketchat?replicaSet=rs0' -e ROOT_URL=http://localhost:3000 -e PORT=3000 \
 -e ADMIN_USERNAME=admin -e ADMIN_PASS=Adm1n-pass-123 -e ADMIN_EMAIL=admin@example.com \
 -e OVERWRITE_SETTING_Show_Setup_Wizard=completed \
 -e OVERWRITE_SETTING_Accounts_TwoFactorAuthentication_Enabled=false \
 -e OVERWRITE_SETTING_Accounts_TwoFactorAuthentication_By_Email_Auto_Opt_In=false \
 -e OVERWRITE_SETTING_Accounts_TwoFactorAuthentication_By_Email_Enabled=false \
 docker.io/rocketchat/rocket.chat:$1 >/dev/null
for i in $(seq 1 150); do curl -sf localhost:3000/api/info >/dev/null && break; sleep 2; done
sleep 5
python3 rcsetup.py
NODE_PATH=${NODE_PATH:-$(npm root -g)} node ${REC:-rec-rc.js} $2.har
ls -la $2.har
