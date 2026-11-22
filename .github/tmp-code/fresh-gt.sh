#!/bin/bash
set -e
cd $SW
${DK:-docker} rm -f gt >/dev/null 2>&1 || true
${DK:-docker} run -d --name gt -p 127.0.0.1:3001:3000 -e GITEA__security__INSTALL_LOCK=true -e GITEA__database__DB_TYPE=sqlite3 -e GITEA__server__ROOT_URL=http://127.0.0.1:3001/ docker.io/gitea/gitea:1.24.6 >/dev/null
for i in $(seq 1 60); do curl -sf -o /dev/null http://127.0.0.1:3001/ && break; sleep 2; done
for u in alice bob carol; do ${DK:-docker} exec -u git gt gitea admin user create --username $u --password "Passw0rd!x1" --email $u@siegekit.test --must-change-password=false >/dev/null 2>&1; done
A='-u alice:Passw0rd!x1 -H Content-Type:application/json'
curl -s $A http://127.0.0.1:3001/api/v1/user/repos -d '{"name":"priv","private":true,"auto_init":true}' -o /dev/null -w 'repo %{http_code}\n'
curl -s $A -X PUT http://127.0.0.1:3001/api/v1/repos/alice/priv/collaborators/bob -d '{"permission":"write"}' -o /dev/null -w 'collab %{http_code}\n'
curl -s $A http://127.0.0.1:3001/api/v1/repos/alice/priv/issues -d '{"title":"seed issue","body":"secret"}' -o /dev/null -w 'issue %{http_code}\n'
NODE_PATH=${NODE_PATH:-$(npm root -g)} node rec-gt.js $1.har
