# $1 out prefix. Fresh Mattermost 12.0.2, setup, HAR from alice's API requests, sweep with the bundle spec.
cd $SW
${DK:-docker} rm -f mm >/dev/null 2>&1; ${DK:-docker} run -d --name mm -p 127.0.0.1:8065:8065 ${MMIMG:-docker.io/mattermost/mattermost-preview:12.0.2} >/dev/null
until curl -sf localhost:8065/api/v4/system/ping >/dev/null; do sleep 3; done
sleep 5
python3 -I mmsetup.py > $1-setup.txt 2>&1 && python3 -I mkhar-mm.py $1.har >> $1-setup.txt 2>&1 || { echo setup failed; tail $1-setup.txt; exit 1; }
SB=bob-mm.session SC=carol-mm.session GAP=0 bash runall.sh $1 http://localhost:8065 $1 $SW/spec/mm-bundle.yaml
