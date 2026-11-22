# $1 app (rc6 rc8 mm gt). Fresh app and recording, then the sweep from server code, no spec.
cd $SW
case $1 in
rc6|rc8) tag=$([ $1 = rc6 ] && echo 6.13.1 || echo 8.9.1); rec=$([ $1 = rc6 ] && echo rec-rc.js || echo rec-rc-ro.js)
  REC=$rec bash fresh-rc.sh $tag x > x-setup.txt 2>&1 || { echo setup failed; tail x-setup.txt; exit 1; }
  bash runc.sh x http://localhost:3000 $SW/src/apps/meteor x-code ;;
mm) ${DK:-docker} run -d --name mm -p 127.0.0.1:8065:8065 docker.io/mattermost/mattermost-preview:12.0.2 >/dev/null
  until curl -sf localhost:8065/api/v4/system/ping >/dev/null; do sleep 3; done; sleep 5
  python3 -I mmsetup.py > x-setup.txt 2>&1 && python3 -I mkhar-mm.py x.har >> x-setup.txt 2>&1 || { echo setup failed; tail x-setup.txt; exit 1; }
  SB=bob-mm.session SC=carol-mm.session bash runc.sh x http://localhost:8065 $SW/src/server x-code ;;
gt) bash fresh-gt.sh x > x-setup.txt 2>&1 || { echo setup failed; tail x-setup.txt; exit 1; }
  SB=bob-gt.session SC=carol-gt.session bash runc.sh x http://127.0.0.1:3001 $SW/src x-code ;;
esac
