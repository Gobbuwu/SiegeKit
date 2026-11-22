# $1 out prefix. Fresh Gitea 1.24.6, setup, Chromium recording, sweep with the app's own /swagger.v1.json.
cd $SW
bash fresh-gt.sh $1 > $1-setup.txt 2>&1 || { echo setup failed; tail $1-setup.txt; exit 1; }
curl -sf http://127.0.0.1:3001/swagger.v1.json -o gt-swagger.json || { echo no spec; exit 1; }
SB=bob-gt.session SC=carol-gt.session GAP=0 bash runall.sh $1 http://127.0.0.1:3001 $1 $SW/gt-swagger.json
