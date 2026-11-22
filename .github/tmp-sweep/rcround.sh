# $1 version tag, $2 out prefix. Fresh RC, recording, then each of the 12 spec files.
cd $SW
bash fresh-rc.sh $1 $2 > $2-setup.txt 2>&1 || { echo setup failed; tail $2-setup.txt; exit 1; }
bash runall.sh $2 http://localhost:3000 $2 $SW/spec/Rocket.Chat-Open-API/*.yaml
