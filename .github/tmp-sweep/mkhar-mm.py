# Builds a HAR of alice's Mattermost API requests as the web client sends
# them (Bearer token, X-Requested-With), with the real answers, by sending
# each one as alice. Writes bob/carol session files.
import json,sys,urllib.request
B='http://localhost:8065'
ids=json.load(open('mmids.json')); T=ids['tokens']; G=ids['group']['cid']; D=ids['dm']['cid']; team=ids['team']; U=ids['users']
H=[{'name':'Authorization','value':'Bearer '+T['alice']},{'name':'X-Requested-With','value':'XMLHttpRequest'},{'name':'Accept','value':'application/json'}]
entries=[]
def send(method,path,body=None):
    data=json.dumps(body).encode() if body is not None else None
    h={x['name']:x['value'] for x in H}
    if data: h['Content-Type']='application/json'
    r=urllib.request.Request(B+path,data=data,headers=h,method=method)
    try: x=urllib.request.urlopen(r); st=x.status; txt=x.read().decode()
    except urllib.error.HTTPError as e: st=e.code; txt=e.read().decode()
    req={'method':method,'url':B+path,'headers':H+([{'name':'Content-Type','value':'application/json'}] if data else [])}
    if data: req['postData']={'mimeType':'application/json','text':data.decode()}
    entries.append({'request':req,'response':{'status':st,'content':{'mimeType':'application/json','text':txt}}})
    print(method,path,st,file=sys.stderr)
    return json.loads(txt) if txt.startswith(('{','[')) else None
send('GET','/api/v4/users/me')
send('GET',f'/api/v4/users/me/teams/{team}/channels')
for cid in (G,D):
    send('GET',f'/api/v4/channels/{cid}')
    send('GET',f'/api/v4/channels/{cid}/posts?page=0&per_page=30')
    send('GET',f'/api/v4/channels/{cid}/members?page=0&per_page=100')
    send('GET',f'/api/v4/channels/{cid}/pinned')
    p=send('POST','/api/v4/posts',{'channel_id':cid,'message':'new private note from alice'})
    send('PUT',f'/api/v4/posts/{p["id"]}/patch',{'message':'new private note from alice (edited)'})
    send('GET',f'/api/v4/posts/{p["id"]}')
send('PUT',f'/api/v4/channels/{G}/patch',{'header':'alice set this header'})
# alice archives the shared channel last. Not sent here (the channel stays
# for the replay, as on a restored snapshot); the entry holds the answer
# Mattermost gives (measured by hand 2026-11-22: 200 {"status":"OK"}).
if len(sys.argv) > 2 and sys.argv[2] == 'delete':
    entries.append({'request':{'method':'DELETE','url':B+f'/api/v4/channels/{G}','headers':H},'response':{'status':200,'content':{'mimeType':'application/json','text':'{"status":"OK"}'}}})
json.dump({'log':{'entries':entries}},open(sys.argv[1],'w'))
for u in ('bob','carol'):
    open(f'{u}-mm.session','w').write(f'Authorization: Bearer {T[u]}\nX-Requested-With: XMLHttpRequest\n')
