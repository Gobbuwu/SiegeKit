import json,urllib.request,uuid
B='http://localhost:8065/api/v4/'
def call(path,tok=None,body=None,method=None,raw=None,ctype='application/json',want_hdr=False):
    h={'Content-Type':ctype,'X-Requested-With':'XMLHttpRequest'}
    if tok: h['Authorization']='Bearer '+tok
    data=raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r=urllib.request.Request(B+path,data=data,headers=h,method=method or ('POST' if data else 'GET'))
    try:
        x=urllib.request.urlopen(r); b=x.read(); j=json.loads(b) if b else {}
        return (j,x.headers) if want_hdr else j
    except urllib.error.HTTPError as e:
        b=e.read(); print('ERR',path,e.code,b[:200]); return ({},{}) if want_hdr else {}
def login(u):
    j,h=call('users/login',body={'login_id':u,'password':'Passw0rd!-'+u+'-123'},want_hdr=True); return h.get('Token')
U={'admin':call('users',body={'email':'admin@siegekit.test','username':'admin','password':'Passw0rd!-admin-123'}).get('id')}
adm=login('admin')
for u in ['alice','bob','carol']:
    U[u]=call('users',adm,{'email':u+'@siegekit.test','username':u,'password':'Passw0rd!-'+u+'-123'}).get('id')
T={u:login(u) for u in U}
team=call('teams',adm,{'name':'acme','display_name':'Acme','type':'O'})['id']
for u in ['alice','bob','carol']: call(f'teams/{team}/members',adm,{'team_id':team,'user_id':U[u]})
G=call('channels',T['alice'],{'team_id':team,'name':'secret-ab','display_name':'Secret AB','type':'P'})['id']
call(f'channels/{G}/members',T['alice'],{'user_id':U['bob']})
D=call('channels/direct',T['alice'],[U['alice'],U['bob']])['id']
ids={'users':U,'tokens':T,'team':team}
for name,cid in [('group',G),('dm',D)]:
    bd='----sk'+uuid.uuid4().hex
    raw=(f'--{bd}\r\nContent-Disposition: form-data; name="channel_id"\r\n\r\n{cid}\r\n--{bd}\r\nContent-Disposition: form-data; name="files"; filename="plan-{name}.txt"\r\nContent-Type: text/plain\r\n\r\nsecret plan {name}\r\n--{bd}--\r\n').encode()
    f=call('files',T['alice'],raw=raw,ctype='multipart/form-data; boundary='+bd)['file_infos'][0]['id']
    p=call('posts',T['alice'],{'channel_id':cid,'message':'private from alice: launch plan '+name,'file_ids':[f]})['id']
    call('posts',T['bob'],{'channel_id':cid,'message':'bob says hi '+name})
    t=call('posts',T['bob'],{'channel_id':cid,'message':'thread reply from bob '+name,'root_id':p})['id']
    call('reactions',T['alice'],{'user_id':U['alice'],'post_id':p,'emoji_name':'smile'})
    call(f'posts/{p}/pin',T['alice'],{})
    call(f'users/{U["alice"]}/preferences',T['alice'],[{'user_id':U['alice'],'category':'flagged_post','name':p,'value':'true'}],method='PUT')
    ids[name]={'cid':cid,'post':p,'tmid':t,'file':f}
json.dump(ids,open('mmids.json','w'),indent=1)
print(json.dumps({k:v for k,v in ids.items() if k!='tokens'}))
