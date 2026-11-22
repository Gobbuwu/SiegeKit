# alice, bob, carol; private group secret-ab (alice+bob) and DM alice-bob.
# Each room: alice's message, bob's message, and a message alice posts and
# then deletes (a real deleted message for chat.getDeletedMessages).
# Writes rooms.txt and B (bob) / C (carol) session files.
import json,sys,os,urllib.request
B='http://localhost:3000/api/v1/'
def call(path,sess=None,body=None):
    h={'Content-Type':'application/json'}
    if sess: h.update(sess)
    data=json.dumps(body).encode() if body is not None else None
    r=urllib.request.Request(B+path,data=data,headers=h,method='POST' if data else 'GET')
    try: return json.loads(urllib.request.urlopen(r).read())
    except urllib.error.HTTPError as e: return json.loads(e.read())
def login(u,p):
    d=call('login',body={'user':u,'password':p})['data']; return {'X-Auth-Token':d['authToken'],'X-User-Id':d['userId']}
adm=login('admin','Adm1n-pass-123')
for u in ['alice','bob','carol']:
    print(u,call('users.create',adm,{'name':u,'email':u+'@example.com','password':'Pass-%s-12345'%u,'username':u,'verified':True,'joinDefaultChannels':True}).get('success'))
S={u:login(u,'Pass-%s-12345'%u) for u in ['alice','bob','carol']}
G=call('groups.create',S['alice'],{'name':'secret-ab','members':['bob']})['group']['_id']
D=call('im.create',S['alice'],{'username':'bob'})['room']['_id']
for name,rid in [('group',G),('dm',D)]:
    print(name,'alice',call('chat.postMessage',S['alice'],{'roomId':rid,'text':'private from alice '+name}).get('success'))
    print(name,'bob',call('chat.postMessage',S['bob'],{'roomId':rid,'text':'bob says hi '+name}).get('success'))
    m=call('chat.postMessage',S['alice'],{'roomId':rid,'text':'alice deletes this '+name})
    print(name,'post-to-delete',m.get('success'),m.get('error'))
    if m.get('success'):
        mid=m['message']['_id']
    else:
        # 8.9.1 offline refuses to send (restricted-workspace): put the message in by DB, delete through the API.
        import subprocess,random,string
        mid=''.join(random.choice(string.ascii_letters+string.digits) for _ in range(17))
        js="db.rocketchat_message.insertOne({_id:'%s',rid:'%s',msg:'alice deletes this %s',ts:new Date(),_updatedAt:new Date(),u:{_id:'%s',username:'alice',name:'alice'}})"%(mid,rid,name,S['alice']['X-User-Id'])
        print(name,'db-insert',subprocess.run([os.environ.get('DK','docker'),'exec','rc-mongo','mongosh','--quiet','rocketchat','--eval',js],capture_output=True,text=True).stdout.strip()[:60])
    print(name,'delete',call('chat.delete',S['alice'],{'roomId':rid,'msgId':mid}).get('success'))
open('rooms.txt','w').write(G+' '+D+'\n')
for u,f in [('bob','bob.session'),('carol','carol.session')]:
    open(f,'w').write('X-Auth-Token: %s\nX-User-Id: %s\n'%(S[u]['X-Auth-Token'],S[u]['X-User-Id']))
print('rooms',G,D)
