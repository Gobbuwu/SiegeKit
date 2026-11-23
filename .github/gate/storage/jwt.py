import hmac,hashlib,base64,json,sys,time
def b(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
sec=sys.argv[1].encode(); role=sys.argv[2]
h=b(json.dumps({"alg":"HS256","typ":"JWT"}).encode()); p=b(json.dumps({"role":role,"iss":"supabase-demo","iat":int(time.time()),"exp":int(time.time())+86400*30}).encode())
print(h+"."+p+"."+b(hmac.new(sec,(h+"."+p).encode(),hashlib.sha256).digest()))
