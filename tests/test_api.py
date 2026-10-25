import json, urllib.request, urllib.error, itertools, base64, hmac, hashlib, time, subprocess, sys
import bcrypt

BASE = "http://localhost:8000"
ORIGIN = "http://localhost:8080"
ipn = itertools.count(1)
results = []

def call(method, path, body=None, token=None, headers=None, raw=None, ip=True):
    h = {}
    if body is not None or raw is not None: h["Content-Type"] = "application/json"
    if token: h["Authorization"] = f"Bearer {token}"
    if ip: h["X-Forwarded-For"] = f"10.0.{next(ipn)//250}.{next(ipn)%250}"
    if headers: h.update(headers)
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        r = urllib.request.urlopen(req)
        code, hd, txt = r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        code, hd, txt = e.code, dict(e.headers), e.read().decode()
    try: js = json.loads(txt) if txt else None
    except Exception: js = txt
    return code, hd, js

def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"   <-- {extra}"))

def psql(sql):
    return subprocess.run(["psql","-h","localhost","-U","app","-d","fs","-tA","-c",sql],env={"PGPASSWORD":"app","PATH":"/usr/bin"},capture_output=True,text=True).stdout.strip()

KEY = "invite123"
# ---------- registration ----------
c,_,j = call("POST","/auth/register",{"username":"owner_a","password":"correct-horse-battery","name":"Owner A","clinic_name":"Clinic A"})
check("register w/o invite key -> 403", c==403, (c,j))
c,_,j = call("POST","/auth/register",{"username":"Owner_A","password":"correct-horse-battery","name":"Owner A","clinic_name":"Clinic A","registration_key":KEY})
check("register clinic A -> 201 + token", c==201 and j.get("token"), (c,j)); A = j["token"]; A_user = j["user"]
check("username stored lowercase", psql("select username from app_users where id=%d"%A_user["id"])=="owner_a")
c,_,j = call("POST","/auth/register",{"username":"owner_b","password":"another-long-pass-1","name":"Owner B","clinic_name":"Clinic B","registration_key":KEY})
check("register clinic B -> 201", c==201, (c,j)); B = j["token"]; B_user = j["user"]
check("A and B are different clinics", A_user["clinic_id"]!=B_user["clinic_id"])
c,_,j = call("POST","/auth/register",{"username":"OWNER_A","password":"correct-horse-battery","name":"x","clinic_name":"Dup","registration_key":KEY})
check("duplicate username (case-insens.) -> 409", c==409, (c,j))
check("failed register left no orphan clinic", psql("select count(*) from clinics where name='Dup'")=="0")
c,_,j = call("POST","/auth/register",{"username":"weakling","password":"short","name":"x","clinic_name":"W","registration_key":KEY})
check("weak password -> 400 with field details", c==400 and any(d["field"]=="password" for d in j["details"]), (c,j))
c,_,j = call("POST","/auth/register",{"username":"sneaky","password":"correct-horse-battery","name":"x","clinic_name":"S","registration_key":KEY,"clinic_id":1,"role":"admin"})
check("register with extra fields (clinic_id/role) -> 400", c==400, (c,j))

# ---------- appointments + tenant isolation ----------
def appt(tok, name, reason, when, **kw):
    return call("POST","/appointments",{"name":name,"reason":reason,"booking_time":when,**kw},tok)
now = time.time()
def iso(offset_days): return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now+offset_days*86400))
c,_,a1 = appt(A,"Alice Smith","Cleaning",iso(-1),phone="+92 300 1234567",email="alice@x.com",insurance="Delta 4471-1234",dob="1990-05-17")
check("A creates appointment -> 201", c==201 and a1["data"]["status"]=="scheduled", (c,a1)); a1=a1["data"]
c,_,a2 = appt(A,"Bob Jones","cleaning ",iso(-2)); a2=a2["data"]
c,_,a3 = appt(A,"Cara Lee","Root Canal",iso(-3)); a3=a3["data"]
c,_,a4 = appt(A,"Dan Cancelled","Cleaning",iso(-1),cancel_time=iso(-1)); a4=a4["data"]
c,_,b1 = appt(B,"Zed Other","Cleaning",iso(-1)); b1=b1["data"]
check("calendar_event_id generated server-side", psql(f"select calendar_event_id like 'crm-%' from appointments where id={a1['id']}")=="t")
check("clinic_id taken from token (A)", psql(f"select clinic_id from appointments where id={a1['id']}")==str(A_user["clinic_id"]))

c,_,j = call("POST","/appointments",{"name":"Evil","booking_time":iso(1),"clinic_id":B_user["clinic_id"]},A)
check("POST with clinic_id in body -> 400 (mass-assignment blocked)", c==400, (c,j))
c,_,j = call("POST","/appointments",{"name":"Evil","booking_time":"not-a-date"},A)
check("bad booking_time -> 400", c==400, (c,j))
c,_,j = call("POST","/appointments",{"name":"x"*151,"booking_time":iso(1)},A)
check("name too long -> 400", c==400)
c,_,j = call("POST","/appointments",{"name":"Bad\u0000Name","booking_time":iso(1)},A)
check("control chars / NUL byte -> 400 (not 500)", c==400, (c,j))
c,_,j = call("POST","/appointments",{"name":"X","booking_time":iso(1),"phone":"abc'; DROP TABLE appointments;--"},A)
check("bad phone -> 400", c==400)

c,_,la = call("GET","/appointments",token=A)
names_a = {r["name"] for r in la["data"]}
check("A sees only A's appointments", names_a=={"Alice Smith","Bob Jones","Cara Lee","Dan Cancelled"}, names_a)
c,_,lb = call("GET","/appointments",token=B)
check("B sees only B's appointments", {r["name"] for r in lb["data"]}=={"Zed Other"}, lb)

c,_,j = call("PATCH",f"/appointments/{a1['id']}",{"reason":"HACKED"},B)
check("B PATCH A's appointment -> 404", c==404, (c,j))
c,_,j = call("DELETE",f"/appointments/{a1['id']}",token=B)
check("B DELETE A's appointment -> 404", c==404, (c,j))
check("A's appointment untouched after B's attempts", psql(f"select reason from appointments where id={a1['id']}")=="Cleaning")
c,_,j = call("PATCH",f"/appointments/{a1['id']}",{"reason":"Whitening"},A)
check("A PATCH own appointment -> 200", c==200 and j["data"]["reason"]=="Whitening", (c,j))
c,_,j = call("PATCH",f"/appointments/{a1['id']}",{"clinic_id":B_user["clinic_id"]},A)
check("A PATCH moving appointment to clinic B -> 400", c==400)
c,_,j = call("PATCH",f"/appointments/{a1['id']}",{"calendar_event_id":"x"},A)
check("PATCH calendar_event_id -> 400", c==400)
c,_,j = call("PATCH",f"/appointments/{a1['id']}",{},A)
check("PATCH empty body -> 400", c==400)
c,_,j = call("PATCH",f"/appointments/{a1['id']}",{"reason":"Cleaning"},A)  # restore

# ---------- SQL injection ----------
for payload in ["' OR '1'='1", "'; DROP TABLE appointments; --", "%", "_", "\\"]:
    c,_,j = call("GET","/appointments?search="+urllib.request.quote(payload),token=A)
    ok = c==200 and len(j["data"])==0
    check(f"search={payload!r} matches nothing (no injection / wildcards escaped)", ok, (c, j if c!=200 else len(j['data'])))
check("appointments table still exists", psql("select count(*) from appointments")!="")
for bad in ["1 OR 1=1","1;DROP TABLE appointments","-1","0x10","99999999999","abc"]:
    c,_,j = call("DELETE","/appointments/"+urllib.request.quote(bad),token=A)
    check(f"DELETE /appointments/{bad} -> 400", c==400, (c,j))
c,_,j = call("GET","/appointments?limit=1%3Bselect%201",token=A); check("non-numeric limit -> 400", c==400)
c,_,j = call("GET","/appointments?clinic_id=%d"%B_user["clinic_id"],token=A); check("unknown query param clinic_id -> 400", c==400)
c,_,j = call("GET","/patients?sort=asc;DROP",token=A); check("bad sort value -> 400", c==400)
c,_,j = call("GET","/appointments?search=alice",token=A); check("search is case-insens. substring", c==200 and len(j["data"])==1, (c,j))
c,_,j = call("GET","/appointments?limit=2&offset=1",token=A); check("pagination limit/offset", c==200 and len(j["data"])==2)

# ---------- analytics ----------
c,_,an = call("GET","/analytics?days=7",token=A)
check("analytics A -> 200 with 7 zero-filled days", c==200 and len(an["bookings"])==7, (c,an))
reasons = {r["reason"]:r["count"] for r in an["reasons"]}
check("reasons normalized + cancelled excluded (Cleaning=2, Root Canal=1)", reasons=={"Cleaning":2,"Root Canal":1}, reasons)
check("bookings total excludes cancelled & other clinic (=3)", sum(d["count"] for d in an["bookings"])==3, an["bookings"])
c,_,anb = call("GET","/analytics?days=7",token=B)
check("analytics B sees only B (1)", sum(d["count"] for d in anb["bookings"])==1)
c,_,j = call("GET","/analytics?days=9999",token=A); check("analytics days out of range -> 400", c==400)

# ---------- patients ----------
c,_,p = call("GET","/patients?sort=desc",token=A)
check("patients grouped per clinic, sorted desc", c==200 and [x["name"] for x in p["data"]]==sorted([x["name"] for x in p["data"]],key=str.lower,reverse=True) and "Zed Other" not in str(p), (c,p))
alice = [x for x in p["data"] if x["name"]=="Alice Smith"][0]
check("patient aggregate has latest email/dob/insurance", alice["email"]=="alice@x.com" and alice["dob"] is not None and alice["total_appointments"]==1, alice)
c,_,j = call("PATCH","/patients",{"name":"Alice Smith","phone":"+92 300 1234567","insurance":"Delta 9999-0000"},B)
check("B PATCH A's patient -> 404", c==404, (c,j))
c,_,j = call("PATCH","/patients",{"name":"Alice Smith","phone":"+92 300 1234567","insurance":"Delta 9999-0000"},A)
check("A PATCH own patient -> updated 1", c==200 and j["updated"]==1, (c,j))
c,_,j = call("DELETE","/patients?name=Cara%20Lee",token=B)
check("B DELETE A's patient -> 404", c==404, (c,j))
check("A's patient still there", psql("select count(*) from appointments where name='Cara Lee'")=="1")

# ---------- roles / hr / deactivation ----------
c,_,j = call("POST","/auth/users",{"username":"hr_user","password":"hr-password-123","name":"HR","role":"hr"},A)
check("admin creates hr user in own clinic", c==201 and j["user"]["clinic_id"]==A_user["clinic_id"], (c,j)); hr_id=j["user"]["id"]
c,_,j = call("POST","/auth/users",{"username":"x_user","password":"hr-password-123","name":"X","role":"admin","clinic_id":B_user["clinic_id"]},A)
check("create-user with clinic_id in body -> 400", c==400)
c,_,j = call("POST","/auth/login",{"username":"hr_user","password":"hr-password-123"})
check("hr login ok", c==200, (c,j)); HR=j["token"]
c,_,j = call("GET","/appointments",token=HR)
alice_hr=[r for r in j["data"] if r["name"]=="Alice Smith"][0]
check("hr can read appointments but phone/email/dob/insurance are null", c==200 and all(alice_hr[k] is None for k in ("phone","email","dob","insurance")), alice_hr)
c,_,j = call("POST","/appointments",{"name":"H","booking_time":iso(1)},HR); check("hr POST appointment -> 403", c==403)
c,_,j = call("DELETE",f"/appointments/{a3['id']}",token=HR); check("hr DELETE appointment -> 403", c==403)
c,_,j = call("GET","/patients",token=HR); check("hr GET patients -> 403", c==403)
c,_,j = call("GET","/analytics",token=HR); check("hr GET analytics -> 200", c==200)
c,_,j = call("POST","/auth/users",{"username":"y_user","password":"hr-password-123","name":"Y","role":"staff"},HR); check("hr cannot create users -> 403", c==403)
c,_,j = call("PATCH",f"/auth/users/{A_user['id']}",{"is_active":False},A); check("admin can't deactivate self -> 400", c==400)
c,_,j = call("PATCH",f"/auth/users/{hr_id}",{"is_active":False},B); check("other clinic's admin can't deactivate A's hr -> 404", c==404, (c,j))
c,_,j = call("PATCH",f"/auth/users/{hr_id}",{"is_active":False},A); check("admin deactivates hr -> 200", c==200 and j["user"]["is_active"] is False, (c,j))
c,_,j = call("GET","/analytics",token=HR); check("deactivated user's EXISTING token rejected immediately -> 401", c==401, (c,j))
c,_,j = call("POST","/auth/login",{"username":"hr_user","password":"hr-password-123"}); check("deactivated user can't log in -> 401", c==401)

# ---------- JWT attacks ----------
def b64(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def forge(payload, secret=b"wrong-secret-wrong-secret-wrong-secret", alg="HS256"):
    hdr = b64(json.dumps({"alg":alg,"typ":"JWT"}).encode()); pl = b64(json.dumps(payload).encode())
    sig = b64(hmac.new(secret, f"{hdr}.{pl}".encode(), hashlib.sha256).digest()) if alg!="none" else ""
    return f"{hdr}.{pl}.{sig}"
claims = {"id":A_user["id"],"clinic_id":A_user["clinic_id"],"role":"admin","iss":"fresh-start-api","aud":"fresh-start-app","exp":int(now)+3600}
c,_,_ = call("GET","/appointments",token=forge(claims)); check("JWT signed with wrong secret -> 401", c==401)
c,_,_ = call("GET","/appointments",token=forge(claims,alg="none")); check("JWT alg=none -> 401", c==401)
good = forge(claims, secret=b"test-secret-test-secret-test-secret-123456")
c,_,_ = call("GET","/appointments",token=good); check("sanity: correctly signed forged-by-test token accepted", c==200, c)
c,_,_ = call("GET","/appointments",token=forge({**claims,"exp":int(now)-10},secret=b"test-secret-test-secret-test-secret-123456")); check("expired JWT -> 401", c==401)
c,_,_ = call("GET","/appointments",token=forge({**claims,"aud":"other"},secret=b"test-secret-test-secret-test-secret-123456")); check("wrong audience -> 401", c==401)
c,_,_ = call("GET","/appointments",token=forge({**claims,"iss":"other"},secret=b"test-secret-test-secret-test-secret-123456")); check("wrong issuer -> 401", c==401)
c,_,j = call("GET","/appointments",token=forge({**claims,"clinic_id":B_user["clinic_id"]},secret=b"test-secret-test-secret-test-secret-123456")); check("valid signature but clinic_id claim != DB clinic -> 401", c==401, (c,j))
c,_,_ = call("GET","/appointments"); check("no token -> 401", c==401)
c,_,_ = call("GET","/appointments",headers={"Authorization":"Basic abc"}); check("non-bearer auth -> 401", c==401)
c,_,_ = call("GET","/appointments",token="a.b.c"); check("garbage token -> 401", c==401)

# ---------- legacy users ----------
leg = bcrypt.hashpw(b"legacy-pass-123", bcrypt.gensalt(10, prefix=b"2b")).decode()
cid = A_user["clinic_id"]
psql(f"insert into app_users(username,password_hash,name,role,clinic_id) values ('Admin.Legacy','{leg}','Legacy','staff',{cid})")
c,_,j = call("POST","/auth/login",{"username":"ADMIN.legacy","password":"legacy-pass-123"})
check("legacy user (mixed-case username, python-bcrypt $2b$ hash) can log in", c==200 and j["user"]["role"]=="staff", (c,j))
psql("insert into app_users(username,password_hash,name,role,clinic_id) values ('orphan_user','%s','Orphan','admin',NULL)"%leg)
c,_,j = call("POST","/auth/login",{"username":"orphan_user","password":"legacy-pass-123"})
check("user with NULL clinic_id cannot log in -> 401", c==401, (c,j))
c,_,j = call("POST","/auth/login",{"username":"nobody_here","password":"x"}); check("unknown user -> 401 same message", c==401 and j["error"]=="Invalid username or password")
c,_,j2 = call("POST","/auth/login",{"username":"owner_a","password":"WRONG-password"}); check("wrong password -> 401 same message", c==401 and j2["error"]==j["error"])
c,_,j = call("POST","/auth/login",{"username":"owner_a","password":"correct-horse-battery"}); check("owner login ok, no password_hash in response", c==200 and "password_hash" not in json.dumps(j), j)

# ---------- rate limiting ----------
codes=[]
for i in range(10):
    c,h,j = call("POST","/auth/login",{"username":"ratelimit_victim","password":"nope-nope"},ip=True)
    codes.append((c,h.get("Retry-After")))
check("per-username login limit: 8x401 then 429 with Retry-After", [x[0] for x in codes]==[401]*8+[429]*2 and codes[-1][1] is not None, codes)
codes=[]
for i in range(35):
    c,h,j = call("POST","/auth/login",{"username":f"spray{i}","password":"nope-nope"},headers={"X-Forwarded-For":"203.0.113.9"},ip=False)
    codes.append(c)
check("per-IP login limit: password-spraying many usernames from one IP -> 429 after 30", codes[:30]==[401]*30 and codes[30:]==[429]*5, codes)
codes=[]
for i in range(7):
    c,_,_ = call("POST","/auth/register",{"username":f"bot{i}","password":"correct-horse-battery","name":"b","clinic_name":"bot","registration_key":"wrong"},headers={"X-Forwarded-For":"198.51.100.7"},ip=False)
    codes.append(c)
check("register limit: 5 per IP/hour then 429", codes==[403]*5+[429]*2, codes)
psql("delete from rate_limits where key like 'api:u%'")
codes=[]
for i in range(125):
    c,_,_ = call("GET","/appointments?limit=1",token=A); codes.append(c)
check("API per-user limit: 120 ok then 429", codes[:120]==[200]*120 and 429 in codes[120:], (codes.count(200), codes.count(429)))

# ---------- CORS ----------
c,h,j = call("GET","/appointments",token=A,headers={"Origin":"https://evil.example"})
check("disallowed Origin -> 403 and no ACAO header", c==403 and "Access-Control-Allow-Origin" not in h, (c,h))
psql("delete from rate_limits where key like 'api:u%'")
c,h,j = call("GET","/appointments?limit=1",token=A,headers={"Origin":ORIGIN})
check("allowed Origin -> ACAO echoed + Vary: Origin", c==200 and h.get("Access-Control-Allow-Origin")==ORIGIN and "Origin" in h.get("Vary",""), h)
c,h,_ = call("OPTIONS","/appointments",headers={"Origin":ORIGIN,"Access-Control-Request-Method":"POST"})
check("preflight allowed -> 204 with allow-headers/methods", c==204 and "authorization" in h.get("Access-Control-Allow-Headers","").lower() and "PATCH" in h.get("Access-Control-Allow-Methods",""), (c,h))
c,h,_ = call("OPTIONS","/appointments",headers={"Origin":"https://evil.example"})
check("preflight from evil origin -> 403", c==403)
check("Cache-Control: no-store on API responses", h.get("Cache-Control")=="no-store")
c,h,j = call("GET","/nope"); check("unknown path -> 404 JSON", c==404 and j["error"]=="Not found")
c,h,j = call("GET","/constructor"); check("prototype-key path (/constructor) -> 404, not a crash", c==404, (c,j))

# ---------- body handling ----------
c,_,j = call("POST","/appointments",raw=b"{not json",token=A); check("invalid JSON -> 400", c==400)
c,_,j = call("POST","/appointments",raw=b"[]",token=A); check("JSON array body -> 400", c==400)
c,_,j = call("POST","/appointments",raw=json.dumps({"name":"A"*20000,"booking_time":iso(1)}).encode(),token=A); check("oversized body -> 413", c==413, (c,j))
req = urllib.request.Request(BASE+"/appointments",data=b'{"name":"x"}',method="POST",headers={"Authorization":f"Bearer {A}","Content-Type":"text/plain","X-Forwarded-For":"10.9.9.9"})
try: urllib.request.urlopen(req); code=200
except urllib.error.HTTPError as e: code=e.code
check("wrong Content-Type -> 415", code==415, code)
c,_,j = call("DELETE",f"/appointments/{a3['id']}",token=A); check("A deletes own appointment -> 200", c==200)
c,_,j = call("DELETE",f"/appointments/{a3['id']}",token=A); check("delete again -> 404", c==404)

# ---------- no secret/stack leakage ----------
log = open("/tmp/server.log").read()
check("server log never contains JWTs or passwords", "correct-horse" not in log and A not in log and "legacy-pass" not in log)

print()
fails = [n for n,ok in results if not ok]
print(f"{len(results)-len(fails)}/{len(results)} passed")
if fails: print("FAILED:", *fails, sep="\n  - "); sys.exit(1)
