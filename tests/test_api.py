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

# ---------- merged additions: health, security headers, user management ----------
import http.client, os
def hdr(h, name): return {k.lower(): v for k, v in h.items()}.get(name.lower())

c,h,j = call("GET","/health")
check("health -> {ok:true}", c==200 and j=={"ok":True}, (c,j))
check("security headers: X-Frame-Options, nosniff, CSP, Referrer-Policy, HSTS",
      hdr(h,"X-Frame-Options")=="DENY" and hdr(h,"X-Content-Type-Options")=="nosniff"
      and "default-src 'none'" in (hdr(h,"Content-Security-Policy") or "")
      and hdr(h,"Referrer-Policy")=="no-referrer" and "max-age" in (hdr(h,"Strict-Transport-Security") or ""), h)
c,h,_ = call("GET","/appointments",token=A,headers={"Origin":"https://evil.example"})
check("Vary: Origin is sent even when the origin is refused", c==403 and "origin" in (hdr(h,"Vary") or "").lower(), h)

c,_,j = call("GET","/auth/me",token=A)
check("/auth/me returns the signed-in user", c==200 and j["user"]["id"]==A_user["id"] and j["user"]["role"]=="admin" and "password_hash" not in j["user"], (c,j))
c,_,_ = call("GET","/auth/me"); check("/auth/me without token -> 401", c==401)

c,_,j = call("POST","/auth/users",{"username":"Staff_One","password":"staff-password-123","name":"Staff One","role":"staff"},A)
check("create user returns is_active + created_at", c==201 and j["user"]["is_active"] is True and j["user"]["created_at"] and j["user"]["username"]=="staff_one", (c,j)); staff_id=j["user"]["id"]
c,_,j = call("POST","/auth/login",{"username":"staff_one","password":"staff-password-123"}); STAFF=j["token"]

c,_,j = call("GET","/auth/users",token=A)
names = {u["username"] for u in j["data"]}
check("admin lists ONLY their own clinic's users", c==200 and {"owner_a","staff_one","hr_user"} <= names and "owner_b" not in names and all(u["clinic_id"]==A_user["clinic_id"] for u in j["data"]), (c,names))
check("user list never exposes password hashes", "password" not in json.dumps(j).lower() and "$2" not in json.dumps(j))
c,_,j = call("GET","/auth/users",token=B)
check("clinic B's admin sees only clinic B's users", c==200 and {u["username"] for u in j["data"]}=={"owner_b"}, j)
c,_,_ = call("GET","/auth/users",token=STAFF); check("staff cannot list users -> 403", c==403)
c,_,_ = call("GET","/auth/users"); check("list users without token -> 401", c==401)

c,_,_ = call("GET","/patients",token=STAFF); check("staff can read patients", c==200, c)
c,_,j = call("PATCH",f"/auth/users/{staff_id}",{"role":"hr","name":"Staff Renamed"},A)
check("admin changes a user's role and name", c==200 and j["user"]["role"]=="hr" and j["user"]["name"]=="Staff Renamed" and j["user"]["is_active"] is True, (c,j))
c,_,_ = call("GET","/patients",token=STAFF); check("role change applies to the EXISTING token at once (staff -> hr: patients 403)", c==403, c)
c,_,_ = call("PATCH",f"/auth/users/{staff_id}",{"role":"staff"},A); check("admin restores role -> 200", c==200)
c,_,_ = call("GET","/patients",token=STAFF); check("...and it is effective again immediately", c==200, c)
c,_,_ = call("PATCH",f"/auth/users/{A_user['id']}",{"role":"staff"},A); check("admin can't change their own role -> 400", c==400)
check("own role unchanged in the database", psql(f"select role from app_users where id={A_user['id']}")=="admin")
c,_,j = call("PATCH",f"/auth/users/{A_user['id']}",{"name":"Owner A"},A); check("admin may rename themselves -> 200", c==200, (c,j))
c,_,_ = call("PATCH",f"/auth/users/{staff_id}",{"role":"superuser"},A); check("unknown role -> 400", c==400)
c,_,_ = call("PATCH",f"/auth/users/{staff_id}",{"password_hash":"x"},A); check("PATCH user with password_hash/unknown key -> 400", c==400)
c,_,_ = call("PATCH",f"/auth/users/{staff_id}",{"clinic_id":B_user["clinic_id"]},A); check("PATCH user moving clinic -> 400", c==400)
c,_,_ = call("PATCH",f"/auth/users/{staff_id}",{},A); check("PATCH user empty body -> 400", c==400)
c,_,_ = call("PATCH",f"/auth/users/{B_user['id']}",{"role":"staff"},A); check("A can't change clinic B's user -> 404", c==404)
check("clinic B's admin untouched", psql(f"select role from app_users where id={B_user['id']}")=="admin")
c,_,_ = call("PATCH",f"/auth/users/{staff_id}",{"role":"hr"},STAFF); check("staff can't change roles -> 403", c==403)
c,_,_ = call("PATCH","/auth/users/1%20OR%201=1",{"role":"hr"},A); check("PATCH /auth/users/<sql> -> 400", c==400)

# successful sign-ins must not count towards the lockout (8 failures / 15 min)
c,_,_ = call("POST","/auth/users",{"username":"clear_me","password":"clear-me-password-1","name":"C","role":"staff"},A)
bad = [call("POST","/auth/login",{"username":"clear_me","password":"nope-nope-nope"})[0] for _ in range(5)]
good = call("POST","/auth/login",{"username":"clear_me","password":"clear-me-password-1"})[0]
bad2 = [call("POST","/auth/login",{"username":"clear_me","password":"nope-nope-nope"})[0] for _ in range(5)]
check("a successful login resets the failure counter (5 bad, 1 good, 5 bad -> no 429)", bad==[401]*5 and good==200 and bad2==[401]*5, (bad,good,bad2))

# ---------- client IP: only the address Heroku appended counts ----------
codes=[]
for i in range(32):
    c,_,_ = call("POST","/auth/login",{"username":f"spoof{i}","password":"x"},
                 headers={"X-Forwarded-For":f"10.1.1.{i}, 192.0.2.55","CF-Connecting-IP":f"1.2.3.{i}"},ip=False)
    codes.append(c)
check("spoofed leftmost X-Forwarded-For / CF-Connecting-IP can't dodge the per-IP limit", codes[:30]==[401]*30 and codes[30:]==[429]*2, codes)
c,_,_ = call("POST","/auth/login",{"username":"spoof-other","password":"x"},headers={"X-Forwarded-For":"10.1.1.1, 192.0.2.56"},ip=False)
check("a different real client address is counted separately", c==401, c)

# ---------- settings ----------
DEF = {"appointment_value":180,"hourly_cost":22,"minutes_per_booking":6,"timezone":"Asia/Karachi"}
c,_,j = call("GET","/settings",token=A); check("settings default until a clinic saves its own", c==200 and j["data"]==DEF, (c,j))
c,_,j = call("PUT","/settings",{"hourly_cost":31.5,"timezone":"America/New_York"},A)
check("PUT settings (partial)", c==200 and j["data"]=={**DEF,"hourly_cost":31.5,"timezone":"America/New_York"}, (c,j))
c,_,j = call("PUT","/settings",{"appointment_value":250,"minutes_per_booking":7.5},A)
want = {"appointment_value":250,"hourly_cost":31.5,"minutes_per_booking":7.5,"timezone":"America/New_York"}
check("second partial PUT keeps earlier values", c==200 and j["data"]==want, (c,j))
check("settings numbers are JSON numbers, not strings", all(isinstance(j["data"][k],(int,float)) for k in ("appointment_value","hourly_cost","minutes_per_booking")), j)
c,_,j = call("GET","/settings",token=STAFF); check("non-admin roles can read settings", c==200 and j["data"]==want, (c,j))
c,_,_ = call("PUT","/settings",{"hourly_cost":1},STAFF); check("non-admin PUT settings -> 403", c==403)
c,_,_ = call("PUT","/settings",{"hourly_cost":1}); check("PUT settings without token -> 401", c==401)
c,_,j = call("GET","/settings",token=B); check("clinic B still has defaults (settings are per clinic)", c==200 and j["data"]==DEF, (c,j))
for label,body in [("empty body",{}),("negative number",{"hourly_cost":-1}),("string number",{"hourly_cost":"12"}),("huge minutes",{"minutes_per_booking":5000}),("clinic_id",{"clinic_id":1}),("bad tz chars",{"timezone":"'; DROP TABLE clinics;--"})]:
    c,_,_ = call("PUT","/settings",body,A); check(f"PUT settings {label} -> 400", c==400, (c,body))
c,_,j = call("PUT","/settings",{"timezone":"Mars/Olympus"},A)
check("unknown time zone -> 400 with field details", c==400 and j["details"]==[{"field":"timezone","message":"Unknown time zone"}], (c,j))
check("clinics table still exists", psql("select count(*) from clinics")!="")
c,_,_ = call("DELETE","/settings",token=A); check("DELETE /settings -> 405", c==405)

# the clinic's own time zone decides which calendar day an appointment falls on
call("PUT","/settings",{"timezone":"UTC"},A)
c,_,probe = call("POST","/appointments",{"name":"Tz Probe","booking_time":"2031-03-10T23:30:00+00:00"},A); probe=probe["data"]
n10 = {r["name"] for r in call("GET","/appointments?date=2031-03-10",token=A)[2]["data"]}
n11 = {r["name"] for r in call("GET","/appointments?date=2031-03-11",token=A)[2]["data"]}
check("clinic in UTC: 23:30Z is still the 10th", "Tz Probe" in n10 and "Tz Probe" not in n11, (n10,n11))
call("PUT","/settings",{"timezone":"Asia/Karachi"},A)
n10 = {r["name"] for r in call("GET","/appointments?date=2031-03-10",token=A)[2]["data"]}
n11 = {r["name"] for r in call("GET","/appointments?date=2031-03-11",token=A)[2]["data"]}
check("clinic in Karachi (UTC+5): the same booking is on the 11th", "Tz Probe" in n11 and "Tz Probe" not in n10, (n10,n11))
call("DELETE",f"/appointments/{probe['id']}",token=A)

# ---------- data formats ----------
c,_,j = call("GET","/appointments?search=alice",token=A)
check("dob is a plain YYYY-MM-DD even when the server runs in another time zone", c==200 and j["data"][0]["dob"]=="1990-05-17", j["data"][0]["dob"] if c==200 else (c,j))
for ph in ["(555) 123-4567","555.123.4567","0300-1234567","+1 555 010 0200"]:
    c,_,j = appt(A,"Phone Test","Cleaning",iso(5),phone=ph)
    check(f"phone {ph!r} accepted", c==201, (c,j))
    if c==201: call("DELETE",f"/appointments/{j['data']['id']}",token=A)
c,_,j = appt(A,"Phone Test","Cleaning",iso(5),phone="+"+"1"*30)
check("31-character phone -> 400 (not a 500 from varchar(30))", c==400, (c,j))
c,_,j = appt(A,"Phone Test","Cleaning",iso(5),phone="12345")
check("phone with fewer than 6 digits -> 400 with ONE message", c==400 and len([d for d in j["details"] if d["field"]=="phone"])==1, (c,j))

# ---------- body size without a Content-Length (chunked) ----------
conn = http.client.HTTPConnection("localhost", 8000)
conn.request("POST", "/appointments", body=iter([b'{"name":"' + b"A"*6000, b"B"*6000 + b'"}']), encode_chunked=True,
             headers={"Content-Type":"application/json","Authorization":f"Bearer {A}","X-Forwarded-For":"10.8.8.8"})
r = conn.getresponse(); r.read(); conn.close()
check("chunked body over 10 KB with no Content-Length -> 413", r.status==413, r.status)

# ---------- registration is OFF unless REGISTRATION_KEY is set; migrations are safe to re-run ----------
srv_env = {**os.environ, "PORT":"8001"}; srv_env.pop("REGISTRATION_KEY", None)
second = subprocess.Popen(["deno","run","--allow-net","--allow-env","--allow-read","main.ts"], env=srv_env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    up = False
    for _ in range(40):
        try: urllib.request.urlopen("http://localhost:8001/health"); up = True; break
        except Exception: time.sleep(0.5)
    req = urllib.request.Request("http://localhost:8001/auth/register", method="POST",
        data=json.dumps({"username":"open_door","password":"correct-horse-battery","name":"x","clinic_name":"Open","registration_key":"invite123"}).encode(),
        headers={"Content-Type":"application/json","X-Forwarded-For":"10.7.7.7"})
    try: urllib.request.urlopen(req); code, body = 200, ""
    except urllib.error.HTTPError as e: code, body = e.code, e.read().decode()
finally:
    second.terminate(); second.wait()
check("no REGISTRATION_KEY configured -> /auth/register is disabled (403)", up and code==403 and "disabled" in body, (up, code, body))
check("...and no clinic was created", psql("select count(*) from clinics where name='Open'")=="0")

mig = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migration.sql")
def psql_file(path): return subprocess.run(["psql","-h","localhost","-U","app","-d","fs","-v","ON_ERROR_STOP=1","-q","-f",path],env={"PGPASSWORD":"app","PATH":"/usr/bin"},capture_output=True,text=True)
before = psql("select count(*) from appointments")
r1, r2 = psql_file(mig), psql_file(mig)
check("migration.sql runs cleanly twice and touches no rows", r1.returncode==0 and r2.returncode==0 and psql("select count(*) from appointments")==before, (r1.stderr, r2.stderr))
rel = subprocess.run(["deno","run","--allow-net","--allow-env","--allow-read","migrate.ts"], env=os.environ, capture_output=True, text=True, cwd=os.path.dirname(mig))
check("release-phase command (migrate.ts) succeeds with the Procfile permissions", rel.returncode==0 and "migration applied" in rel.stdout, (rel.stdout, rel.stderr))

# ---------- no secret/stack leakage ----------
log = open("/tmp/server.log").read()
check("server log never contains JWTs or passwords", "correct-horse" not in log and A not in log and "legacy-pass" not in log)

print()
fails = [n for n,ok in results if not ok]
print(f"{len(results)-len(fails)}/{len(results)} passed")
if fails: print("FAILED:", *fails, sep="\n  - "); sys.exit(1)
