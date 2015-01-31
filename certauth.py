#!/usr/bin/python

import os,sys
import pprint

my_dir=os.path.dirname(__file__)
sys.path.append(os.path.join(my_dir, "lib"))

from bottle import Bottle, redirect, request, response, static_file, abort

from bottle_sqlite import Plugin as SQLitePlugin
import json, time, random
import sqlite3
import bottle
import struct

DBNAME=os.environ.get("CERT_DB", os.path.join(my_dir, "certs.db"))
CA_CRT=os.environ.get("CA_CRT", os.path.join(my_dir, "ca.crt"))
CA_KEY=os.environ.get("CA_KEY", os.path.join(my_dir, "ca.key"))

if os.environ.get("DEBUG"): bottle.debug(True)

app=Bottle()
app.install(SQLitePlugin(dbfile=DBNAME))

app.get("/new", name="new")(lambda: static_file("new.html", my_dir))
app.get("/new.js")(lambda: static_file("new.js", my_dir))

def to_json(*args, **kwargs):
    if len(args)==1 and not kwargs:
        ret=args[0]
    else: ret=dict(*args, **kwargs)
    return json.dumps(ret)

@app.get("/")
def index_page(): return redirect(app.get_url("new"))

@app.get("/req")
def get_requests(db):
    response.content_type="application/json"
    req_id=request.get_cookie("req_id")
    if not req_id: return to_json([])
    cur=db.cursor()
    cur.execute("select req_id,cert_serial is not null as have_cert,uname,resource,request_info from requests where req_id=?", (req_id,))
    ret=map(lambda row: dict(map(lambda (i,d): (d[0],json.loads(row[i]) if d[0]=="request_info" else row[i]), enumerate(cur.description))), cur)
    return to_json(ret)

@app.post("/new", name="new")
def new_key(db):
    spkac=request.POST["spkac"]
    uname=request.POST["uname"]
    resource=request.POST["resource"]
    req_id="".join(map(lambda x: "%02x"%random.randint(0,255), range(4)))
    cur=db.cursor()
    req_info=dict(
        headers=dict(request.headers),
        remote_addr=request.environ["REMOTE_ADDR"],
        remote_port=int(request.environ.get("REMOTE_PORT", -1)),
        timestamp=time.time(),
        remote_user=request.environ.get("REMOTE_USER"))
    cur.execute("insert into requests(req_id, spkac, uname, resource, request_info) values(?,?,?,?,?)", (req_id, spkac, uname, resource, to_json(req_info)))
    response.set_cookie("req_id", req_id)
    return redirect(app.get_url("new"))

@app.get("/cert/<req_id>")
def get_cert(db, req_id):
    cur=db.cursor()
    cur.execute("select cert from certs where cert_serial=(select cert_serial from requests where req_id=?)", (req_id,))
    response.content_type="application/x-x509-user-cert"
    return cur.fetchone()[0]

@app.get("/ca.crt")
def get_ca():
    response.content_type="application/x-x509-ca-cert"
    return open(CA_CRT).read()

@app.post("/authorize/<req_id>")
def authorize(req_id):
    abort(500, "Not implemented yet")

@app.get("/auth")
def authenticate(db):
    response.content_type="application/json"
    auth_info=get_current_auth(db)
    if auth_info is None: abort(401)
    return to_json(auth_info)

def get_current_auth(db):
    try: cert_serial=struct.unpack(">I", request.environ["SSL_SERIAL"].decode("hex"))[0]
    except: return None
    cursor=db.cursor()
    cursor.execute("select uname,resource from user_certs where cert_serial=?", (cert_serial,))
    row=cursor.fetchone()
    if row is None: raise KeyError("No cert with serial %r"%(cert_serial,))
    return dict(row)

sql_existing="""
  select spkac,uname,resource,
    (select uname from users where users.uname=requests.uname) as existing_user,
    (select cert_serial from certs where certs.cert_serial=requests.cert_serial) as cert_serial
  from requests where req_id=?
"""

from pyasn1.type import univ, namedtype, char
from pyasn1_modules.rfc2459 import SubjectPublicKeyInfo, AlgorithmIdentifier
class PublicKeyAndChallenge(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("spki", SubjectPublicKeyInfo()),
        namedtype.NamedType("challenge", char.IA5String()),
    )

class SignedPublicKeyAndChallenge(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("publicKeyAndChallenge", PublicKeyAndChallenge()),
        namedtype.NamedType("signatureAlgorithm", AlgorithmIdentifier()),
        namedtype.NamedType("signature", univ.BitString()),
    )

def spkac2pubkey(spkac_data):
    from M2Crypto import BIO, EVP, RSA
    from pyasn1.codec.der.decoder import decode as decode_der
    from pyasn1.codec.der.encoder import encode as encode_der
    spkac_asn1, extra_data=decode_der(spkac_data.decode("base64"), asn1Spec=SignedPublicKeyAndChallenge())
    if extra_data: raise ValueError("Extra data after spkac: %r"%(extra_data, ))
    pubkey_bio=BIO.MemoryBuffer("{d}BEGIN {n}{d}\n{b64}{d}END {n}{d}\n".format(d="-"*5, n="PUBLIC KEY", b64=encode_der(spkac_asn1["publicKeyAndChallenge"]["spki"]).encode("base64")))
    pubkey_bio.close()
    pubkey=EVP.PKey()
    pubkey.assign_rsa(RSA.load_pub_key_bio(pubkey_bio))
    return pubkey

def sign_request(db, req_id, subject_dn=None):
    from M2Crypto import X509, EVP
    cursor=db.cursor()
    cursor.execute(sql_existing, (req_id,))
    row=cursor.fetchone()
    if row is None: raise KeyError("Request with req_id=%r not found"%(req_id,))
    spkac_data,uname,resource,have_user, have_cert=row
    if have_cert: raise ValueError("already have cert")
    ca_crt=X509.load_cert(CA_CRT)
    cert=create_cert(spkac2pubkey(spkac_data), EVP.load_key(CA_KEY), ca_crt.get_subject(), subject_dn=subject_dn)
    cursor.execute("insert into certs (cert, cert_serial) values (?,?)", (cert.as_pem(), cert.get_serial_number()))
    if not have_user: cursor.execute("insert into users (uname) values (?)", (uname,))
    cursor.execute("insert into user_certs (uname, resource, cert_serial) values (?,?,?)", (uname, resource, cert.get_serial_number()))
    cursor.execute("update requests set cert_serial=? where req_id=?", (cert.get_serial_number(), req_id,))
    db.commit()
    return True

if bottle.DEBUG:
    @app.get("/debug")
    def debug_info():
        response.content_type="text/plain"
        ret=[]
        for k in sorted(request.environ.keys()):
            ret.append("%s=%r"%(k, request.environ[k]))
        ret.append("Headers: \n\t%s"%("\n\t".join(map(lambda x: "%s=%r"%(x, request.headers.raw(x)),request.headers))))
        return "\n".join(ret)

def create_cert(pubkey, ca_key, issuer=None, exts=None, subject_dn=None):
    from M2Crypto import X509, ASN1
    if exts is None: exts=[
        X509.new_extension('basicConstraints', 'CA:FALSE', critical = True),
        X509.new_extension('keyUsage', 'digitalSignature, keyEncipherment', critical = True),
        X509.new_extension('extendedKeyUsage', 'clientAuth'),
    ]
    now=long(time.time())
    cert=X509.X509()
    cert.set_version(2)
    cert.set_serial_number(now)
    not_before=ASN1.ASN1_UTCTIME()
    not_before.set_time(now)
    cert.set_not_before(not_before)
    not_after=ASN1.ASN1_UTCTIME()
    not_after.set_time(now+365*24*3600)
    cert.set_not_after(not_after)
    cert.set_pubkey(pubkey)
    subject=X509.X509_Name()
    if subject_dn is None:
        subject_dn=[]
        while True:
            c=raw_input("Subject DN component (like CN=XYZ, Enter to finish): ")
            if not c: break
            subject_dn.append(c.split("=", 1))
    for name,val in subject_dn:
        setattr(subject, name, val)
    cert.set_subject(subject)
    cert.set_issuer(subject if issuer is None else issuer)
    map(cert.add_ext, exts)
    cert.sign(pkey=ca_key, md="sha256")
    return cert

if __name__ == '__main__':
    db=sqlite3.connect(DBNAME)
    try: req_id=sys.argv[1]
    except IndexError:
        print >>sys.stderr, """
Usage: %(arg0)s <req_id> [<dnval=x1> ..]
 OR    %(arg0)s --server [<ip>][:<port>]
"""%{"arg0":os.path.basename(sys.argv[0])}
        cursor=db.cursor()
        try: cursor.execute("select req_id,uname,resource,request_info from requests where cert_serial is null")
        except Exception as e:
            print >>sys.stderr, "Database error:",e
            if raw_input("Do you want to initialize %s? [y/N] "%(DBNAME, )).lower().startswith("y"):
                os.environ["CERT_DB"]=DBNAME
                os.environ["DB_SQL"]=os.path.join(my_dir, "db.sql")
                os.system("sqlite3 \"$CERT_DB\" < \"$DB_SQL\"")
            first=None
        req_id=None
        for (req_id,uname,resource,req_info) in cursor:
            print "Unsigned request", `req_id`
            print "\tUsername:", uname
            print "\tResource:", resource
            print "\tRequest info:"
            pprint.pprint(json.loads(req_info))
            print
        if not os.path.exists(CA_CRT):
            if raw_input("Do you want to create %s? [y/N] "%(CA_CRT,)).lower().startswith("y"):
                from M2Crypto import RSA, EVP, X509
                if not os.path.exists(CA_KEY):
                    print "Saving key to %s"%(CA_KEY,)
                    RSA.gen_key(2432, 0x10001).save_key(CA_KEY, None)
                key=EVP.load_key(CA_KEY)
                cert=create_cert(key, key, exts=[
                    X509.new_extension("basicConstraints", "CA:TRUE", critical=True),
                    X509.new_extension("keyUsage", "Certificate Sign, CRL Sign", critical=True),
                ])
                cert.save_pem(CA_CRT)
        raise SystemExit(1)
    if req_id=="--server":
        port=8080
        host="127.0.0.1"
        if len(sys.argv)>2:
            host_port=sys.argv[2].split(":",1)
            if len(host_port)>1: port=int(host_port[1])
            if host_port[0]: host=host_port[0]
        app.run(host=host, port=port)
    else:
        sign_request(db, req_id, subject_dn=map(lambda x: x.split("=",1), sys.argv[2:]) or None)
