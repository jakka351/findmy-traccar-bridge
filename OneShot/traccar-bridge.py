#!/usr/bin/env python3
# // ================================================================================================ // #
# //
# /                                          .  ....       .            ..                            
#                                          .:::. .:.... ...           .=+.                           
#                                           .::::::::::::::.         .=++-.                          
#                                          .:::::::::::::..          .++++:                          
#                                 .:-=.   .::::::::::::::.:          :++++-                          
#                               .=+++++-:..:::::::::::::.  .         :+++++-=.                       
#                              :+++++++++:::::::::::::::::...        :++++++++.                      
#                           ...-+++++++++::::::::::::::::::::.  .    +++++++++:                      
#                         .-=.+++++++++++-:::::::::::::::::::-++:  .=+++++++++=.                     
#                         -++++++++++++++-:::::::::::::::::::-+++++++++++++++++-                     
#                        .-++++++++++++++-:::::::::::::::::::=+++++++++++++++++-                     
#                       .=+++++++++++++++-:::::::::::::::::::=++++++++++++++++++..                   
#                     .:+++++++++++++++++=:::::::::::::::::::=++++++++++++++++++++=.                 
#                ..-+++++++++++++++++++++=:::::::::::::::::::+++++++++++++++++++++++=.               
#            .:=+++++++++++++++++++++++++=:::::::::::::::::::++++++++++++++++++++++++-               
#         ..:++++++++++++++++++++++++++++=:::::::::::::::::::+++++++++++++++++++++++++.              
#        :.+++++++++++++++++++++++++++++++:::::::::::::::::::+++++++++++++++++++++++++++-.           
#        -++++++++++++++++++++++++++++++++.::::JAKKA351::::::+++++++++++++++++++++++++++=            
#        :++++++++++++++++++++++++++++++++.::::::::::::::::::++++++++++++++++++++++++++++=.          
#        -++++++++++++++++++++++++++++++++.:-------------::::======++++++++++++++++++++++++.         
#        .=+++++++++++++++++++++++++++++++-+++++++++++++++++++++++=+++++++++++++++++++++++++:        
#        .+-++++++++++++++++++++++++++++++-+++++++++++++++++++++++=+++++++++++++++++++++++++-        
#        .:+++++++++++++++++++++++++++++++-+++++++++++++++++++++++=+++++++++++++++++++++++++:        
#          .++++++++++++++++++++++++++++++-+++++++++++++++++++++++----======++++++++==++=+==:        
#           .+++++++++++++++++++++++++++++=+++++++++++++++++++++++-===============-=========-.       
#             =++++++++++++++++++++++++++++=++++++++++++++++++++++-=========================.        
#             .++++++++++++++++++++++++++++=++==++++++++++++++++++-========================..        
#              :+++++++++++++++++++++++=:.       ..:-+++++++++++++-=======================-.         
#               .+++++++++++++++++=:.               .-+++++==+++++=======================-.          
#               .++++++++++++++++:                    .+++:.++++++-====================-:.           
#               .=++++++++:......                     .==  =:+++++=+:=================:              
#              .-++++++=.                                 ..:+++++=+++:==========--=-.               
#                 ..:..                                  .... .=+=+++++=----==-===--:.               
#                                                              -+=+++++++++++++-==-.                 
#                                                              .=-+++++++++++++=:-:.                 
#                                                                ..:=+++++++++:::.                   
#                                                                    ..  .:-.                        
#         TESTER PRESENT SPECIALIST AUTOMOTIVE SOLUTIONS              .:.     .                       
#                                                                     ....   ..                      
#                                                                      :=====-                       
#                                                                      .=====:                       
#                                                                      .-===-.                       
#                                                                        ::.                         
#
# =============================================================================
#  traccar_bridge.py
#
#  ONE-FILE bridge: Apple "Find My" network  ->  Traccar (OsmAnd protocol).
#
#  Runs on a Raspberry Pi alongside Traccar. Every POLL_INTERVAL it logs into
#  Apple (cached token), pulls the location reports for the ******* 16-key
#  rotating beacon, decrypts them locally with the private keys, and forwards
#  each new fix to Traccar's OsmAnd endpoint (default :5055) as one device.
#
#  It reuses the exact, proven crypto/auth from this project (pypush_gsa_icloud
#  + fgtcm_locator) inlined here so the whole thing is a single portable file.
#  Modelled on github.com/jannisko/findmy-traccar-bridge (BRIDGE_* env names,
#  OsmAnd target, conservative poll interval) but with our own retrieval stack.
#
#  ---------------------------------------------------------------------------
#  QUICK START (on the Pi)
#  ---------------------------------------------------------------------------
#   1. Dependencies:
#         pip3 install requests cryptography srp pbkdf2 pycryptodome
#   2. Anisette server (same one you already use), reachable at ANISETTE_URL:
#         docker run -d --restart always --name anisette -p 6969:6969 \
#             dadoum/anisette-v3-server
#   3. In Traccar, add a Device whose **Identifier** equals TRACCAR_DEVICE_ID
#      (default "fgtcm16").  Settings -> Devices -> +  ->  Identifier: fgtcm16
#   4. Log in to Apple ONCE (interactive, needs the SMS code):
#         python3 traccar_bridge.py --login
#      This writes auth.json next to the script and is reused forever after.
#   5. Run the bridge (foreground test):
#         python3 traccar_bridge.py --once     # single cycle, then exit
#         python3 traccar_bridge.py            # daemon loop
#      or install the systemd unit shipped beside this file.
#
#  ---------------------------------------------------------------------------
#  CONFIG  (all overridable by environment variables / systemd Environment=)
#  ---------------------------------------------------------------------------
#   TRACCAR_URL        OsmAnd endpoint            (default http://localhost:5055)
#   TRACCAR_DEVICE_ID  Traccar device identifier  (default fgtcm16)
#   ANISETTE_URL       anisette server            (default http://localhost:6969)
#   POLL_INTERVAL      seconds between polls       (default 1800 = 30 min)
#   LOOKBACK_HOURS     report window each poll     (default 24)
#   MIN_FIX_GAP        thin track: min seconds between posted fixes (default 0 = all)
#   SECOND_FACTOR      sms | trusted_device        (default sms, used only at --login)
#   STATE_DIR          where auth.json/state live  (default: this script's folder)
#   LOG_LEVEL          DEBUG | INFO | WARNING      (default INFO)
#   BRIDGE_PRIVATE_KEYS  comma-sep base64 privkeys (default: the 16 embedded below)
#   KEYS_FILE          path to a *_devices.json    (alternative key source)
#
# =============================================================================
import os, sys, json, base64, struct, hashlib, time, datetime, logging, argparse
import uuid, locale, hmac, plistlib as plist
from getpass import getpass

import requests
import pbkdf2
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from Crypto.Hash import SHA256

# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------
ANISETTE_URL      = os.environ.get("ANISETTE_URL", "http://localhost:6969")
TRACCAR_URL       = os.environ.get("TRACCAR_URL", "http://localhost:5055")
TRACCAR_DEVICE_ID = os.environ.get("TRACCAR_DEVICE_ID", "placeholder01")
POLL_INTERVAL     = int(os.environ.get("POLL_INTERVAL", "1800"))
LOOKBACK_HOURS    = int(os.environ.get("LOOKBACK_HOURS", "24"))
MIN_FIX_GAP       = int(os.environ.get("MIN_FIX_GAP", "0"))
SECOND_FACTOR     = os.environ.get("SECOND_FACTOR", "trusted_device")
STATE_DIR         = os.environ.get("STATE_DIR", os.path.dirname(os.path.realpath(__file__)))
LOG_LEVEL         = os.environ.get("LOG_LEVEL", "INFO").upper()

AUTH_CACHE = os.path.join(STATE_DIR, "auth.json")
STATE_FILE = os.path.join(STATE_DIR, "bridge_state.json")
APPLE_EPOCH = 978307200          # 2001-01-01 00:00 UTC -> unix offset

# The 16 FGTCM16 private keys (base64, P-224). Override via BRIDGE_PRIVATE_KEYS
# (comma separated) or KEYS_FILE (a macless-haystack *_devices.json).
EMBEDDED_KEYS = [
    "aaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbcccccc==",
]

log = logging.getLogger("bridge")

# ---------------------------------------------------------------------------
#  Apple Grand-Slam auth  (inlined verbatim from pypush_gsa_icloud.py - proven)
# ---------------------------------------------------------------------------
USER_ID   = uuid.uuid4()
DEVICE_ID = uuid.uuid4()
srp.rfc5054_enable()
srp.no_username_in_x()
import urllib3
urllib3.disable_warnings()


def icloud_login_mobileme(username='', password='', second_factor='sms'):
    if not username:
        username = input('Apple ID: ')
    if not password:
        password = getpass('Password: ')

    g = gsa_authenticate(username, password, second_factor)
    pet = g["t"]["com.apple.gs.idms.pet"]["token"]
    adsid = g["adsid"]

    data = {
        "apple-id": username,
        "delegates": {"com.apple.mobileme": {}},
        "password": pet,
        "client-id": str(USER_ID),
    }
    data = plist.dumps(data)

    headers = {
        "X-Apple-ADSID": adsid,
        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>',
    }
    headers.update(generate_anisette_headers())

    r = requests.post(
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
        auth=(username, pet), data=data, headers=headers, verify=False,
    )
    return plist.loads(r.content)


def gsa_authenticate(username, password, second_factor='sms'):
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()
    r = gsa_authenticated_request({"A2k": A, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"})
    if r["sp"] not in ["s2k", "s2k_fo"]:
        log.error("unsupported protocol %s (only s2k/s2k_fo)", r.get("sp"))
        return
    usr.p = encrypt_password(password, r["s"], r["i"], r["sp"])
    M = usr.process_challenge(r["s"], r["B"])
    if M is None:
        log.error("failed to process SRP challenge")
        return
    r = gsa_authenticated_request({"c": r["c"], "M1": M, "u": username, "o": "complete"})
    usr.verify_session(r["M2"])
    if not usr.authenticated():
        log.error("failed to verify SRP session")
        return

    spd = decrypt_cbc(usr, r["spd"])
    PLISTHEADER = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
"""
    spd = plist.loads(PLISTHEADER + spd)

    if "au" in r["Status"] and r["Status"]["au"] in ["trustedDeviceSecondaryAuth", "secondaryAuth"]:
        log.info("2FA required, requesting code")
        for k, v in spd.items():
            if isinstance(v, bytes):
                spd[k] = base64.b64encode(v).decode()
        if second_factor == 'sms':
            sms_second_factor(spd["adsid"], spd["GsIdmsToken"])
        elif second_factor == 'trusted_device':
            trusted_second_factor(spd["adsid"], spd["GsIdmsToken"])
        return gsa_authenticate(username, password)
    elif "au" in r["Status"]:
        log.error("unknown auth value %s", r["Status"]["au"])
        return
    else:
        return spd


def gsa_authenticated_request(parameters):
    body = {"Header": {"Version": "1.0.1"}, "Request": {"cpd": generate_cpd()}}
    body["Request"].update(parameters)
    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>',
    }
    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers=headers, data=plist.dumps(body), verify=False, timeout=10,
    )
    return plist.loads(resp.content)["Response"]


def generate_cpd():
    cpd = {"bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud"}
    cpd.update(generate_anisette_headers())
    return cpd


def generate_anisette_headers():
    try:
        import pyprovision
        from ctypes import c_ulonglong
        import secrets
        base = os.path.dirname(os.path.realpath(__file__)) + "/anisette/"
        adi = pyprovision.ADI(base)
        adi.provisioning_path = base
        device = pyprovision.Device(base + "device.json")
        if not device.initialized:
            device.server_friendly_description = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
            device.unique_device_identifier = str(uuid.uuid4()).upper()
            device.adi_identifier = secrets.token_hex(8).lower()
            device.local_user_uuid = secrets.token_hex(32).upper()
        adi.identifier = device.adi_identifier
        dsid = c_ulonglong(-2).value
        if not adi.is_machine_provisioned(dsid):
            log.info("provisioning anisette...")
            pyprovision.ProvisioningSession(adi, device).provision(dsid)
        otp = adi.request_otp(dsid)
        a = {"X-Apple-I-MD": base64.b64encode(bytes(otp.one_time_password)).decode(),
             "X-Apple-I-MD-M": base64.b64encode(bytes(otp.machine_identifier)).decode()}
    except ImportError:
        h = json.loads(requests.get(ANISETTE_URL, timeout=10).text)
        a = {"X-Apple-I-MD": h["X-Apple-I-MD"], "X-Apple-I-MD-M": h["X-Apple-I-MD-M"]}
    a.update(generate_meta_headers(user_id=USER_ID, device_id=DEVICE_ID))
    return a


def generate_meta_headers(serial="0", user_id=uuid.uuid4(), device_id=uuid.uuid4()):
    return {
        "X-Apple-I-Client-Time": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "X-Apple-I-TimeZone": str(datetime.datetime.utcnow().astimezone().tzinfo),
        "loc": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Apple-I-MD-LU": base64.b64encode(str(user_id).upper().encode()).decode(),
        "X-Mme-Device-Id": str(device_id).upper(),
        "X-Apple-I-SRL-NO": serial,
    }


def encrypt_password(password, salt, iterations, protocol):
    assert protocol in ["s2k", "s2k_fo"]
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return pbkdf2.PBKDF2(p, salt, iterations, SHA256).read(32)


def create_session_key(usr, name):
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def decrypt_cbc(usr, data):
    key = create_session_key(usr, "extra data key:")
    iv = create_session_key(usr, "extra data iv:")[:16]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def trusted_second_factor(dsid, idms_token):
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()
    headers = {
        "Content-Type": "text/x-xml-plist", "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist", "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth", "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>',
    }
    headers.update(generate_anisette_headers())
    requests.get("https://gsa.apple.com/auth/verify/trusteddevice",
                 headers=headers, verify=False, timeout=10)
    code = getpass("Enter 2FA code: ")
    headers["security-code"] = code
    resp = requests.get("https://gsa.apple.com/grandslam/GsService2/validate",
                        headers=headers, verify=False, timeout=10)
    if resp.ok:
        log.info("2FA accepted")


def sms_second_factor(dsid, idms_token):
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()
    headers = {
        "User-Agent": "Xcode", "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth", "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>',
    }
    headers.update(generate_anisette_headers())
    body = {"phoneNumber": {"id": 1}, "mode": "sms"}
    requests.put("https://gsa.apple.com/auth/verify/phone/",
                 json=body, headers=headers, verify=False, timeout=10)
    code = input("Enter 2FA code: ")
    body["securityCode"] = {"code": code}
    resp = requests.post("https://gsa.apple.com/auth/verify/phone/securitycode",
                        json=body, headers=headers, verify=False, timeout=10)
    if resp.ok:
        log.info("2FA accepted")


# ---------------------------------------------------------------------------
#  Keys, auth cache, report decrypt  (from fgtcm_locator.py)
# ---------------------------------------------------------------------------
def _sha256(b):
    h = hashlib.new("sha256"); h.update(b); return h.digest()


def _private_keys():
    """Return the list of base64 private keys from env / KEYS_FILE / embedded."""
    env = os.environ.get("BRIDGE_PRIVATE_KEYS")
    if env:
        return [k.strip() for k in env.split(",") if k.strip()]
    kf = os.environ.get("KEYS_FILE")
    if kf and os.path.exists(kf):
        with open(kf) as f:
            dev = json.load(f)[0]
        return [dev["privateKey"]] + dev.get("additionalKeys", [])
    return list(EMBEDDED_KEYS)


def load_keys():
    """{hashed_adv_key_b64: (private_key_b64, index)} for every configured key."""
    out = {}
    for i, priv_b64 in enumerate(_private_keys()):
        d = int.from_bytes(base64.b64decode(priv_b64), "big")
        x = ec.derive_private_key(d, ec.SECP224R1(), default_backend()
                                  ).public_key().public_numbers().x
        out[base64.b64encode(_sha256(x.to_bytes(28, "big"))).decode()] = (priv_b64, i)
    return out


def get_auth(regen=False, second_factor="sms"):
    """(dsid, searchPartyToken); cached in auth.json after the first login."""
    if os.path.exists(AUTH_CACHE) and not regen:
        with open(AUTH_CACHE) as f:
            j = json.load(f)
    else:
        m = icloud_login_mobileme(second_factor=second_factor)
        j = {"dsid": m["dsid"],
             "searchPartyToken":
                 m["delegates"]["com.apple.mobileme"]["service-data"]["tokens"]["searchPartyToken"]}
        with open(AUTH_CACHE, "w") as f:
            json.dump(j, f)
        log.info("Apple login OK - token cached in %s", AUTH_CACHE)
    return (j["dsid"], j["searchPartyToken"])


def decrypt_report(priv_b64, payload_b64):
    """OpenHaystack ECIES: ECDH(P-224) -> SHA256 KDF -> AES-128-GCM -> location."""
    priv = int.from_bytes(base64.b64decode(priv_b64), "big")
    data = base64.b64decode(payload_b64)
    if len(data) > 88:
        data = data[:4] + data[5:]
    timestamp = int.from_bytes(data[0:4], "big") + APPLE_EPOCH
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), data[5:62])
    shared = ec.derive_private_key(priv, ec.SECP224R1(), default_backend()
                                   ).exchange(ec.ECDH(), eph_pub)
    sym = _sha256(shared + b"\x00\x00\x00\x01" + data[5:62])
    dec_key, iv = sym[:16], sym[16:]
    enc, tag = data[62:72], data[72:]
    dec = Cipher(algorithms.AES(dec_key), modes.GCM(iv, tag), default_backend()).decryptor()
    pt = dec.update(enc) + dec.finalize()
    return {
        "lat": struct.unpack(">i", pt[0:4])[0] / 1e7,
        "lon": struct.unpack(">i", pt[4:8])[0] / 1e7,
        "conf": pt[8],
        "status": pt[9],
        "timestamp": timestamp,
    }


def fetch_fixes(hours):
    """Authenticate (cached) + fetch + decrypt -> list of fixes sorted by time."""
    keys = load_keys()
    now = int(datetime.datetime.now().timestamp())
    start = now - hours * 3600
    body = {"search": [{"startDate": start * 1000, "endDate": now * 1000,
                        "ids": list(keys.keys())}]}
    r = requests.post("https://gateway.icloud.com/acsnservice/fetch",
                      auth=get_auth(), headers=generate_anisette_headers(),
                      json=body, timeout=30)
    r.raise_for_status()
    results = r.json().get("results", [])
    fixes = []
    for rep in results:
        k = keys.get(rep["id"])
        if not k:
            continue
        try:
            loc = decrypt_report(k[0], rep["payload"])
            loc["key_index"] = k[1]
            loc["key_hex"] = f"{k[1]:X}"
            fixes.append(loc)
        except Exception as e:
            log.debug("decrypt failed for %s...: %s", rep["id"][:12], e)
    fixes.sort(key=lambda x: x["timestamp"])
    log.info("fetched %d reports -> %d decrypted fixes (last %dh)",
             len(results), len(fixes), hours)
    return fixes


# ---------------------------------------------------------------------------
#  Traccar OsmAnd output
# ---------------------------------------------------------------------------
def battery_from_status(status):
    """Best-effort: OpenHaystack status bits 6-7 encode a coarse battery level."""
    return {0: 100, 1: 60, 2: 30, 3: 10}.get((status >> 6) & 0x03, 0)


def post_to_traccar(fix):
    """POST one fix to Traccar's OsmAnd endpoint. Returns True on HTTP 200."""
    params = {
        "id": TRACCAR_DEVICE_ID,
        "lat": f"{fix['lat']:.7f}",
        "lon": f"{fix['lon']:.7f}",
        "timestamp": int(fix["timestamp"]),
        "batt": battery_from_status(fix["status"]),
        "conf": fix["conf"],
        "status": fix["status"],
        "key": fix["key_hex"],
    }
    try:
        r = requests.post(TRACCAR_URL, params=params, timeout=15)
    except requests.RequestException as e:
        log.error("Traccar unreachable at %s: %s", TRACCAR_URL, e)
        return False
    if r.status_code == 200:
        return True
    if r.status_code == 400:
        log.error("Traccar 400 - is a device with Identifier '%s' added in Traccar?",
                  TRACCAR_DEVICE_ID)
    else:
        log.error("Traccar HTTP %s for fix @ %s", r.status_code, fix["timestamp"])
    return False


# ---------------------------------------------------------------------------
#  State (dedup across restarts) + one bridge cycle
# ---------------------------------------------------------------------------
def load_state():
    try:
        with open(STATE_FILE) as f:
            s = json.load(f)
            return set(s.get("sent", [])), s.get("last_posted_ts", 0)
    except Exception:
        return set(), 0


def save_state(sent, last_posted_ts):
    cutoff = int(time.time()) - 14 * 86400          # keep 14 days of dedup history
    sent = {t for t in sent if t >= cutoff}
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"sent": sorted(sent), "last_posted_ts": last_posted_ts}, f)
    os.replace(tmp, STATE_FILE)
    return sent


def run_cycle():
    sent, last_posted_ts = load_state()
    fixes = fetch_fixes(LOOKBACK_HOURS)
    posted = 0
    for fx in fixes:
        ts = int(fx["timestamp"])
        if ts in sent:
            continue
        if MIN_FIX_GAP and last_posted_ts and (ts - last_posted_ts) < MIN_FIX_GAP:
            sent.add(ts)                            # thinned out, but mark seen
            continue
        if post_to_traccar(fx):
            sent.add(ts)
            last_posted_ts = max(last_posted_ts, ts)
            posted += 1
            iso = datetime.datetime.fromtimestamp(ts).isoformat()
            log.info("-> Traccar  %s  %.6f,%.6f  key=%s batt=%d%%",
                     iso, fx["lat"], fx["lon"], fx["key_hex"], battery_from_status(fx["status"]))
    save_state(sent, last_posted_ts)
    if posted:
        log.info("posted %d new fix(es) to device '%s'", posted, TRACCAR_DEVICE_ID)
    else:
        log.info("no new fixes this cycle")
    return posted


# ---------------------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Bridge Apple Find My -> Traccar (OsmAnd).")
    ap.add_argument("--login", action="store_true",
                    help="interactive Apple login (do this once over SSH), then exit")
    ap.add_argument("--once", action="store_true", help="run a single poll cycle, then exit")
    ap.add_argument("--hours", type=int, help="override LOOKBACK_HOURS for this run")
    args = ap.parse_args()

    logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")

    global LOOKBACK_HOURS
    if args.hours:
        LOOKBACK_HOURS = args.hours

    if args.login:
        log.info("interactive Apple login (anisette at %s)", ANISETTE_URL)
        get_auth(regen=True, second_factor=SECOND_FACTOR)
        return

    if not os.path.exists(AUTH_CACHE):
        if sys.stdin and sys.stdin.isatty():
            log.warning("no auth.json - running interactive login now")
            get_auth(regen=True, second_factor=SECOND_FACTOR)
        else:
            log.error("no auth.json and no terminal. Run once with --login first.")
            sys.exit(2)

    log.info("FindMy->Traccar bridge | traccar=%s device=%s anisette=%s interval=%ss lookback=%sh keys=%d",
             TRACCAR_URL, TRACCAR_DEVICE_ID, ANISETTE_URL, POLL_INTERVAL, LOOKBACK_HOURS,
             len(_private_keys()))

    if args.once:
        run_cycle()
        return

    while True:
        try:
            run_cycle()
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            if code in (401, 403):
                log.error("Apple rejected the token (HTTP %s). Re-run: %s --login",
                          code, os.path.basename(__file__))
            else:
                log.error("fetch HTTP error %s", code)
        except Exception as e:
            log.exception("cycle failed: %s", e)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
