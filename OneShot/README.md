# One Shot Python script for n00bs 

  `traccar_bridge.py`  

  ---------------------------------------------------------------------------
  ### ONE-FILE bridge: Apple "Find My" network  ->  Traccar (OsmAnd protocol).
  ---------------------------------------------------------------------------
  
  Runs on a Raspberry Pi alongside Traccar. Every POLL_INTERVAL it logs into  
  Apple (cached token), pulls the location reports for the ******* 16-key  
  rotating beacon, decrypts them locally with the private keys, and forwards  
  each new fix to Traccar's OsmAnd endpoint (default :5055) as one device.  
  
  It reuses the exact, proven crypto/auth from this project (pypush_gsa_icloud  
  + fgtcm_locator) inlined here so the whole thing is a single portable file.  
  Modelled on github.com/jannisko/findmy-traccar-bridge (BRIDGE_* env names,  
  OsmAnd target, conservative poll interval) but with our own retrieval stack.  

 ---------------------------------------------------------------------------
 ### QUICK START (on the Pi)
 ---------------------------------------------------------------------------
  1. Dependencies:
        pip3 install requests cryptography srp pbkdf2 pycryptodome --break-system-packages
  2. Anisette server , reachable at ANISETTE_URL:
        docker run -d --restart always --name anisette -p 6969:6969 \
            dadoum/anisette-v3-server
  3. In Traccar, add a Device whose **Identifier** equals TRACCAR_DEVICE_ID
     (default "******").  Settings -> Devices -> +  ->  Identifier: ******
  4. Log in to Apple ONCE (interactive, needs the SMS code OR trusted device):
        python3 traccar_bridge.py --login
     This writes auth.json next to the script and is reused forever after.
  5. Run the bridge (foreground test):
        python3 traccar_bridge.py --once     # single cycle, then exit
        python3 traccar_bridge.py            # daemon loop
     or install the systemd unit shipped beside this file.



 ---------------------------------------------------------------------------
 ### CONFIG  (all overridable by environment variables / systemd Environment=)
 ---------------------------------------------------------------------------
  TRACCAR_URL        OsmAnd endpoint            (default http://localhost:5055)
  TRACCAR_DEVICE_ID  Traccar device identifier  (default ******)
  ANISETTE_URL       anisette server            (default http://localhost:6969)
  POLL_INTERVAL      seconds between polls       (default 1800 = 30 min)
  LOOKBACK_HOURS     report window each poll     (default 24)
  MIN_FIX_GAP        thin track: min seconds between posted fixes (default 0 = all)
  SECOND_FACTOR      sms | trusted_device        (default sms, used only at --login)
  STATE_DIR          where auth.json/state live  (default: this script's folder)
  LOG_LEVEL          DEBUG | INFO | WARNING      (default INFO)
  BRIDGE_PRIVATE_KEYS  comma-sep base64 privkeys (default: the 16 removed below)
  KEYS_FILE          path to a *_devices.json    (alternative key source)

  
