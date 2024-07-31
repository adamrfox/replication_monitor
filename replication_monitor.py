#!/usr/bin/python3

import sys
import getopt
import getpass
import requests
import urllib.parse
import json
import time
import os
import keyring
from datetime import datetime
import urllib.parse
import urllib3
urllib3.disable_warnings()

import pprint
pp = pprint.PrettyPrinter(indent=4)

def usage():
    print("Usage goes here!")
    exit(0)

def dprint(message):
    if DEBUG:
        dfh = open('debug.out', 'a')
        dfh.write(message + "\n")
        dfh.close()

def oprint(fp, message):
    if fp:
        fp.write(message + '\n')
    else:
        print(message)
    return
def api_login(qumulo, user, password, token):
    in_keyring = True
    headers = {'Content-Type': 'application/json'}
    if not token:
        if not user:
            user = input("User: ")
        if not password:
            password = keyring.get_password(RING_SYSTEM, user)
        if not password:
            in_keyring = False
            password = getpass.getpass("Password: ")
        payload = {'username': user, 'password': password}
        payload = json.dumps(payload)
        autht = requests.post('https://' + qumulo + '/api/v1/session/login', headers=headers, data=payload,
                              verify=False, timeout=timeout)
        dprint(str(autht.ok))
        auth = json.loads(autht.content.decode('utf-8'))
        dprint(str(auth))
        if autht.ok:
            auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + auth['bearer_token']}
            if not in_keyring:
                use_ring = input("Put these credentials into keyring? [y/n]: ")
                if use_ring.startswith('y') or use_ring.startswith('Y'):
                    keyring.set_password(RING_SYSTEM, user, password)
        else:
            sys.stderr.write("ERROR: " + auth['description'] + '\n')
            exit(2)
    else:
        auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + token}
    dprint("AUTH_HEADERS: " + str(auth_headers))
    return(auth_headers)

def qumulo_get(addr, api):
    dprint("API_GET: " + api)
    good = False
    while not good:
        good = True
        try:
            res = requests.get('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying..")
            time.sleep(5)
            good = False
            continue
        if res.content == b'':
            print("NULL RESULT[GET]: retrying..")
            good = False
            time.sleep(5)
    if res.status_code == 200:
        dprint("RESULTS: " + str(res.content))
        results = json.loads(res.content.decode('utf-8'))
        return(results)
    elif res.status_code == 404:
        return("404")
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + "\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)

def get_token_from_file(file):
    with open(file, 'r') as fp:
        tf = fp.read().strip()
    fp.close()
    t_data = json.loads(tf)
    dprint(t_data['bearer_token'])
    return(t_data['bearer_token'])

def read_conf_file(cf, good_states, ignore_paths, ignore_tags):
    ops = []
    with open(cf, 'r') as fp:
        for line in fp:
            line = line.rstrip('\n')
            if line.startswith('#') or line == "":
                continue
            lf = line.split('=')
            ops = lf[1].split(',')
            if lf[0] == "good_states":
                good_states = ops
            elif lf[0] == "ignore_paths":
                ignore_paths = ops
            elif lf[0] == "ignore_tags":
                ignore_tags = ops
    fp.close()
    return(good_states, ignore_paths, ignore_tags)

def find_alert(job_data):
    reason = ""
    if job_data['src_path'] not in ignore_paths:
        if job_data['state'] in good_states:
            if 'replication_enabled' not in ignore_tags and job_data['enabled']:
                if rec_window:
                    rp = job_data['rec_point_dt']
                    print(job_data['src_path'] + " : " + str(now) + " : " + str(rp) + " = " + str(now - rp))
                    if (now - rp) <= rec_window:
                        return("", reason)
                    reason = "Outside of Recovery Window"
                else:
                    return("",reason)
            else:
                reason = "Replication is not enabled"
        else:
            reason = "Job State is " + job_data['state']
    else:
        return("", reason)
    return(job_data['id'], reason)

def convert_window(win_s):
    t = int(win_s[:-1])
    unit = win_s[-1]
    if unit.lower() == "m":
        t = t * 60
    elif unit.lower() == "h":
        t = t * 3600
    elif unit.lower() == "d":
        t = t * 86400
    elif unit.lower == "w":
        t = t * 604800
    elif unit.lower() == "m":
        t = t * 2629800
    else:
        sys.stderr.write("Acceptable window units: [m, h, d, w, m\n")
        exit(2)
    return(t)

if __name__ == "__main__":
    DEBUG = False
    default_token_file = ".qfsd_cred"
    timeout = 30
    token_file = ""
    token = ""
    user = ""
    password = ""
    timeout = 30
    RING_SYSTEM = "q_rep_mon"
    EMAIL = True
    good_states = ['ESTABLISHED']
    ignore_paths = []
    ignore_tags = []
    paths = []
    alerts = []
    conf_file = "./rep_mon.conf"
    fp = ""
    outfile = ""
    rec_window = 0

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:c:f:C:o:nw:', ['help', 'DEBUG', 'token=', 'creds=', 'token-file=',
                                                                   'config-file=', 'output-file=', '--no-email', '--window='  ])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
        if opt in ('-t', '--token'):
            token = a
        if opt in ('-c', '--creds'):
            if ':' in a:
                (user, password) = a.split(':')
            else:
                user = a
        if opt in ('-f', '--token-file'):
            token_file = a
        if opt in ('c','--config-file'):
            conf_file = a
        if opt in ('-o', '--output-file'):
            outfile = a
        if opt in ('-n', '--no-email'):
            EMAIL = False
        if opt in ('-w', '--window'):
            rec_window = convert_window(a)

    qumulo = args.pop(0)
    RING_SYSTEM = RING_SYSTEM + "_" + qumulo
    paths = args
    if os.path.isfile(conf_file):
        (good_states, ignore_paths, ignore_tags) = read_conf_file(conf_file, good_states, ignore_paths, ignore_tags)
        dprint("GOOD_STATES: " + str(good_states))
        dprint("IGNORE_PATHS: " + str(ignore_paths))
        dprint("IGNORE_TAGS: " + str(ignore_tags))
    if not user and not token:
        if not token_file:
            token_file = default_token_file
        if os.path.isfile(token_file):
            token = get_token_from_file(token_file)
    auth = api_login(qumulo, user, password, token)
    dprint(str(auth))
    now = int(datetime.utcnow().timestamp())
    rep_status = qumulo_get(qumulo, '/v2/replication/source-relationships/status/')
#    pp.pprint(rep_status)
    if outfile:
        fp = open(outfile + '.new', 'w')
    oprint(fp, 'Source:,Path:,Target:,Path,Mode:,State:,Job State:,Enabled:, Recovery Point:')
    job_data = []
    for job in rep_status:
        jd = {}
        jd['id'] = job['id']
        jd['src'] = job['source_cluster_name']
        jd['src_path'] = job['source_root_path']
        jd['tgt'] = job['target_cluster_name']
        jd['tgt_path'] = job['target_root_path']
        jd['mode'] = job['replication_mode']
        jd['state'] = job['state']
        jd['job_state'] = job['job_state']
        jd['enabled'] = job['replication_enabled']
        if job['recovery_point']:
            rt = job['recovery_point'].split('.')
            rts = datetime.strptime(rt[0], "%Y-%m-%dT%H:%M:%S")
            jd['rec_point_dt'] = int(rts.timestamp())
            jd['rec_point_s'] = rts.strftime("%Y-%m-%d %H:%M:%S")
        (alert_id, reason) = find_alert(jd)
        if alert_id:
            alerts.append({'job': jd, 'reason': reason})
        job_data.append(jd)
    pp.pprint(alerts)
    if outfile:
        fp.close()
        os.replace(outfile + 'new', outfile)
