import argparse
import json
from random import randint
import random
import sys
import time

import requests
from requests.auth import HTTPBasicAuth

STATIONS = {
    'atl': 'vir',
    'dal': 'chi',
    'nrk': 'nyc-ovi',
    'nva': 'vir',
    'fre': 'sfo-dio',
    'nca': 'nca',
    'ore': 'nca',
    'amd': 'ams-edi',
    'ire': 'dub',
    'lon': 'lon-lin',
    'sin': 'sng',
    'syd': 'syd',
    'tky': 'tyo',
    'tok': 'tyo-lin',
    'sap': 'spa',
}

COMP = {
    '<': 'lt',
    '>': 'gt',
    '<=': 'lte',
    '>=': 'gte',
    '==': 'eq',
    '!=': 'neq',
    '=~': 'c',
    '!~': 'nc',
    None: 'None'
}

# need to modify filesystem.

SECTIONS = {
    # "ce_filesystem_v1 free": ["system", "diskUsage"],  # needs a specifier for which part.
    # "ce_filesystem_v1 free_pcent": "Server: Filesystem Free (%) (avg)",
    # "ce_filesystem_v1 used": "Server: Filesystem Used (bytes) (avg)",
    "ce_filesystem_v1 used_pcent": ["system", "diskUsage"],
    # "ce_health health_index": "Health Index (avg)", not applicable
    "ce_health health_state_last_updated": ["noData", "device"],
    "ce_probe_summary_v1 app_connect_time": ["http", "time"],
    # "ce_probe_summary_v1 connect_time": "Probe Response: Connect Time (avg)",
    # "ce_probe_summary_v1 health": "Probe Health (avg)",
    # "ce_probe_summary_v1 pre_xfer_time": "Probe Response: Pretransfer Time (avg)",
    # "ce_probe_summary_v1 start_xfer_time": "Probe Response: Start Transfer Time (avg)",
    "ce_probe_summary_v1 message": ["http", "content"],
    "ce_probe_summary_v1 status": ["http", "status"],
    # "ce_probe_summary_v1 status_code": ["http", "code"],
    "ce_probe_summary_v1 time": ["service", "time"],
    "ce_rcsummary_v1 active": ["system", "idle"],
    # "ce_rcsummary_v1 blocked_pids": "Server Blocked Processes (avg)",
    # io "ce_rcsummary_v1 disk_reads": "Server Disk: Reads (bytes) (avg)",
    # io "ce_rcsummary_v1 disk_writes": "Server Disk: Writes (bytes) (avg)",
    "ce_rcsummary_v1 free_pcent": ["system", "memPhysFree"],
    "ce_rcsummary_v1 guest": ["system", "guest"],
    "ce_rcsummary_v1 idle": ["system", "idle"],
    "ce_rcsummary_v1 if_bytes_rx_gauge": ["networkTraffic", "rxMByteS"],
    "ce_rcsummary_v1 if_bytes_tx_gauge": ["networkTraffic", "txMByteS"],
    "ce_rcsummary_v1 iowait": ["system", "iowait"],
    "ce_rcsummary_v1 irq": ["system", "irq"],
    # "ce_rcsummary_v1 load_longterm": "Server Load: Longterm (avg)",
    # "ce_rcsummary_v1 load_midterm": "Server Load: Midterm (avg)",
    "ce_rcsummary_v1 load_shortterm": ["system", "loadAvrg"],
    # "ce_rcsummary_v1 mem_buffered": "Server Memory: Buffered (avg)",
    "ce_rcsummary_v1 mem_cached": ["system", "memPhysCached"],
    "ce_rcsummary_v1 nice": ["system", "nice"],
    "ce_rcsummary_v1 running_pids": ["Process", "processCount"],
    "ce_rcsummary_v1 softirq": ["system", "soft"],
    "ce_rcsummary_v1 steal": ["system", "steal"],
    "ce_rcsummary_v1 swap_free": ["system", "memSwapFree"],
    # "ce_rcsummary_v1 swap_total_pcent": "Server Swap: Total (avg)",
    "ce_rcsummary_v1 sys": ["system", "sys"],
    # "ce_rcsummary_v1 uptime": "Server Uptime (avg)",
    "ce_rcsummary_v1 used_pcent": ["system", "memPhysUsed"],
    "ce_rcsummary_v1 user": ["system", "usr"],
    "ce_usage payload": ["Process", "processNotRunning"],
}


def get_ce_json(api, urlpart):
    url = 'https://{0}:U@api.copperegg.com/v2'.format(api) + urlpart
    r = requests.get(url)
    if r.status_code == 200:
        return r.json()
    else:
        sys.exit("Error: {}".format(r.content))


def get_json(api, url):
    # note raise failure if cannot get.
    r = requests.get(url, auth=HTTPBasicAuth(api, 'u'))
    if r.status_code == 200:
        return r.json()
    else:
        sys.exit("Error: {}".format(r.content))


def random_color():
    return ''.join([random.choice('0123456789ABCDEF') for x in range(6)])


def SD_post(urlpart, data, SDtoken):
    """Gives you a json dictionary back"""

    url = 'https://api.serverdensity.io' + urlpart
    r = requests.post(url, params={'token': SDtoken}, data=data)
    j = r.json()
    if r.status_code == 200:
        if j.get('name'):
            print('Migrated item {0} to Server Density'.format(j.get('name')))
        elif j.get('firstName'):
            print('Migrated user {0} {1} to Server Density'.format(
                j.get('firstName'), j.get('lastName')))
        elif j.get('field'):
            print('Migrated alert {0} to Server Density'.format(
                j.get('field')))
        else:
            print('Migrated item to Server Density')
    else:
        sys.exit("Error! Status Code is: {}. Reason: {}".format(
            r.status_code, r.content))
        print("Will still continue")
    time.sleep(0.2)
    return j


def random_password():
    # good chars from 32 to 126
    password = ''
    for x in xrange(30):
        password += chr(randint(32, 126))
    return password


def get_servers(api, tagdict):
    urlpart = '/revealcloud/systems.json?show_hidden=1'
    servers = get_ce_json(api, urlpart)
    serverlist = []

    for no, server in enumerate(servers):
        data = {}
        data['name'] = server['a'].get('l', 'Server-'+str(no))
        data['hostname'] = server['a'].get('n')
        tag_ids = [tagdict[key].keys()[0] for key in server['a'].get('t')]
        data['tags'] = json.dumps(tag_ids)
        data['ce-uid'] = server['uuid']
        data['competitor'] = 'copperegg'
        serverlist.append(data)
    return serverlist


def things_with_tags(taglist, tagdict, things):
    """get devices or services based on tags
    only have one set of thing.
    Use a set to prevent duplication when several tags.
    """
    no_dup = set()
    thingdic = {}

    if taglist:
        for tag in taglist:
            tag_id = tagdict[tag].keys()[0]
            for thing in things.values():
                if tag_id in thing['tags']:
                    reformat = {thing['ce-uid']: thing}
                    no_dup.add(json.dumps(reformat))

        for thing in no_dup:
            thingdic.update(json.loads(thing))

        return thingdic
    else:
        return thingdic


def get_recipients(alert, raw_profiles, migrated_user_channel):
    """iterate over all not_profiles, check if alert exist
    in destination of profile. Correlate profile with user

    have something called migrated instead.
    """

    def modify_actions(all_recp, user_id, action):
        for recp in all_recp:
            if recp.get('user_id') == user_id:
                recp['actions'].append(action)
                # avoid duplicates of actions
                list(set(recp['actions']))
                return True
        return False

    all_recp = []

    for profile in raw_profiles:
        for dest in profile['destinations']:
            if alert['id'] in dest['alert_ids']:
                if dest['type'] == 'Email' or dest['type'] == 'Sms':
                    if not modify_actions(all_recp, profile['user_id'], dest['type'].lower()):
                        recp = {
                            'type': 'user',
                            'id': migrated_user_channel[str(profile['user_id'])]['_id'],  # need migrated user_id or migrated pagerduty/hipchat
                            'actions': [dest['type'].lower()],
                            'user_id': profile['user_id']
                        }
                        all_recp.append(recp)
                elif dest['type'] == 'Twitter' or dest['type'] == 'Campfire':
                    pass
                else:  # Pagerduty, hipchat,
                    recp = {
                        'type': dest['type'].lower(),
                        'id': migrated_user_channel[dest['id']]['_id'],
                    }
                    all_recp.append(recp)
    return all_recp


def get_alerts(api, migrated):
    """takes a dictionary migrated that contains
    raw_profiles, servers, services, user_channels, tags
    """

    urlpart = '/alerts/definitions.json'
    ce_alerts = get_ce_json(api, urlpart)
    sd_alerts = []

    def fill_data(alert, migrated):
        data = {}
        recipients = get_recipients(alert, migrated['raw_profiles'], migrated['user_channels'])

        repeat = {
            'seconds': 0,
            'enabled': False,
            'displayUnits': 's'
        }

        wait = {
            'seconds': 0,
            'enabled': False,
            'displayUnits': 's'
        }

        data['enabled'] = True
        section = ' '.join(alert['comp_val1'])

        elif section == 'ce_probe_summary_v1 status':
            data['comparison'] = 'eq'
            if alert['comp_val2'][0] > 99.0:
                data['value'] = 'up'
            elif alert['comp_val2'][0] > 95.0 or alert['comp_val2'][0] < 99.0:
                data['value'] = 'slow'
            else:
                data['value'] = 'down'
        else:
            data['comparison'] = COMP[alert['comp_func']]
            data['value'] = alert['comp_val2'][0]

        data['section'] = SECTIONS[section][0]
        data['subject'] = 'ALL'
        data['field'] = SECTIONS[section][1]
        data['recipients'] = json.dumps(recipients)
        data['repeat'] = json.dumps(repeat)
        data['wait'] = json.dumps(wait)
        data['ce-uid'] = alert['id']
        data['fix'] = True

        return data

    def associate_device_alert(tagged_devices, instruments, data):
        datalist = []
        if tagged_devices:  # associate alerts for tagged devices
            for thing in tagged_devices.values():
                data['subjectId'] = thing['_id']
                if thing.get('hostname'):
                    data['subjectType'] = 'device'
                else:
                    data['subjectType'] = 'service'
                datalist.append(data)
        else:  # if no tagged devices associate alert with all devices
            for instrument in instruments.values():
                data['subjectId'] = instrument['_id']
                if instrument.get('hostname'):
                    data['subjectType'] = 'device'
                else:
                    data['subjectType'] = 'service'
                datalist.append(data)
        return datalist

    for alert in ce_alerts:
        section = ' '.join(alert['comp_val1'])
        if alert['kind'] == 'ce_revealuptime' and SECTIONS.get(section):
            tagged_devices = things_with_tags(alert['match'].get('tag'),
                                              migrated['tags'], migrated['services'])
            data = fill_data(alert, migrated)
            datalist = associate_device_alert(
                tagged_devices, migrated['services'], data)
            sd_alerts.extend(datalist)

        elif alert['kind'] == 'ce_revealcloud' and SECTIONS.get(section):
            tagged_devices = things_with_tags(alert['match'].get('tag'),
                                              migrated['tags'], migrated['servers'])
            data = fill_data(alert, migrated)
            datalist = associate_device_alert(
                tagged_devices, migrated['servers'], data)
            sd_alerts.extend(datalist)
        else:
            pass  # skipping custom metrics called ce_revealmetrics

    return sd_alerts


def get_services(api, tagdict):
    urlpart = '/revealuptime/probes.json'
    services = get_ce_json(api, urlpart)
    serviceslist = []

    for service in services:
        if not service['type'] == 'ICMP':
            data = {}
            if service['type'] == 'GET' or service['type'] == 'PUT':
                data['checkType'] = 'HTTP'
                data['checkMethod'] = service['type']
            else:
                data['checkType'] = 'TCP'
            stationset = set()
            [stationset.add(STATIONS[place]) for place in service['stations']]
            tag_ids = [tagdict[key].keys()[0] for key in service.get('tags')]
            data['name'] = service['probe_desc']
            data['timeout'] = service['timeout']
            data['checkLocations'] = json.dumps(list(stationset))
            data['checkUrl'] = service['probe_dest']
            data['slowThreshold'] = '500'
            data['headers'] = json.dumps(service.get('headers'))
            data['body'] = service.get('probe_data')
            data['data'] = service.get('probe_data')
            data['tags'] = json.dumps(tag_ids)
            data['ce-uid'] = service['id']
            serviceslist.append(data)
    return serviceslist


def get_tags(api, SDtoken):
    """
    Creates all the tags that users have and return
    a dict in format {'name_of_tag': {'tag_id': {'mode': 'read'}}}"""

    servers = get_ce_json(api, '/revealcloud/systems.json?show_hidden=1')
    probes = get_ce_json(api, '/revealuptime/probes.json')

    tags = set()
    for server in servers:
        [tags.add(tag) for tag in server['a']['t']]

    for probe in probes:
        [tags.add(tag) for tag in probe['tags']]

    tagdict = {}
    for tag in tags:
        data = {
            'name': tag,
            'color': random_color()
        }
        response = SD_post('/inventory/tags', data, SDtoken)
        tagdict[tag] = {response['_id']: {'mode': 'read'}}
    return tagdict


def get_users_2(api, tagdict):
    """think of adding more addresses from notfications"""

    url = 'https://app.copperegg.com/api/2011-04-26/user/users.json'
    users = get_json(api, url)
    userslist = []

    for user in users:
        data = {}
        if user['role'] == 'admin':
            admin = True
        else:
            admin = False

        tags = {'tags': {}}
        for value in user['tags_allowed']:
            try:
                tags['tags'].update(tagdict[value])
            except KeyError as e:
                print('Unable to add: {}, no device has that tag'.format(value))
        data = {
            'admin': admin,
            'firstName': user.get('first_name'),
            'lastName': user.get('last_name'),
            'login': user.get('email'),  # same login as in copperegg
            'emailAddresses': json.dumps([user.get('email')]),
            'phoneNumbers': json.dumps([user.get('phone')]),
            'permissions': json.dumps(tags),
            'password': random_password(),
            'ce-not-id': user.get('notification_profile_id'),
            'ce-uid': user.get('id')
        }
        userslist.append(data)
        # how to handle failures?

    return userslist


def get_channels(api):
    """Get the different channels like slack, pagerduty, etc"""
    urlpart = '/alerts/profiles.json'
    profiles = get_ce_json(api, urlpart)
    channels = []
    for profile in profiles:
        for dest in profile['destinations']:
            if dest['type'] == 'Webhook':
                data = {
                    'name': dest['options'].get('url'),
                    'url': dest['options'].get('url'),
                    'type': 'webhook',
                    'ce-uid': dest['id']
                }
                channels.append(data)
            elif dest['type'] == 'PagerDuty':
                data = {
                    'name': 'Pagerduty',
                    'apiKey': dest['options'].get('api_key'),
                    'type': 'pagerduty',
                    'ce-uid': dest['id']
                }
                channels.append(data)
            elif dest['type'] == 'HipChat':
                data = {
                    'name': dest['options'].get('room_id'),
                    'room': dest['options'].get('room_id'),
                    'token': dest['options'].get('auth_token'),
                    'type': 'hipchat',
                    'ce-uid': dest['id']
                }
                channels.append(data)
    return channels


def migrate(items, SDurl, SDtoken):
    uid_map = {}
    for data in items:
        jsondict = SD_post(SDurl, data, SDtoken)
        uid_map[data['ce-uid']] = jsondict

    return uid_map


def migrate_users_old(userlist, SDtoken):
    # in case the other fail.

    # getting all users.

    # need to take care of destinations.
    # several users may have
    # we set a randomized password string.
    # then the user needs to reset the password.

    # how to configure the slack and  options.
    # how to choose username? - go for the firstname.
    #

    # which user would you like to be admin.
    print("Which user would you like to be admin?")
    for no, user in enumerate(userlist):
        print("(" + no + ") " + user['name'])

    integer = False
    while(not integer):
        choice = raw_input('Input which number: ')
        try:
            choice = int(choice)
            if choice <= len(userlist):
                integer = True
            else:
                print('There is not that many users in your list')

        except ValueError:
            print('Input a number, not something else')

    data = {}

    for no, user in enumerate(userlist):
        name = user['name']
        namelist = name.split(' ')

        # names
        data['firstName'] = namelist[0]
        if len(namelist) > 1:
            data['lastName'] = ''.join(namelist[1:])
        else:
            data['lastName'] = ''

        # numbers
        phonenumbers = [alert['options'].get('phone') for alert in
                        user['destinations'] if alert['label'] == 'SMS']

        emails = [alert['options'].get('email') for alert in
                  user['destinations'] if alert['label'] == 'Email']

        # chosen admin
        if no == choice:
            admin = True
        else:
            admin = False

        data['admin'] = admin
        data['phoneNumbers'] = json.dumps(phonenumbers)
        data['emailAddresses'] = json.dumps(emails)
        data['login'] = data['firstName']


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("api",
                        help="the api token you get from CopperEgg")
    parser.add_argument("SDtoken",
                        help="the api token you get from Server Density")
    args = parser.parse_args()

    tags = get_tags(api, SDtoken)
    channels = get_channels(api)
    users = get_users_2(api, tags)

    services = get_services(api, tags)
    servers = get_servers(api, tags)

    raw_profiles = get_ce_json(api, '/alerts/profiles.json')

    migrated_users = migrate(users, '/users/users', SDtoken)
    migrated_channels = migrate(channels, '/notifications/recipients', SDtoken)
    migrated_user_channel = migrated_users.update(migrated_channels)

    migrated = {}
    migrated['servers'] = migrate(servers, '/inventory/devices', SDtoken)
    migrated['services'] = migrate(services, '/inventory/services', SDtoken)
    migrated['user_channels'] = migrated_users
    migrated['raw_profiles'] = raw_profiles
    migrated['tags'] = tags

    alerts = get_alerts(api, migrated)

    migrate_alerts = migrate(alerts, '/alerts/configs', SDtoken)


