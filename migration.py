import json
from random import randint
import random
import requests
from requests.auth import HTTPBasicAuth


# url = 'https://{0}:U@api.copperegg.com/v2/alerts/profiles.json'

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
    '!~': 'nc'
}


def get_ce_json(api, urlpart):
    url = 'https://{0}:U@api.copperegg.com/v2'.format(api) + urlpart
    r = requests.get(url)
    return r.json()


def get_json(api, url):
    # note raise failure if cannot get.
    r = requests.get(url, auth=HTTPBasicAuth(api, 'u'))
    return r.json()


def random_color():
    return ''.join([random.choice('0123456789ABCDEF') for x in range(6)])


def SD_post(urlpart, data, SDtoken):
    # note raise failure if not cannot post.

    url = 'https://api.serverdensity.io' + urlpart
    r = requests.post(url, params={'token': SDtoken}, data=data)
    return r.json()


def random_password():
    # good chars from 32 to 126
    password = ''
    for x in xrange(30):
        password += chr(randint(32, 126))
    return password


def migrate_notifications(userlist):
    """
    _id: "54eb5af28ac41c10531bd560"
    accountId: "5460a25976d377c3324420b2"
    name: "jonathan"
    type: "webhook"
    url: "https://github.com/serverdensity/Fluffify"
    userId: "5460a25f76d377cf324420b1

    return a mapping between not-id and _id

    """
    # how the post request looks like.


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


def things_with_tags(taglist, tagdict, services, servers):
    """get devices or services based on tags
    only have one set of thing."""
    no_dup = set()

    everything = services + servers
    if taglist:
        for tag in taglist:
            tag_id = tagdict[tag].keys()[0]
            for thing in everything:
                if tag_id in thing['tags']:
                    no_dup.add(json.dumps(thing))

        no_dup_list = []
        for thing in no_dup:
            no_dup_list.append(json.loads(thing))

        return no_dup_list
    else:
        return everything


def get_recipients(alert, noti_profiles):
    """iterate over all not_profiles, check if alert exist
    in destination of profile. Correlate profile with user"""

    def find_user_profile_id(all_recp, p_id):
        """if there is a user recp added already, find it"""
        for no, recp in enumerate(all_recp):
            if recp['type'] == 'user' and recp['profile_id'] == p_id:
                found = all_recp.pop(no)
                return all_recp, found
        return None

    all_recp = []

    for profile in noti_profiles:
        destinations = profile['destinations']
        for dest in destinations:
            if alert['id'] in dest['alert_ids']:
                all_recp, former_recp = find_user_profile_id(all_recp, profile['id'])
                if former_recp and (dest['type'] == 'Sms' or dest['email'] == 'Email'):
                    former_recp['actions'].append(dest['type'].lower())
                    all_recp.append(former_recp)
                elif dest['type'] == 'Email' or dest['type'] == 'Sms':
                    recp = {
                        'type': 'user'
                        'id': # need migrated id
                        'actions': [dest['type'].lower()]
                        'profile_id': profile['id']
                    }
                    all_recp.append(recp)



def get_alerts(api, tagdict, mig_servers, mig_services, mig_users):
    urlpart = '/alerts/definitions.json'
    alerts = get_ce_json(api, urlpart)
    alertslist = []

    for alert in alerts:
        data = {}
        if alert['kind'] == 'ce_revealuptime':
            tagged_devices = things_with_tags(alert['match'].get('tag'),
                                              tagdict, mig_services)
        elif alert['kind'] == 'ce_revealcloud':
            tagged_devices = things_with_tags(alert['match'].get('tag'),
                                              tagdict, mig_servers)
        else:
            tagged_devices = []


        recipients = get_recipients(alert, not_profiles)

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

        data['']


def migrate_servers(serverlist, SDtoken):
    """Use a list of server data and return a mapping
    of ce-uid and service"""
    urlpart = '/inventory/devices'

    uuid_map = {}
    for data in serverlist:
        r = SD_post(urlpart, data, SDtoken)
        uuid_map[data['ce-uid']] = r.json()

    return uuid_map


def get_services(api, tagdict):
    urlpart = '/revealuptime/probes.json'
    services = get_ce_json(api, urlpart)
    serviceslist = []

    for service in services:
        data = {}
        stationset = set()
        [stationset.add(STATIONS[place]) for place in service['stations']]
        tag_ids = [tagdict[key].keys()[0] for key in service.get('tags')]

        data['name'] = service['probe_desc']
        data['checkType'] = service['type']
        data['timeout'] = service['timeout']
        data['checkLocations'] = json.dumps(list(stationset))
        data['checkUrl'] = service['probe_dest']
        data['headers'] = json.dumps(service.get('headers'))
        data['body'] = service.get('probe_data')
        data['data'] = service.get('probe_data')
        data['tags'] = json.dumps(tag_ids)
        data['ce-uid'] = service['id']
        serviceslist.append(data)
    return serviceslist


def migrate_services(serviceslist, SDtoken):
    """Use a list of services and return a mapping of
    ce-uid and the service"""
    urlpart = '/inventory/services'
    uid_map = {}

    for data in serviceslist:
        r = SD_post(urlpart, data, SDtoken)
        uid_map[data['ce-uid']] = r.json()

    return uid_map


def create_tags(SDtoken, users):
    """
    Creates all the tags that users have and return
    a dict in format {'name_of_tag': {'tag_id': {'mode': 'read'}}}"""

    tags = set()
    for user in users:
        [tags.add(tag) for tag in user['tags_allowed']]

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
            tags['tags'].update(tagdict[value])

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

def migrate_users(userslist, SDtoken):
    # SD_post('/users/users', data, SDtoken)
    pass

def migrate_users(userlist, SDtoken):
    # in case the other fail.

    # getting all users.

    # need to take care of destinations.
    # several users may have
    # we set a randomized password string.
    # then the user needs to reset the password.

    # how to configure the slack and hipchat options.
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

