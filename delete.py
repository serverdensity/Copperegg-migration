import argparse
import time
import requests


def getSD(SDtoken, urlpart):
    url = 'https://api.serverdensity.io{}'.format(urlpart)
    r = requests.get(url, params={'token': SDtoken})
    j = r.json()
    time.sleep(0.1)
    return j


def delete(sdid, SDtoken, urlpart):
    url = 'https://api.serverdensity.io{0}/{sdid}'.format(urlpart, sdid=sdid)
    r = requests.delete(url, params={'token': SDtoken})
    time.sleep(0.1)
    return r.status_code


def delete_list(items, SDtoken, urlpart):
    for item in items:
        if '@' in str(item.get('login')):
            delete(item['_id'], SDtoken, urlpart)
            print "Item with id: {} has been deleted".format(item['_id'])
        else:
            print "Saving users that don't have an email as username"


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("SDtoken",
                        help="the api token you get from Server Density")
    args = parser.parse_args()

    SDtoken = args.SDtoken

    users = getSD(SDtoken, '/users/users')
    devices = getSD(SDtoken, '/inventory/devices')
    services = getSD(SDtoken, '/inventory/services')
    tags = getSD(SDtoken, '/inventory/tags')
    notifications = getSD(SDtoken, '/notifications/recipients')

    delete_list(users, SDtoken, '/users/users')
    delete_list(devices, SDtoken, '/inventory/devices')
    delete_list(services, SDtoken, '/inventory/services')
    delete_list(tags, SDtoken, '/inventory/tags')
    delete_list(notifications, SDtoken, '/notifications/recipients')
