#!/usr/bin/env python
# coding: utf8
#########################################################
# API REST CENTREON                                     #
# last update 28/05/17                                  #
#########################################################

#https://documentation.centreon.com/docs/centreon/en/2.8.x/api/api_rest/index.html
__authors__ = 'Morgan Fourny'
__version__ = '1'
__email__ = 'morgan@1000mercis.com'
__status__ = 'alpha'


import json
import sys
import logging
import ssl
import os

# For debug
logging.basicConfig(filename='/tmp/ansible.log', level=logging.DEBUG)

# For use https link without error
#ssl._create_default_https_context = ssl._create_unverified_context

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

if sys.version_info.major == 3:
 
    try:
        import urllib.request
        import urllib.response
        import urllib.error
        HAS_REQUEST = True
    except ImportError:
        HAS_REQUEST = False
else:
    try:
        import urllib2
        HAS_REQUEST = True
    except ImportError:
        HAS_REQUEST = False

from ansible.module_utils.basic import *


class CentreonAPI(object):

    def __init__(self, url, **credentials):
        self.url = url
        self.action_url = "{}/{}".format(self.url, "?action=action&object=centreon_clapi")
        self.credentials = credentials

        self.token = self.get_auth_token()
        if not self.token:
            sys.exit(0)

        self.headers = headers = {
           'Centreon-Auth-Token': self.token["authToken"],
           'Content-Type':'application/json',
           'Cache-Control':'no-cache',
           'Return_Content':'True',
           'connection':'close',
           'Accept':'*/*'
        }

    def ____my_send(self, payload, url=None, headers=None):
        """ Return the request response. Otherwise, empty dict.
        """
        try:
            _headers = headers or self.headers
            _url = url or self.action_url
            #if not payload[0] == chr(34) and playload[-1] == chr(34):
            #    payload = chr(34) + payload + chr(34)

            if sys.version_info.major == 3:
                req = urllib.request.Request(_url, str.encode(payload), _headers)
                with urllib.request.urlopen(req) as response:
                    return json.loads(response.read().decode())
            else:
                req = urllib2.Request(_url, str.encode(payload), _headers)
                response = urllib2.urlopen(req)
                return json.loads(response.read().decode())
        except Exception as e:
            # TODO: print log
            #return json.loads(e)
            logging.debug(e)
            logging.debug(dir(e))
            err = e.read().decode()
            logging.debug(err)
            return json.loads(err)

    def send(self, payload, url=None, headers=None):
        """ Return the request response. Otherwise, empty dict.
        """

        _headers = headers or self.headers
        _url = url or self.action_url
        #if not payload[0] == chr(34) and playload[-1] == chr(34):
        #    payload = chr(34) + payload + chr(34)

        if sys.version_info.major == 3:
            try:
                req = urllib.request.Request(_url, str.encode(payload), _headers)
                with urllib.request.urlopen(req) as response:
                    return json.loads(response.read().decode())
            except urllib.error.HTTPError as err:
                if err.code == 200:
                    error = json.dumps({ '' : "200 " + err.reason })
                if err.code == 400:
                    error = json.dumps({ '' : "400 " + err.reason })
                if err.code == 401:
                    error = json.dumps({ '' : "401 " + err.reason })
                if err.code == 404:
                    error = json.dumps({ '' : "404 " + err.reason })
                if err.code == 409:
                    error = json.dumps({ '' : "409 " + err.reason })
                if err.code == 500:
                    error = json.dumps({ '' : "500 " + err.reason })
                return json.loads(error)
            except Exception as e:
                # TODO: print log
                #return json.loads(e)
                return json.loads(e.read().decode())


        else:
            try:
                req = urllib2.Request(_url, str.encode(payload), _headers)
                response = urllib2.urlopen(req)
                return json.loads(response.read().decode())
                #message = json.dumps({ '' : "200 " + response.read().decode() })
                #return json.loads(message)
            except urllib2.HTTPError as err:
                if err.code == 200:
                    error = json.dumps({ '' : "200 " + err.read() })
                if err.code == 400:
                    error = json.dumps({ '' : "400 " + err.read() })
                if err.code == 401:
                    error = json.dumps({ '' : "401 " + err.read() })
                if err.code == 404:
                    error = json.dumps({ '' : "404 " + err.read() })
                if err.code == 409:
                    error = json.dumps({ '' : "409 " + err.read() })
                if err.code == 500:
                    error = json.dumps({ '' : "500 " + err.read() })
                return json.loads(error)
            except Exception as e:
                # TODO: print log
                #return json.loads(e)
                return json.loads(e.read().decode())



    def get_auth_token(self):
        #Authentification, if success you'll receive a token.
        #Otherwise, None.
        try:
            headers = {
               'Content-Type':'application/x-www-form-urlencoded',
               'Accept':'*/*'
            }
            payload = '&username={user}&password={password}'.format(**self.credentials)
            url = "{}/{}".format(self.url, "?action=authenticate")
            return self.send(payload=payload, url=url, headers=headers)
        except Exception as e:
            # TODO: print log
            logging.debug(e)
            return json.loads(e.read().decode())

    def get_list_hosts(self):
        """ Get list of all hosts in centreon"""
#       self.send(payload='{"action":"show", "object":"host"}')
        payload = '{"action":"show", "object":"host"}'
        return self.send(payload=payload)
    def add_host(self, values):
        """Add new host in centreon.values :
            1 Host name
            2 Host alias
            3 Host IP address
            4 Host templates; for multiple definitions, use delimiter |
            5 Instance name (poller)
            6 Hostgroup; for multiple definitions, use delimiter |
        """
        return self.send(payload=self.make_payload(action='add', values=values))

    def del_host(self, values):
        return self.send(payload=self.make_payload(action='del', values=values))

    def set_parameters(self, values):
        return self.send(payload=self.make_payload(action='setparam', values=values))

    def set_instance_poller(self, values):
        return self.send(payload=self.make_payload(action='setinstance', values=values))

    def get_macro(self, values):
        return self.send(payload=self.make_payload(action='getmacro', values=values))

    def set_macro(self, values):
        """Set macro for one host. ("values": "hostname;MacroName;NewValue")"""
        return self.send(payload=self.make_payload(action='setmacro', values=values))

    def del_macro(self, values):
        """del macro for one host. ("values": "hostname;MacroName")"""
        return self.send(payload=self.make_payload(action='delmacro', values=values))

    def get_template(self, values):
        """Get template(s) used for one host. ("values": "hostname")"""
        return self.send(payload=self.make_payload(action='gettemplate', values=values))

    def set_template(self, values):
        """Set one template used for the host. ("values": "hostname;MyHostTemplate")
        Erase others template(s)"""
        return self.send(payload=self.make_payload(action='settemplate', values=values))

    def add_template(self, values):
        """Add one template used for the host. ("values": "hostname;MyHostTemplate")
        Don't erase others template(s)"""
        return self.send(payload=self.make_payload(action='addtemplate', values=values))

    def delete_template(self, values):
        """Del one template on the host. ("values": "hostname;MyHostTemplate")"""
        return self.send(payload=self.make_payload(action='deltemplate', values=values))

    def apply_template(self, values):
        """Apply one template on the host. ("values": "hostname")"""
        return self.send(payload=self.make_payload(action='applytpl', values=values))

    def get_parent(self, values):
        """Get parent on the host. ("values": "hostname")"""
        return self.send(payload=self.make_payload(action='getparent', values=values))

    def add_parent(self, values):
        """Add parent(s) on the host. ("values": "hostname;parent1|parent2")
        without overwrite"""
        return self.send(payload=self.make_payload(action='addparent', values=values))

    def set_parent(self, values):
        """Set parent(s) on the host. ("values": "hostname;parent1|parent2")
        it's overwrite"""
        return self.send(payload=self.make_payload(action='setparent', values=values))

    def del_parent(self, values):
        """Del parent(s) on the host. ("values": "hostname;parent1|parent2")
        """
        return self.send(payload=self.make_payload(action='delparent', values=values))

    def get_contact_group(self, values):
        """Get contact(s) group on the host. ("values": "hostname")
        """
        return self.send(payload=self.make_payload(action='getcontactgroup', values=values))

    def add_contact_group(self, values):
        """Add contact(s) group on the host. ("values": "host;contact_group_name1|contact_group_nameX")
        without overwrite"""
        return self.send(payload=self.make_payload(action='addcontactgroup', values=values))

    def set_contact_group(self, values):
        """Set contact(s) group on the host. ("values": "host;contact_group_name1|contact_group_nameX")
        it's overwrite"""
        return self.send(payload=self.make_payload(action='setcontactgroup', values=values))

    def del_contact_group(self, values):
        """Del contact(s) group on the host. ("values": "host;contact_group_name1|contact_group_nameX")
        """
        return self.send(payload=self.make_payload(action='delcontactgroup', values=values))

    def get_contact(self, values):
        """Get contact(s) on the host. ("values": "hostname")
        """
        return self.send(payload=self.make_payload(action='getcontact', values=values))

    def add_contact(self, values):
        """Add contact(s) on the host. ("values": "host;contact_group_name1|contact_group_nameX")
        without overwrite"""
        return self.send(payload=self.make_payload(action='addcontact', values=values))

    def set_contact(self, values):
        """Set contact(s) on the host. ("values": "host;contact_group_name1|contact_group_nameX")
        it's overwrite"""
        return self.send(payload=self.make_payload(action='setcontact', values=values))

    def del_contact(self, values):
        """Del contact(s) on the host. ("values": "host;contact_group_name1|contact_group_nameX")"""
        return self.send(payload=self.make_payload(action='delcontact', values=values))

    def get_hostgroup(self, values):
        """Get hostgroup(s) for the host. ("values": "hostname")"""
        return self.send(payload=self.make_payload(action='gethostgroup', values=values))

    def add_hostgroup(self, values):
        """Add hostgroup(s) for the host. ("values": "hostname;hostgroup1|hostgroupX")"""
        return self.send(payload=self.make_payload(action='addhostgroup', values=values))

    def create_hostgroup(self, values):
        """Add hostgroup(s) for the host. ("values": "hostname;hostgroup1|hostgroupX")"""
        return self.send(payload=self.make_payload(action='add', obj='HG', values=values))

    def set_hostgroup(self, values):
        """Set hostgroup(s) for the host. ("values": "hostname;hostgroup1|hostgroupX")
        overwrite the previous configuration"""
        return self.send(payload=self.make_payload(action='sethostgroup', values=values))

    def del_hostgroup(self, values):
        """Del hostgroup(s) for the host. ("values": "hostname;hostgroup1|hostgroupX")"""
        return self.send(payload=self.make_payload(action='delhostgroup', values=values))

    def enable_host(self, values):
        """Enable host. ("values": "hostname")"""
        return self.send(payload=self.make_payload(action='enable', values=values))

    def disable_host(self, values):
        """Disable host. ("values": "hostname")"""
        return self.send(payload=self.make_payload(action='disable', values=values))

    def make_payload(self, action='', obj='host', values=''):
        payload = '{ "action":"%s", "object":"%s", "values":' % (action, obj)
        payload += chr(34) + values.lower() + chr(34) + ' }'
        return payload

def set_ssh_env():
    ssh_connection = os.environ.get('SSH_CONNECTION')
    

def main():

    # TODO: check presence
    module = AnsibleModule(
        argument_spec = dict(
            user=dict(default=None),
            password=dict(default=None),
            url=dict(default=None),
            action=dict(default=None, choices=['get_list_hosts', 'add_host', 'del_host', 'set_hostgroup', 'add_hostgroup', 'create_hostgroup', 'set_parameters']),
            values=dict(default=None),
        ),
        supports_check_mode=False,
    )

    if not HAS_REQUEST:
        module.fail_json(msg="requests is required")

    module.debug(msg='{}'.format(sys.version_info.major))
    user = module.params['user']
    password = module.params['password']
    url = module.params['url']
    action = module.params['action']
    values =  module.params['values']

    credentials = {
        'user': user,
        'password': password,
    }

    centreon_api = CentreonAPI(url, **credentials)
    if action == 'get_list_hosts':
        result = getattr(centreon_api, action)()
    else:
        result = getattr(centreon_api, action)(values)    
   
    if '401' in str(result) or '404' in str(result) or '500' in str(result):
        module.fail_json( msg='{}'.format(result))

    if '200' in str(result) or '[]' in str(result):
        module.exit_json(changed=True, msg='{}'.format(result))
    else:
        module.exit_json(changed=False, msg='{}'.format(result))

if __name__ == '__main__':
    main()
