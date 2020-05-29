#!/usr/bin/env python3

import os
import ldap3
from pyzabbix import ZabbixAPI
from configparser import RawConfigParser
from ldap3.core.exceptions import LDAPSocketOpenError


def read_config(path='ad2zbx.conf'):
    """
    Read ad2zbx.conf config file.

    :param path:
    Path to the config file.
    :return:
    configparser.RawConfigParser object.
    """

    cfg = RawConfigParser()
    if os.path.exists(path):
        cfg.read(path)
        return cfg
    else:
        # Creating 'startup_error.log' if config file cannot be open
        with open('startup_error.log', 'w') as err_file:
            err_file.write('ERROR: Cannot find "ad2zbx.conf" in current directory.')
            raise SystemExit('Missing config file (csv2ldap.conf) in current directory')


def ldap_connect(ldap_server, ldap_user, ldap_password):
    """
    Establishing connection with LDAP server.

    :param ldap_server:
    str() LDAP server name or IP address.
    :param ldap_user:
    str() Username (sAMAccountName) using to connect with NTLM.
    :param ldap_password:
    str() User password.
    :return:
    ldap3.Connection object.
    """

    srv = ldap3.Server(ldap_server, get_info='ALL', mode='IP_V4_PREFERRED', use_ssl=AD_SSL)
    try:
        conn = ldap3.Connection(srv, auto_bind=True, authentication=ldap3.NTLM, user=ldap_user, password=ldap_password)
    except LDAPSocketOpenError as e:
        raise SystemExit('ERROR: {}'.format(e.__str__()))
    return conn


def get_users(conn, searchfilter, attrs):
    """
    Search users in catalog using searchfilter and return it with given attributes.

    :param conn:
    ldap3.Connection object.
    :param searchfilter:
    LDAP search filter from config file.
    :param attrs:
    List of attributes to get from catalog.
    :return:
    dict with all found objects.
    """

    base_dn = conn.server.info.other['rootDomainNamingContext'][0]
    conn.search(search_base=base_dn, search_filter=searchfilter, attributes=attrs)
    ldap_users = conn.entries
    return ldap_users


def get_dn(conn, object_class, property_value, property_name='sAMAccountName'):
    """
    Get DN of given object name.

    :param conn:
    ldap3.Connection object.
    :param object_class:
    Class of searchable objec (user, group, person etc)
    :param property_name:
    Name of searchable object. sAMAccountName in general.
    :param property_value:
    Value of given property name.
    :return:
    List
    """

    filter_str = f'(&(objectClass={object_class})({property_name}={property_value}))'

    # Search in LDAP with our filter
    conn.search(conn.server.info.other['rootDomainNamingContext'], filter_str)
    dn_list = [entry.entry_dn for entry in conn.entries]
    return dn_list


def check_aduser(user):
    """
    Check AD user properties
    :param user:
    Dict with user properties
    :return:
    List of True or False and list of empty attributes
    """

    empty_attrs = []
    for attr in AD_ATTRS:
        if len(user[attr]) == 0:
            empty_attrs.append(attr)

    if len(empty_attrs) == 0:
        return True, empty_attrs
    else:
        return False, empty_attrs


def prepare_aduser(user):
    """

    :param user:
    :return:
    """

    # "alias": "asand3r", "usrgrps": [{"usrgrpid": zbx_group_id}], "type": "3",
    # "name": "Alexander", "surname": "Khatsayuk",
    # "user_medias": [{"mediatypeid": "1", "sendto": ["asand3r@gexample.com"], "severity": "60"}]}

    nuser = {}
    for attr, value in user.items():
        nuser[attr] = user[attr][0]

    return print(nuser)


if __name__ == '__main__':
    # Read and parse config file
    config = read_config()

    # Check that config file defines all mandatory sections
    for section in ['ldap', 'zabbix']:
        if not config.has_section(section):
            raise SystemExit('CRITICAL: Config file missing "{}" section'.format(section))

    # ldap section
    AD_SRV = config.get('ldap', 'ad_server')
    AD_USER = config.get('ldap', 'bind_user')
    AD_PASS = config.get('ldap', 'bind_pass')
    AD_SSL = config.getboolean('ldap', 'use_ssl', fallback=False)
    # AD_GROUPS = [group for group in config.get('ldap', 'group_names').replace(" ", "").split(",")]
    AD_GROUPS = eval(config.get('ldap', 'group_names'))
    AD_ATTRS = [attr for attr in config.get('ldap', 'ldap_attrs').replace(" ", "").split(",")]
    AD_USER_FILTER = config.get('ldap', 'ldap_user_filter')

    # zabbix section
    ZBX_API_URL = config.get('zabbix', 'zabbix_api_url')
    ZBX_USER = config.get('zabbix', 'zabbix_user')
    ZBX_PASS = config.get('zabbix', 'zabbix_pass')
    ZBX_GROUP = config.get('zabbix', 'zabbix_group_name')
    ZBX_MEDIA_MAP = eval(config.get('zabbix', 'zabbix_media_map'))

    # Establish connection with AD server
    ldap_conn = ldap_connect(AD_SRV, AD_USER, AD_PASS)

    ad_users_by_group = {}
    for group in AD_GROUPS.keys():
        group_dn = get_dn(ldap_conn, 'Group', group)
        if len(group_dn) > 1:
            raise SystemExit(f'ERROR: Found more than one groups for name {group}')
        # Find users of group
        search_filter = f'(&{AD_USER_FILTER}(memberOf={group_dn[0]}))'
        ad_users = get_users(ldap_conn, search_filter, AD_ATTRS)
        ad_users_by_group[group] = [user.entry_attributes_as_dict for user in ad_users]

    # Connect to Zabbix API
    zapi = ZabbixAPI(ZBX_API_URL)
    zapi.login(ZBX_USER, ZBX_PASS)

    # Get target group ID
    zbx_group = zapi.do_request(method="usergroup.get", params={"filter": {"name": ZBX_GROUP}})
    if len(zbx_group['result']) != 1:
        raise SystemExit(f'ERROR: Found more that 1 group with name {ZBX_GROUP} in Zabbix. That\'s weird')
    zbx_group_id = zbx_group['result'][0]['usrgrpid']

    # Get users list of target group
    zbx_users = zapi.do_request(method="user.get", params={"usrgrpids": [zbx_group_id]})
    # Get target mediatypes
    media_params = {"filter": {"name": [media for media in ZBX_MEDIA_MAP.keys()]}, "output": ["mediatypeid", "name"]}
    zbx_media = zapi.do_request(method="mediatype.get", params=media_params)
    # Create users for each group
    for group, users in ad_users_by_group.items():
        for user in users:
            check_res = check_aduser(user)
            if check_res[0]:
                alias = user['sAMAccountName'][0]
                usertype = AD_GROUPS[group]
                name = user['givenName'][0]
                surname = user['sn'][0]
                mail = user['mail'][0]
                create_params = {"alias": alias, "usrgrps": [{"usrgrpid": zbx_group_id}], "type": usertype,
                                 "name": name, "surname": surname,
                                 "user_medias": [{"mediatypeid": "1", "sendto": [mail], "severity": "60"}]}
                zapi.do_request(method="user.create", params=create_params)
            else:
                print(f'SKIPPING: User {user["sAMAccountName"][0]} has empty attributes: {check_res[1]}')
            # create_params = {
            #     "alias": "asand3r", "usrgrps": [{"usrgrpid": zbx_group_id}], "type": "3",
            #     "name": "Alexander", "surname": "Khatsayuk",
            #     "user_medias": [{"mediatypeid": "1", "sendto": ["asand3r@gexample.com"], "severity": "60"}]}
    # Logout from Zabbix
    # zapi.user.logout()
