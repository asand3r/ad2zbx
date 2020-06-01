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


def check_aduser_media(user):
    """
    Check AD user media attributes to have a not-null value.

    :param user:
    Dict with user's attributes.
    :return:
    Two element list of: Bool, empty_attrs
    """

    empty_attrs = []
    for attr in ZBX_USER_MEDIA_MAP.values():
        if user[attr] is None:
            empty_attrs.append(attr)

    if len(empty_attrs) == 0:
        return True, empty_attrs
    else:
        return False, empty_attrs


def prepare_to_create(user, gid, utype, mtypes):
    """
    Prepare dict from ldap3 to JSON document for Zabbix API.

    :param user:
    Dict with user's attributes from 'entry_attributes_as_dict' ldap3 method
    :param gid:
    User group ID
    :param utype"
    Usertype - Zabbix User, Zabbix Admin, Zabbix Super Admin
    :param mtypes:
    Dict with media type IDs.
    :return:
    Dict for Zabbix API.
    """

    # TODO: Rewrite all this shit. I feel really bad
    # Result dict with params for "user.create" method
    create_result = {}

    # Adding static user parameters
    for user_prop, attr in ZBX_USER_ATTR_MAP.items():
        create_result[user_prop] = user[attr]

    # Adding user group id
    create_result["usrgrps"] = [{"usrgrpid": gid}]
    # Adding user type
    create_result["type"] = utype

    # Prepare media types
    media_types = {mt['name']: mt['mediatypeid'] for mt in mtypes}

    # Forming user medias list
    user_medias = []
    for zm, attr in ZBX_USER_MEDIA_MAP.items():
        if user[attr] is not None:
            if zm == "Email":
                media = {"mediatypeid": media_types[zm], "sendto": [user[attr]], "severity": "60"}
            else:
                media = {"mediatypeid": media_types[zm], "sendto": user[attr], "severity": "54"}
            user_medias.append(media)
    create_result["user_medias"] = user_medias

    return create_result


def prepare_to_update(user, zuser):
    """
    Prepare JSON object to update existing users in Zabbix.

    :param user:
    JSON with AD user
    :param zuser:
    JSON with Zabbix user
    :return:
    Dict for Zabbix API.
    """

    # Result dict with params for "user.update" method
    update_result = {}

    # Check common Zabbix user attributes
    for zbx_attr, ad_attr in ZBX_USER_ATTR_MAP.items():
        if zuser[zbx_attr] != user[ad_attr]:
            print(f'{zbx_attr} attributes are differ: Zabbix {zuser[zbx_attr]}, AD: {user[ad_attr]}')
            update_result['userid'] = zuser['userid']
            update_result[zbx_attr] = user[ad_attr]

    # Check media Zabbix user attributes
    # Prepare media types

    return update_result


if __name__ == '__main__':
    # Read and parse config file
    config = read_config()

    # Check that config file defines all mandatory sections
    for section in ['ldap', 'zabbix']:
        if not config.has_section(section):
            raise SystemExit('CRITICAL: Config file missing "{}" section'.format(section))

    # Default parameters
    DEF_ZBX_USER_ATTR_MAP = {"alias": "sAMAccountName", "name": "givenName", "surname": "sn"}
    DEF_ZBX_USER_MEDIA_MAP = {"Email": "mail", "SMS": "mobile"}
    DEF_LDAP_USER_FILTER = "(ObjectClass=Person)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
    DEF_LDAP_USER_ATTRS = "sAMAccountName, sn, givenName, mobile, mail"
    DEF_MAIN_DISABLE_MISSING = False
    DEF_MAIN_CREATE_WITH_EMPTY_MEDIA = False

    # main section
    MAIN_DISABLE_MISSING = config.getboolean('main', 'disable_missing', fallback=DEF_MAIN_DISABLE_MISSING)
    MAIN_CREATE_WITH_EMPTY_MEDIA = config.getboolean('main', 'create_with_empty_media',
                                                     fallback=DEF_MAIN_CREATE_WITH_EMPTY_MEDIA)
    # ldap section
    AD_SRV = config.get('ldap', 'ad_server')
    AD_USER = config.get('ldap', 'bind_user')
    AD_PASS = config.get('ldap', 'bind_pass')
    AD_SSL = config.getboolean('ldap', 'use_ssl', fallback=False)
    AD_GROUPS = eval(config.get('ldap', 'group_names_map'))
    AD_ATTRS = [attr for attr in config.get('ldap', 'ldap_user_attrs',
                                            fallback=DEF_LDAP_USER_ATTRS).replace(" ", "").split(",")]
    AD_USER_FILTER = config.get('ldap', 'ldap_user_filter', fallback=DEF_LDAP_USER_FILTER)

    # zabbix section
    ZBX_API_URL = config.get('zabbix', 'zbx_api_url')
    ZBX_USER = config.get('zabbix', 'zbx_user')
    ZBX_PASS = config.get('zabbix', 'zbx_pass')
    ZBX_GROUP = config.get('zabbix', 'zbx_group_name')
    ZBX_USER_MEDIA_MAP = eval(config.get('zabbix', 'zbx_user_media_map', fallback=DEF_ZBX_USER_MEDIA_MAP))
    ZBX_USER_ATTR_MAP = eval(config.get('zabbix', 'zbx_user_attr_map', fallback=DEF_ZBX_USER_ATTR_MAP))

    # Establish connection with AD server
    ldap_conn = ldap_connect(AD_SRV, AD_USER, AD_PASS)

    # Create a dict with users separated by AD groups
    ad_users_by_group = {}
    for group in AD_GROUPS.keys():
        group_dn = get_dn(ldap_conn, 'Group', group)
        if len(group_dn) > 1:
            raise SystemExit(f'ERROR: Found more than one groups for name {group}')
        search_filter = f'(&{AD_USER_FILTER}(memberOf={group_dn[0]}))'
        ad_users = get_users(ldap_conn, search_filter, AD_ATTRS)
        # ad_users_by_group[group] = [user.entry_attributes_as_dict for user in ad_users]
        ad_users_list = []
        for ad_user in ad_users:
            ad_users_list.append({attr: ad_user[attr].value for attr in AD_ATTRS})
            ad_users_by_group[group] = ad_users_list

    # Connect to Zabbix API
    zapi = ZabbixAPI(ZBX_API_URL)
    zapi.login(ZBX_USER, ZBX_PASS)

    # Get target group ID and check it
    zbx_group = zapi.do_request(method="usergroup.get", params={"filter": {"name": ZBX_GROUP}})['result']
    if len(zbx_group) != 0:
        if zbx_group[0]['gui_access'] == '0':
            print(f'WARNING: Target Zabbix group "{ZBX_GROUP}" isn\'t set to use LDAP authentication method.'
                  f' It\'s OK if default method is.')
        elif zbx_group[0]['gui_access'] in ('1', '3'):
            print(f'WARNING: Target group is using internal authentication method or set to disable gui access.')
        zbx_group_id = zbx_group[0]['usrgrpid']
    else:
        raise SystemExit(f'ERROR: Cannot find group "{ZBX_GROUP}" in Zabbix.')

    # Get users of target Zabbix group
    zbx_users = zapi.do_request(method="user.get", params={"usrgrpids": [zbx_group_id],
                                                           "selectMedias": "extend"})['result']
    # Create a list just of Zabbix user logins
    zbx_users_logins = [zbx_user['alias'] for zbx_user in zbx_users]

    # Get list of Zabbix media types present in configuration file
    media_params = {"filter": {"name": [media for media in ZBX_USER_MEDIA_MAP.keys()]},
                    "output": ["mediatypeid", "name"]}
    zbx_target_medias = zapi.do_request(method="mediatype.get", params=media_params)['result']

    # Prepare data for Zabbix
    users_to_create = []
    users_to_update = []
    for group, ad_users in ad_users_by_group.items():
        for ad_user in ad_users:
            ad_user_login = ad_user['sAMAccountName']
            # Create new user if it doesn't exist
            if ad_user_login not in zbx_users_logins:
                # Check given users attributes for null values
                check_result = check_aduser_media(ad_user)
                # Create new user if: check return True as 1st element or create_with_empty_media set to True in config
                if MAIN_CREATE_WITH_EMPTY_MEDIA or check_result[0]:
                    create_params = prepare_to_create(ad_user, zbx_group_id, AD_GROUPS[group], zbx_target_medias)
                    users_to_create.append(create_params)
                else:
                    print(f'INFO: User {ad_user_login} has empty attributes: {check_result[1]}. Skipping.')
            # Update existing user in Zabbix
            else:
                for zbx_user in zbx_users:
                    if zbx_user['alias'] == ad_user_login:
                        update_params = prepare_to_update(ad_user, zbx_user)
                        if len(update_params) != 0:
                            users_to_update.append(update_params)

    # Create users in Zabbix
    if len(users_to_create) != 0:
        print(f'DEBUG: create list of users: {users_to_create}')
        zapi.do_request(method="user.create", params=users_to_create)
    else:
        print(f'DEBUG: list of users to create is empty. Nothing to do')
    # Update users in Zabbix
    if len(users_to_update) != 0:
        print(f'DEBUG: update list of users: {users_to_update}')
        zapi.do_request(method="user.update", params=users_to_update)
    else:
        print(f'DEBUG: list of users to update is empty. Nothing to do')
    # Logout from Zabbix
    # zapi.user.logout()
    # ldap_conn.unbind()
