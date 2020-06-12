#!/usr/bin/env python3

import os
import ldap3
from pyzabbix import ZabbixAPI
from configparser import RawConfigParser
from ldap3.core.exceptions import LDAPSocketOpenError


class Person:

    def __init__(self, name, surname, mobile, email):
        self.name = name
        self.surname = surname
        self.mobile = mobile
        self.email = email

    def __str__(self):
        return f'Person is:\nSurname: {self.surname}\nName: {self.name}\nMobile: {self.mobile}\nEmail: {self.email}'

    def __repr__(self):
        return self.surname


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


def ldap_connect(ldap_server, bind_user, bind_password):
    """
    Establishing connection with LDAP server.

    :param ldap_server:
    str() LDAP server name or IP address.
    :param bind_user:
    str() Username (sAMAccountName) using to connect with NTLM.
    :param bind_password:
    str() User password.
    :return:
    ldap3.Connection object.
    """

    srv = ldap3.Server(ldap_server, get_info='ALL', mode='IP_V4_PREFERRED', use_ssl=LDAP_SSL)
    try:
        conn = ldap3.Connection(srv, auto_bind=True, authentication=ldap3.NTLM, user=bind_user, password=bind_password)
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

    base_dn = conn.server.info.other['DefaultNamingContext'][0]
    conn.search(search_base=base_dn, search_filter=searchfilter, attributes=attrs)
    return conn.entries


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
    conn.search(conn.server.info.other['DefaultNamingContext'], filter_str)
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
        if user[attr[0]] is None:
            empty_attrs.append(attr)

    if len(empty_attrs) == 0:
        return True, empty_attrs
    else:
        return False, empty_attrs


def prepare_to_create(user, gid, zu_type, zm_types):
    """
    Prepare dict from ldap3 to JSON document for Zabbix API.

    :param user:
    Dict with user's attributes from 'entry_attributes_as_dict' ldap3 method
    :param gid:
    User group ID
    :param zu_type:
    Usertype - Zabbix User, Zabbix Admin, Zabbix Super Admin
    :param zm_types:
    Dict with mediatype ID and type
    :return:
    Dict for Zabbix API.
    """

    # Result dict with params for "user.create" method
    create_result = {}

    # Adding static user parameters
    for user_prop, attr in ZBX_USER_ATTR_MAP.items():
        create_result[user_prop] = user[attr]
    create_result["usrgrps"] = [{"usrgrpid": gid}]
    create_result["type"] = zu_type

    # Forming user medias list
    user_medias = []
    for zm, attr in ZBX_USER_MEDIA_MAP.items():
        if user[attr[0]] is not None:
            # TODO: Rewrite zm_sendto
            zm_sendto = [user[attr[0]]] if zm_types[zm]['type'] == '0' else user[attr[0]]
            media = {"mediatypeid": zm_types[zm]['mtid'], "sendto": zm_sendto, "severity": ZBX_USER_MEDIA_MAP[zm][1]}
            user_medias.append(media)
    create_result["user_medias"] = user_medias

    return create_result


def prepare_to_update(user, zuser, zm_types):
    """
    Prepare JSON object to update existing users in Zabbix.

    :param user:
    Dict with AD user
    :param zuser:
    Dict with Zabbix user
    :param zm_types:
    Dict with Zabbix medias
    :return:
    Dict for Zabbix API user.update method.
    """

    # Result dict with params for "user.update" method
    update_result = {}

    # Check common Zabbix user attributes
    for zm, ad_attr in ZBX_USER_ATTR_MAP.items():
        if zuser[zm] != user[ad_attr]:
            update_result[zm] = user[ad_attr]

    # List of Zabbix medias to update
    update_medias = []
    # TODO: DRY! Look at prepare_to_create function
    # If all Zabbix user medias are empty - fill it with AD values
    if len(zuser['medias']) == 0:
        for zm, attr in ZBX_USER_MEDIA_MAP.items():
            if user[attr[0]] is not None:
                zm_mtid = zm_types[zm]['mtid']
                # TODO: Rewrite zm_sendto
                zm_sendto = [user[attr]] if zm_types[zm]['type'] == '0' else user[attr]
                zm_severity = ZBX_USER_MEDIA_MAP[zm][1]
                media = {"mediatypeid": zm_mtid, "sendto": zm_sendto, "severity": zm_severity}
                update_medias.append(media)
        update_result["user_medias"] = update_medias
    elif len(zuser['medias']) != 0:
        # Current Zabbix User media list
        zbx_user_media_list = [{"mediatypeid": media['mediatypeid'],
                                "sendto": media['sendto'], "severity": media['severity']} for media in zuser['medias']]
        # AD user media list
        ldap_user_media_list = []
        for zm, attr in ZBX_USER_MEDIA_MAP.items():
            # Do not compare with empty AD attribute
            if user[attr[0]] is not None:
                # TODO: Key error for nonpresent media
                zm_mtid = zm_types[zm]['mtid']
                # TODO: Rewrite zm_sendto
                zm_sendto = [user[attr[0]]] if zm_types[zm]['type'] == '0' else user[attr[0]]
                zm_severity = ZBX_USER_MEDIA_MAP[zm][1]
                ldap_user_media_list.append({"mediatypeid": zm_mtid, "sendto": zm_sendto, "severity": zm_severity})
        # Sorting AD and ZBX media lists to simple compare it
        sorted_ldap_user_media_list = sorted(ldap_user_media_list, key=lambda k: k['mediatypeid'])
        sorted_zbx_user_media_list = sorted(zbx_user_media_list, key=lambda k: k['mediatypeid'])
        if sorted_ldap_user_media_list != sorted_zbx_user_media_list:
            for ldap_media in ldap_user_media_list:
                ldap_media_id, ldap_media_sendto, ldap_media_severity = ldap_media.values()
                for zbx_media in zbx_user_media_list:
                    if ldap_media_id in [zm['mediatypeid'] for zm in zbx_user_media_list]:
                        zbx_media_id, zbx_media_sendto, zbx_media_severity = zbx_media.values()
                        if zbx_media_id == ldap_media_id:
                            if ldap_media_sendto == zbx_media_sendto and ldap_media_severity == zbx_media_severity:
                                update_medias.append(zbx_media)
                            else:
                                update_medias.append(ldap_media)
                    else:
                        update_medias.append(ldap_media)
        # Append list with medias to result dict
        if len(update_medias) != 0:
            update_result['user_medias'] = update_medias
    # Add user id to result dict
    if len(update_result) != 0:
        update_result['userid'] = zuser['userid']
    return update_result


if __name__ == '__main__':
    # Read and parse config file
    config = read_config()

    # Check that config file defines all mandatory sections
    for section in ['main', 'ldap', 'zabbix']:
        if not config.has_section(section):
            raise SystemExit('CRITICAL: Config file missing "{}" section'.format(section))

    # Default parameters
    DEF_LDAP_USER_FILTER = "(ObjectClass=Person)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
    DEF_LDAP_USER_ID_ATTR = "sAMAccountName"
    DEF_LDAP_USER_ATTRS = "{}, sn, givenName, mobile, mail".format(DEF_LDAP_USER_ID_ATTR)
    DEF_MAIN_DISABLE_MISSING = False
    DEF_MAIN_CREATE_WITH_EMPTY_MEDIA = False
    DEF_ZBX_USER_ATTR_MAP = {"alias": DEF_LDAP_USER_ID_ATTR, "name": "givenName", "surname": "sn"}
    DEF_ZBX_USER_MEDIA_MAP = {"Email": "mail", "SMS": "mobile"}

    # main section
    MAIN_DISABLE_MISSING = config.getboolean('main', 'disable_missing', fallback=DEF_MAIN_DISABLE_MISSING)
    MAIN_CREATE_WITH_EMPTY_MEDIA = config.getboolean('main', 'create_with_empty_media',
                                                     fallback=DEF_MAIN_CREATE_WITH_EMPTY_MEDIA)
    # ldap section
    LDAP_SRV = config.get('ldap', 'ldap_server')
    LDAP_USER = config.get('ldap', 'ldap_user')
    LDAP_PASS = config.get('ldap', 'ldap_pass')
    LDAP_SSL = config.getboolean('ldap', 'use_ssl', fallback=False)
    LDAP_GROUPS = eval(config.get('ldap', 'group_names_map'))
    LDAP_ATTRS = [attr for attr in config.get('ldap', 'ldap_user_attrs',
                                              fallback=DEF_LDAP_USER_ATTRS).replace(" ", "").split(",")]
    LDAP_USER_FILTER = config.get('ldap', 'ldap_user_filter', fallback=DEF_LDAP_USER_FILTER)
    LDAP_USER_ID_ATTR = config.get('ldap', 'ldap_user_id_attr', fallback=DEF_LDAP_USER_ID_ATTR)

    # zabbix section
    ZBX_API_URL = config.get('zabbix', 'zbx_api_url')
    ZBX_USER = config.get('zabbix', 'zbx_user')
    ZBX_PASS = config.get('zabbix', 'zbx_pass')
    ZBX_GROUP = config.get('zabbix', 'zbx_group_name')
    ZBX_USER_MEDIA_MAP = eval(config.get('zabbix', 'zbx_user_media_map', fallback=DEF_ZBX_USER_MEDIA_MAP))
    ZBX_USER_ATTR_MAP = eval(config.get('zabbix', 'zbx_user_attr_map', fallback=DEF_ZBX_USER_ATTR_MAP))

    # Establish connection with AD server
    ldap_conn = ldap_connect(LDAP_SRV, LDAP_USER, LDAP_PASS)

    # Create a dict with users separated by AD groups
    ad_users_by_group = {}
    for group in LDAP_GROUPS.keys():
        group_dn = get_dn(ldap_conn, 'Group', group)
        if len(group_dn) > 1:
            raise SystemExit(f'ERROR: Found more than one groups for name {group}')
        search_filter = f'(&{LDAP_USER_FILTER}(memberOf={group_dn[0]}))'
        ad_users = get_users(ldap_conn, search_filter, LDAP_ATTRS)
        if len(ad_users) == 0:
            raise SystemExit(f'ERROR: LDAP query returned 0 users')
        # ad_users_by_group[group] = [user.entry_attributes_as_dict for user in ad_users]
        ad_users_list = []
        for ad_user in ad_users:
            ad_users_list.append({attr: ad_user[attr].value for attr in LDAP_ATTRS})
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
    users_params = {"usrgrpids": [zbx_group_id], "selectMedias": "extend", "output": list(ZBX_USER_ATTR_MAP.keys())}
    zbx_users = zapi.do_request(method="user.get", params=users_params)['result']
    # Create a list just of Zabbix user logins
    zbx_users_logins = [zbx_user['alias'] for zbx_user in zbx_users]

    # Get list of Zabbix media types set in configuration file
    # Possible mediatypes:
    # 0 - email;
    # 1 - script;
    # 2 - SMS;
    # 4 - Webhook.
    media_params = {"filter": {"name": list(ZBX_USER_MEDIA_MAP.keys())},
                    "output": ["mediatypeid", "name", "type"]}
    zbx_target_medias = zapi.do_request(method="mediatype.get", params=media_params)['result']
    zbx_attr_media_map = {zm['name']: {"mtid": zm['mediatypeid'], "type": zm['type']} for zm in zbx_target_medias}

    # Prepare list to store data for ZabbixAPI methods
    users_to_create = []
    users_to_update = []
    for ldap_group, ldap_users in ad_users_by_group.items():
        for ldap_user in ldap_users:
            ldap_user_login = ldap_user[LDAP_USER_ID_ATTR]
            if ldap_user_login not in zbx_users_logins:
                # Check given users attributes for null values
                check_result = check_aduser_media(ldap_user)
                # Create new user if: check return True as 1st element or create_with_empty_media set to True in config
                if MAIN_CREATE_WITH_EMPTY_MEDIA or check_result[0]:
                    create_params = prepare_to_create(ldap_user, zbx_group_id, LDAP_GROUPS[ldap_group],
                                                      zbx_attr_media_map)
                    users_to_create.append(create_params)
                else:
                    print(f'INFO: User {ldap_user_login} has empty attributes: {check_result[1]}. Skipping.')
            # Update existing user in Zabbix
            else:
                for zbx_user in zbx_users:
                    if zbx_user['alias'] == ldap_user_login:
                        update_params = prepare_to_update(ldap_user, zbx_user, zbx_attr_media_map)
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

    # Logout from Zabbix and LDAP
    zapi.user.logout()
    ldap_conn.unbind()
