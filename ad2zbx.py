#!/usr/bin/env python3

import os
import ldap3
import logging
from argparse import ArgumentParser
from configparser import RawConfigParser, NoOptionError

from pyzabbix import ZabbixAPI
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPBindError


class Person:
    def __init__(self, login, sn, name, privileges=1, media=None):
        self.login = login
        self.sn = sn
        self.name = name
        self.privileges = privileges
        self.media = media

    def __repr__(self):
        return self.login

    def __str__(self):
        zabbix_roles = {1: 'Zabbix User', 2: 'Zabbix Admin', 3: 'Zabbix Super Admin'}
        person = f"Login: {self.login}\nSurname: {self.sn}\nName: {self.name}\n" \
                 f"Privileges: {zabbix_roles[self.privileges]} ({self.privileges})"
        return person

    def __eq__(self, other):
        return True if self.__hash__() == other.__hash__() else False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.login, self.sn, self.name, tuple((m for m in self.media))))


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
        logger.critical(f'{e.__str__()}')
        raise SystemExit(f'ERROR: {e.__str__()}')
    except ConnectionError as e:
        logger.critical(f'{e.__str__()}')
        raise SystemExit(f'ERROR: {e.__str__()}')
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

    :param conn: ldap3.Connection object.
    :param object_class: Class of searchable object (user, group, person etc)
    :param property_name: Name of searchable object. sAMAccountName in general.
    :param property_value: Value of given property name.
    :return: List of DNs
    """

    ldap_filter = f'(&(objectClass={object_class})({property_name}={property_value}))'

    # Search in LDAP with our filter
    conn.search(conn.server.info.other['DefaultNamingContext'], ldap_filter)
    dn_list = [entry.entry_dn for entry in conn.entries]
    return dn_list


def check_aduser_media(user):
    """
    Check AD user media attributes to have a not-null value.

    :param user: Dict with user's attributes.
    :return: Two element list of: Bool, empty_attrs
    """

    empty_attrs = []
    for attr in ZBX_USER_MEDIA_MAP.values():
        if user[attr[0]] is None:
            empty_attrs.append(attr)

    if len(empty_attrs) == 0:
        return True, empty_attrs
    else:
        return False, empty_attrs


def prepare_to_create(user, gid, zm_types):
    """
    Prepare dict from ldap3 to JSON document for Zabbix API.

    :param user: Dict with user's attributes from 'entry_attributes_as_dict' ldap3 method
    :param gid: User group ID
    :param zm_types: Dict with mediatype ID and type
    :return: Dict for Zabbix API user.create method
    """

    # Result dict with params for "user.create" method
    result = {}

    # Adding static user parameters
    for user_prop, attr in ZBX_USER_ATTR_MAP.items():
        result[user_prop] = user[attr]
    result["usrgrps"] = [{"usrgrpid": gid}]

    # Forming user medias list
    user_medias = []
    for zm, attr in ZBX_USER_MEDIA_MAP.items():
        ldap_attr_name = attr[0]
        ldap_attr_value = user[ldap_attr_name]
        if ldap_attr_value is not None:
            # TODO: Rewrite zm_sendto
            zm_sendto = [ldap_attr_value] if zm_types[zm]['type'] == '0' else ldap_attr_value
            media = {"mediatypeid": zm_types[zm]['mtid'], "sendto": zm_sendto, "severity": ZBX_USER_MEDIA_MAP[zm][1]}
            user_medias.append(media)
    result["user_medias"] = user_medias

    return result


def prepare_to_update(user, zuser, zm_types):
    """
    Prepare JSON object to update existing users in Zabbix.

    :param user: Dict with AD user
    :param zuser: Dict with Zabbix user
    :param zm_types: Dict with Zabbix medias
    :return: Dict for Zabbix API user.update method.
    """

    # Result dict with params for "user.update" method
    result = {}

    # Check common Zabbix user attributes
    for zm, ad_attr in ZBX_USER_ATTR_MAP.items():
        if zuser[zm] != user[ad_attr]:
            result[zm] = user[ad_attr]

    # Check target user type
    if zuser['type'] != str(user['type']):
        result['type'] = str(user['type'])

    # List of Zabbix medias to update
    update_medias = []
    # TODO: DRY! Look at prepare_to_create function
    # If all Zabbix user medias are empty - fill it with AD values
    if len(zuser['medias']) == 0:
        for zm, attr in ZBX_USER_MEDIA_MAP.items():
            if user[attr[0]] is not None:
                zm_mtid = zm_types[zm]['mtid']
                # TODO: Rewrite zm_sendto
                zm_sendto = [user[attr[0]]] if zm_types[zm]['type'] == '0' else user[attr[0]]
                zm_severity = ZBX_USER_MEDIA_MAP[zm][1]
                media = {"mediatypeid": zm_mtid, "sendto": zm_sendto, "severity": zm_severity}
                update_medias.append(media)
        result["user_medias"] = update_medias
    elif len(zuser['medias']) != 0:
        # Current Zabbix User media list
        zbx_user_media_list = [{"mediatypeid": media['mediatypeid'],
                                "sendto": media['sendto'], "severity": media['severity']} for media in zuser['medias']]
        # AD user media list
        ldap_user_media_list = []
        for zm, attr in ZBX_USER_MEDIA_MAP.items():
            # Do not compare with empty AD attribute
            if user[attr[0]] is not None:
                # TODO: Key error for non-present media
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
            result['user_medias'] = update_medias
    # Add user id to result dict
    if len(result) != 0:
        result['userid'] = zuser['userid']
    return result


def prep_exec(user, value, steps):
    """
    Preprocessing for values received from LDAP catalog.

    :param user: LDAP user login
    :param value: Value from LDAP.
    :param steps: Dict object as a string.
    :return: Formatted string
    """

    logger.debug(f'Running preprocessing for "{user}", value "{value}" and steps "{steps}"')
    # Check value is as string
    if not isinstance(value, str):
        logger.error(f'Preprocessing: User {user}, value {value} must be a string, but it\'s a {type(value)}')
        raise TypeError(f'ERROR: value must be a string, but it\'s a {type(value)}')
    for func, step_args in steps.items():
        logger.debug(f'In value: "{value}", func: {func}, args: "{step_args}"')
        if func == 'replace':
            if len(step_args) == 2:
                value = value.replace(step_args[0], step_args[1])
            else:
                logger.error(f'Preprocessing: User {user}, replace step must contains two arguments'
                             f'but {len(step_args)} given')
                raise ValueError(f'ERROR: {user}, replace step must contains two arguments but {len(step_args)} given')
        elif func == 'remove_spaces':
            value = value.replace(" ", "")
        elif func == 'add_suffix':
            value = value + step_args
        elif func == 'add_prefix':
            value = step_args + value
        elif func == 'to_lower':
            value = value.lower()
        elif func == 'to_upper':
            value = value.upper()
        else:
            logger.critical(f'Preprocessing: function {func} is unknown. Check config file.')
            raise ValueError(f'ERROR: function {func} is unknown')
        logger.debug(f'Out value: "{value}"')
    return value


def get_config_parameter(env_var, conf_section, conf_option):
    """
    Read environment variable or config parameter as fallback.
    :param env_var: environment variable name
    :param conf_section: fallback config section name
    :param conf_option: fallback config option name
    :return: parameter value
    """

    param_value = os.environ.get(env_var)
    if param_value is None:
        logger.debug(f'Env variable {env_var} is not set. Using config file to get {conf_option}')
        try:
            param_value = config.get(conf_section, conf_option)
        except NoOptionError:
            logger.critical(f'Cannot set {conf_option} parameter neither from config file nor env variable. '
                            f'Please set {conf_option} config parameter or {env_var} env variable')
            raise SystemExit()
    return param_value


if __name__ == '__main__':

    VERSION = '0.1alpha3'

    # Parsing CLI arguments
    main_parser = ArgumentParser(description='Script to import users from LDAP to Zabbix', add_help=True)
    main_parser.add_argument('-d', '--dry-run', action='store_true', help='Do not make any changes')
    main_parser.add_argument('-c', '--config', type=str, default='./ad2zbx.conf', help='Path to configuration file')
    main_parser.add_argument('-v', '--version', action='version', version=VERSION)
    main_parser.add_argument('-l', '--console-log-level', type=str, default='INFO', help='Console log level')
    args = main_parser.parse_args()

    # Set console logger
    logger = logging.getLogger('ad2zbx')
    logger.setLevel(args.console_log_level)
    console_formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')
    console_handler = logging.StreamHandler()
    console_handler.setLevel(args.console_log_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Read and parse config file
    logger.debug(f'Read config file')
    config = RawConfigParser()
    try:
        with open(args.config) as cfg:
            config.read_file(cfg)
    except FileNotFoundError:
        raise SystemExit(f'Cannot read config file "{args.config}"')

    # logging
    LOG_FILE = config.get('logging', 'log_file', fallback='/tmp/ad2zbx.log')
    LOG_LEVEL = config.get('logging', 'log_level', fallback='WARNING')

    # Set file logger setting
    logger.debug(f'Creating file logger. Writes messages to {LOG_FILE} starting with {LOG_LEVEL} level')
    logger.setLevel(LOG_LEVEL)
    file_formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Set const from CLI params
    DRY_RUN = True if args.dry_run else False
    if DRY_RUN:
        logger.debug(f'Running in test mode. No data will change.')
    # Check all mandatory config file sections and options
    mandatory_options = {'ldap': ('ldap_server', 'ldap_user', 'group_names_map'),
                         'zabbix': ('zbx_api_url', 'zbx_user', 'zbx_group_name')}
    for section, options in mandatory_options.items():
        if not config.has_section(section):
            raise SystemExit(f'CRITICAL: Config file miss "{section}" section')
        for option in options:
            if not config.has_option(section, option):
                raise SystemExit(f'CRITICAL: Config file miss "{option}" option in "ldap" section')

    # Default parameters
    DEF_LDAP_USER_FILTER = '(ObjectClass=Person)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))'
    DEF_LDAP_USER_ID_ATTR = 'sAMAccountName'
    DEF_LDAP_USER_ATTRS = 'sn, givenName, mobile, mail'
    DEF_LDAP_MERGE_PRIVILEGES = 'lower'
    DEF_LDAP_USE_NESTED_GROUPS = False
    DEF_MAIN_DISABLE_MISSING = False
    DEF_MAIN_CREATE_WITH_EMPTY_MEDIA = False
    DEF_ZBX_USER_ATTR_MAP = {"alias": DEF_LDAP_USER_ID_ATTR, "name": "givenName", "surname": "sn"}
    DEF_ZBX_USER_MEDIA_MAP = {"Email": ["mail", 60], "SMS": ["mobile", 48]}
    DEF_ZBX_API_VERIFY_SSL = False

    # main section
    MAIN_DISABLE_MISSING = config.getboolean('main', 'disable_missing', fallback=DEF_MAIN_DISABLE_MISSING)
    MAIN_CREATE_WITH_EMPTY_MEDIA = config.getboolean('main', 'create_with_empty_media',
                                                     fallback=DEF_MAIN_CREATE_WITH_EMPTY_MEDIA)
    # ldap section
    LDAP_SRV = config.get('ldap', 'ldap_server')
    LDAP_USER = config.get('ldap', 'ldap_user')
    LDAP_PASS = get_config_parameter('AD2ZBX_LDAP_PASS', 'ldap', 'ldap_pass')
    LDAP_SSL = config.getboolean('ldap', 'use_ssl', fallback=False)
    LDAP_GROUPS = eval(config.get('ldap', 'group_names_map'))
    LDAP_MERGE_PRIVILEGES = config.get('ldap', 'merge_privileges', fallback=DEF_LDAP_MERGE_PRIVILEGES)
    LDAP_USER_FILTER = config.get('ldap', 'ldap_user_filter', fallback=DEF_LDAP_USER_FILTER)
    LDAP_USER_ID_ATTR = config.get('ldap', 'ldap_user_id_attr', fallback=DEF_LDAP_USER_ID_ATTR)
    LDAP_USER_ATTRS = [attr.strip() for attr in config.get('ldap', 'ldap_user_attrs',
                                                           fallback=DEF_LDAP_USER_ATTRS).split(",")]
    LDAP_USER_ATTRS.append(LDAP_USER_ID_ATTR)
    LDAP_USE_NESTED_GROUPS = config.getboolean('ldap', 'use_nested_groups', fallback=DEF_LDAP_USE_NESTED_GROUPS)

    # zabbix section
    ZBX_API_URL = config.get('zabbix', 'zbx_api_url')
    ZBX_API_VERIFY_SSL = config.get('zabbix', 'verify_ssl', fallback=DEF_ZBX_API_VERIFY_SSL)
    ZBX_USER = config.get('zabbix', 'zbx_user')
    ZBX_PASS = get_config_parameter('AD2ZBX_ZBX_PASS', 'zabbix', 'zbx_pass')
    ZBX_TARGET_GROUP = config.get('zabbix', 'zbx_group_name')
    ZBX_USER_MEDIA_MAP = eval(config.get('zabbix', 'zbx_user_media_map', fallback=DEF_ZBX_USER_MEDIA_MAP))
    ZBX_USER_ATTR_MAP = eval(config.get('zabbix', 'zbx_user_attr_map', fallback=DEF_ZBX_USER_ATTR_MAP))

    # preprocessing section
    PREP_STEPS = {}
    if config.has_section('preprocessing') and config.items('preprocessing'):
        for attr, prep_steps in config.items('preprocessing'):
            try:
                prep_steps = eval(prep_steps)
            except SyntaxError:
                logger.critical(f'Cannot parse {prep_steps[1]} as dict for step {prep_steps}')
                raise SyntaxError(f'ERROR: Cannot parse {prep_steps[1]} as dict for step {prep_steps}')
            PREP_STEPS[attr] = prep_steps

    # Establish connection with AD server
    logger.debug(f'Connecting to LDAP: {LDAP_SRV} with user {LDAP_USER}')
    try:
        ldap_conn = ldap_connect(LDAP_SRV, LDAP_USER, LDAP_PASS)
        logger.debug(f'Connected to {ldap_conn.server.host}:{ldap_conn.server.port}')
    except LDAPBindError:
        logger.critical(f'Cannot bind to LDAP server {LDAP_SRV} with given user and password')
        raise SystemExit()

    ldap_users_result_list = []
    temp_processed_ldap_users = []
    merge_reverse = True if LDAP_MERGE_PRIVILEGES == 'higher' else False
    # Sort LDAP groups by privileges level
    ldap_groups = {k: v for k, v in sorted(LDAP_GROUPS.items(), key=lambda x: x[1], reverse=merge_reverse)}
    for group in ldap_groups.keys():
        group_dn = get_dn(ldap_conn, 'Group', group)
        use_nested = ':1.2.840.113556.1.4.1941:' if LDAP_USE_NESTED_GROUPS else ''
        search_filter = f'(&{LDAP_USER_FILTER}(memberOf{use_nested}={group_dn[0]}))'
        ldap_users = get_users(ldap_conn, search_filter, LDAP_USER_ATTRS)
        for ldap_user in ldap_users:
            # Dict to store user's attr: value pares
            ad_user_dict = {'type': LDAP_GROUPS[group]}
            for attr in LDAP_USER_ATTRS:
                raw_attr_value = ldap_user[attr].value
                # Preprocessing
                if attr in PREP_STEPS.keys() and raw_attr_value is not None:
                    ad_user_dict[attr] = prep_exec(ldap_user['sAMAccountName'], raw_attr_value, PREP_STEPS[attr])
                else:
                    ad_user_dict[attr] = raw_attr_value
            if ldap_user['sAMAccountName'] not in temp_processed_ldap_users:
                ldap_users_result_list.append(ad_user_dict)
            temp_processed_ldap_users.append(ldap_user['sAMAccountName'])
    logger.debug(f'Received {len(ldap_users_result_list)} users from LDAP')
    # Connect to Zabbix API
    zapi = ZabbixAPI(ZBX_API_URL)
    zapi.session.verify = ZBX_API_VERIFY_SSL
    zapi.login(ZBX_USER, ZBX_PASS)
    logger.debug(f'Connected to Zabbix API {zapi.api_version()}')

    # Get target group ID and check it
    zbx_group = zapi.do_request(method="usergroup.get", params={"filter": {"name": ZBX_TARGET_GROUP}})['result']
    logger.debug(f'Received group from Zabbix API {zbx_group}')
    if len(zbx_group) != 0:
        if zbx_group[0]['gui_access'] == '0':
            logger.warning(f'Target Zabbix group "{ZBX_TARGET_GROUP}" isn\'t set to use LDAP authentication method.'
                           f' It\'s OK if default method is.')
        elif zbx_group[0]['gui_access'] in ('1', '3'):
            logger.warning(f'Target group is using internal authentication method or set to disable gui access.')
        zbx_group_id = zbx_group[0]['usrgrpid']
    else:
        logger.critical(f'Cannot find group "{ZBX_TARGET_GROUP}" in Zabbix.')
        raise SystemExit(f'ERROR: Cannot find group "{ZBX_TARGET_GROUP}" in Zabbix.')

    # Get all Zabbix users with Zabbix API
    user_get_params = {"selectMedias": "extend", "output": list(ZBX_USER_ATTR_MAP.keys()) + ['type']}
    zbx_users = {zu['alias']: zu for zu in zapi.do_request(method="user.get", params=user_get_params)['result']}
    zbx_users_logins = [zbx_user for zbx_user in zbx_users.keys()]
    logger.debug(f'Received {len(zbx_users_logins)} users from Zabbix')

    # Get list of Zabbix media types (mt) set in configuration file
    # Possible mediatypes: 0 - email; 1 - script; 2 - SMS; 4 - Webhook.
    mt_get_params = {"filter": {"name": list(ZBX_USER_MEDIA_MAP.keys())}, "output": ["mediatypeid", "name", "type"]}
    zbx_target_medias = zapi.do_request(method="mediatype.get", params=mt_get_params)['result']
    zbx_attr_media_map = {zm['name']: {"mtid": zm['mediatypeid'], "type": zm['type']} for zm in zbx_target_medias}
    logger.debug(f'Received mediatypes: {zbx_target_medias}')
    logger.debug(f'Form mediatype to LDAP attr map: {zbx_attr_media_map}')

    # Prepare list to store data for ZabbixAPI methods
    logger.debug(f'Start to process LDAP users list')
    users_create_params = []
    users_update_params = []
    for ldap_user in ldap_users_result_list:
        ldap_user_login = ldap_user[LDAP_USER_ID_ATTR]
        logger.debug(f'Checking user {ldap_user_login}')
        if ldap_user_login not in zbx_users_logins:
            logger.debug(f'User {ldap_user_login} not found in Zabbix and must be created.')
            # Check given users attributes for null values
            check_result = check_aduser_media(ldap_user)
            # Create new user if: check return True as 1st element or create_with_empty_media set to True in config
            if MAIN_CREATE_WITH_EMPTY_MEDIA or check_result[0]:
                logger.info(f'User must be created {ldap_user}')
                create_params = prepare_to_create(ldap_user, zbx_group_id, zbx_attr_media_map)
                users_create_params.append(create_params)
            else:
                logger.info(f'User {ldap_user_login} has empty attributes: {check_result[1]}. Skipping.')
        # Update existing user in Zabbix
        else:
            logger.debug(f'User {ldap_user_login} found in Zabbix. Checking the need for an update')
            zbx_user = zbx_users[ldap_user_login]
            update_params = prepare_to_update(ldap_user, zbx_user, zbx_attr_media_map)
            if len(update_params) != 0:
                logger.debug(f'User {ldap_user_login} must be updated in Zabbix with params: {update_params}')
                users_update_params.append(update_params)
            else:
                logger.debug(f'User {ldap_user_login} is up to date')

    # Create users in Zabbix
    logger.info(f'Number of users to create: {len(users_create_params)}')
    logger.debug(f'List of users to create: {users_create_params}')
    if not DRY_RUN:
        zapi.do_request(method='user.create', params=users_create_params)

    # Update users in Zabbix
    logger.info(f'Number of users to update: {len(users_update_params)}')
    logger.debug(f'List of users to update: {users_update_params}')
    if not DRY_RUN:
        zapi.do_request(method='user.update', params=users_update_params)

    # Logout from Zabbix and LDAP
    logger.debug(f'Logout from Zabbix API')
    zapi.user.logout()
    logger.debug(f'Unbind LDAP connection')
    ldap_conn.unbind()
