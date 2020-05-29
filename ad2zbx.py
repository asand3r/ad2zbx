#!/usr/bin/env python3

import re
import ldap3
from pyzabbix import ZabbixAPI
from ldap3.core.exceptions import LDAPSocketOpenError


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

    srv = ldap3.Server(ldap_server, get_info='ALL', mode='IP_V4_PREFERRED', use_ssl=LDAP_SSL)
    try:
        conn = ldap3.Connection(srv, auto_bind=True, authentication='NTLM', user=ldap_user, password=ldap_password)
    except LDAPSocketOpenError as e:
        raise SystemExit('ERROR: {}'.format(e.__str__()))
    return conn


def get_users(conn, searchfilter, attrs):
    """
    Function search users in LDAP catalog using search filter in config file.
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

# AD params
AD_SRV = "172.16.1.100"
AD_USER = "AGC\\asand3r"
AD_PASS = "P@ssw0rd"
LDAP_SSL = False

# Zabbix params
ZBX_API_URL = "http://127.0.0.1:81"
ZBX_USER = "Admin"
ZBX_PASS = "zabbix"

group = "CN=CORE-GU-SKM-ZBX-SADMINS,OU=AGC Groups,DC=agc,DC=local"
attrs = ['sn', 'givenName', 'mobile', 'sAMAccountName', 'mail']
search_filter = "(&(ObjectClass=Person)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(memberOf={}))".format(group)
conn = ldap_connect(AD_SRV, AD_USER, AD_PASS)
ad_users = get_users(conn, search_filter, attrs)

zapi = ZabbixAPI(ZBX_API_URL)
zapi.login(ZBX_USER, ZBX_PASS)

for user in ad_users:
    print(f'Login: {user.sAMAccountName.value}, mail: {user.mail.value}, phone: {user.mobile.value}')
    zapi.user.create(
        alias=user.sAMAccountName.value, name=user.givenName.value, surname=user.sn.value,
        usrgrps=['14'])