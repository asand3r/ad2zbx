DEF_LDAP_USER_FILTER = '(ObjectClass=Person)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))'
DEF_LDAP_USER_ID_ATTR = 'sAMAccountName'
DEF_LDAP_USER_ATTRS = 'sn, givenName, mobile, mail'
DEF_LDAP_MERGE_PRIVILEGES = 'lower'
DEF_LDAP_USE_NESTED_GROUPS = False
DEF_ZBX_USER_ATTR_MAP = {"alias": DEF_LDAP_USER_ID_ATTR, "name": "givenName", "surname": "sn"}
DEF_ZBX_USER_MEDIA_MAP = '{"Email": ["mail", 60], "SMS": ["mobile", 48]}'
DEF_ZBX_API_VERIFY_SSL = False
