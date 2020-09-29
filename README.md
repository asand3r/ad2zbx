# ad2zbx
Script to import users from Microsoft Active Directory groups to Zabbix Monitoring system.

## Current version
0.1alpha3

## Dependencies
- pyzabbix
- ldap3

## Features
- Create new users from given list of Active Directory groups
- Update existing users from Active Directory
- LDAP attributes preprocessing
  - replace
  - remove_spaces
  - to_lower
  - to_upper
  - add_suffix
  - add_prefix
