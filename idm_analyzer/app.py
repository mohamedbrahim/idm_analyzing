#!/usr/bin/env python3
"""
IDM Permission Analyzer - Interactive Web Application
Analyze user permissions, trace permission sources, and compare users.

Requirements:
    pip install flask python-freeipa requests

Usage:
    python app.py --server ipa.example.com --login admin
    python app.py --server ipa.example.com --kerberos
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from enum import Enum
from functools import lru_cache
from typing import Optional, List, Dict, Set, Any
import warnings

from flask import Flask, render_template, jsonify, request

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

try:
    from python_freeipa import ClientMeta
    from python_freeipa.exceptions import NotFound, Unauthorized
except ImportError:
    print("ERROR: python-freeipa not installed. Run: pip install python-freeipa")
    sys.exit(1)


app = Flask(__name__)

# Global IDM client (initialized at startup)
idm_client = None


class NodeType(str, Enum):
    USER = "user"
    GROUP = "group"
    HBAC_RULE = "hbac"
    SUDO_RULE = "sudo"
    HOST = "host"
    HOSTGROUP = "hostgroup"
    SUDO_CMD = "sudocmd"
    SUDO_CMDGROUP = "sudocmdgroup"


@dataclass
class PermissionPath:
    """Represents a path from user to a specific permission."""
    target: str
    target_type: str
    path: List[Dict[str, str]]
    rule_name: str
    rule_type: str
    hosts: List[str]
    commands: List[str]
    description: str


class IDMClient:
    """Enhanced IDM client with caching and permission tracing."""

    def __init__(self, server: str, username: str = None, password: str = None,
                 use_kerberos: bool = False, verify_ssl: bool = False, debug: bool = False):
        self.server = server
        self.verify_ssl = verify_ssl
        self.debug = debug
        self._client = None
        self._cache = {}
        self._connect(username, password, use_kerberos)
    
    def _debug(self, msg):
        """Print debug message if debug mode is enabled."""
        if self.debug:
            print(f"[DEBUG] {msg}")

    def _connect(self, username: str, password: str, use_kerberos: bool):
        """Establish connection to FreeIPA server."""
        try:
            self._client = ClientMeta(self.server, verify_ssl=self.verify_ssl)
            if use_kerberos:
                self._client.login_kerberos()
                print(f"[+] Connected to {self.server} using Kerberos")
            else:
                if not username or not password:
                    raise ValueError("Username and password required")
                self._client.login(username, password)
                print(f"[+] Connected to {self.server} as {username}")
        except Exception as e:
            print(f"[!] Connection error: {e}")
            raise

    def _cache_get(self, key: str):
        return self._cache.get(key)

    def _cache_set(self, key: str, value: Any):
        self._cache[key] = value
        return value

    # ==================== User Methods ====================

    def get_all_users(self) -> List[Dict]:
        """Get list of all users."""
        cache_key = "all_users"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            self._debug("Fetching all users from IDM...")
            result = self._client.user_find(all=True, sizelimit=0)
            self._debug(f"Raw API response keys: {result.keys() if result else 'None'}")
            self._debug(f"Number of results: {len(result.get('result', []))}")
            
            # Debug: print first user structure
            if result.get('result') and len(result['result']) > 0:
                first_user = result['result'][0]
                self._debug(f"First user keys: {first_user.keys()}")
                self._debug(f"First user sample: uid={first_user.get('uid')}, cn={first_user.get('cn')}")
            
            users = []
            for user in result.get('result', []):
                # Handle both list and string formats for uid
                uid = user.get('uid', [''])[0] if isinstance(user.get('uid'), list) else user.get('uid', '')
                cn = user.get('cn', [''])[0] if isinstance(user.get('cn'), list) else user.get('cn', '')
                mail_field = user.get('mail')
                mail = mail_field[0] if isinstance(mail_field, list) and mail_field else (mail_field if mail_field else '')
                
                users.append({
                    'uid': uid,
                    'cn': cn,
                    'mail': mail,
                    'memberof_group': user.get('memberof_group', []),
                })
            
            self._debug(f"Processed {len(users)} users")
            if users:
                self._debug(f"Sample users: {[u['uid'] for u in users[:5]]}")
            
            return self._cache_set(cache_key, users)
        except Exception as e:
            print(f"Error fetching users: {e}")
            import traceback
            traceback.print_exc()
            return []

    def get_user(self, username: str) -> Optional[Dict]:
        """Get detailed user information."""
        cache_key = f"user:{username}"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            self._debug(f"Fetching user: {username}")
            result = self._client.user_show(username, all=True)
            self._debug(f"user_show result type: {type(result)}")
            self._debug(f"user_show result keys: {result.keys() if isinstance(result, dict) else 'not a dict'}")
            
            # Unwrap the result - API returns {'result': {...}, 'value': ..., 'summary': ...}
            if isinstance(result, dict) and 'result' in result:
                user_data = result['result']
                self._debug(f"Unwrapped user data keys: {user_data.keys()}")
                return self._cache_set(cache_key, user_data)
            
            return self._cache_set(cache_key, result)
        except NotFound:
            self._debug(f"User not found: {username}")
            return None
        except Exception as e:
            print(f"Error fetching user {username}: {e}")
            import traceback
            traceback.print_exc()
            return None

    # ==================== Group Methods ====================

    def get_group(self, groupname: str) -> Optional[Dict]:
        """Get detailed group information."""
        cache_key = f"group:{groupname}"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.group_show(groupname, all=True)
            # Unwrap the result - API returns {'result': {...}, 'value': ..., 'summary': ...}
            if isinstance(result, dict) and 'result' in result:
                group_data = result['result']
                return self._cache_set(cache_key, group_data)
            return self._cache_set(cache_key, result)
        except NotFound:
            return None
        except Exception as e:
            print(f"Error fetching group {groupname}: {e}")
            return None

    def get_all_groups(self) -> List[Dict]:
        """Get all groups."""
        cache_key = "all_groups"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.group_find(all=True, sizelimit=0)
            groups = []
            for group in result.get('result', []):
                groups.append({
                    'cn': group.get('cn', [''])[0],
                    'description': group.get('description', [''])[0] if group.get('description') else '',
                    'member_user': group.get('member_user', []),
                    'member_group': group.get('member_group', []),
                    'memberof_group': group.get('memberof_group', []),
                })
            return self._cache_set(cache_key, groups)
        except Exception as e:
            print(f"Error fetching groups: {e}")
            return []

    def get_nested_group_membership(self, groupname: str, visited: Set[str] = None) -> List[Dict]:
        """Get all groups this group is a member of (recursively)."""
        if visited is None:
            visited = set()

        if groupname in visited:
            return []

        visited.add(groupname)
        memberships = []

        group_info = self.get_group(groupname)
        if not group_info:
            return memberships

        parent_groups = group_info.get('memberof_group', [])
        for parent in parent_groups:
            memberships.append({
                'child': groupname,
                'parent': parent,
            })
            memberships.extend(self.get_nested_group_membership(parent, visited))

        return memberships

    # ==================== HBAC Rules ====================

    def get_all_hbac_rules(self) -> List[Dict]:
        """Get all HBAC rules."""
        cache_key = "all_hbac_rules"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.hbacrule_find(all=True, sizelimit=0)
            return self._cache_set(cache_key, result.get('result', []))
        except Exception as e:
            print(f"Error fetching HBAC rules: {e}")
            return []

    def get_hbac_rule(self, rule_name: str) -> Optional[Dict]:
        """Get detailed HBAC rule information."""
        cache_key = f"hbac_rule:{rule_name}"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.hbacrule_show(rule_name, all=True)
            # Unwrap the result
            if isinstance(result, dict) and 'result' in result:
                return self._cache_set(cache_key, result['result'])
            return self._cache_set(cache_key, result)
        except NotFound:
            return None

    # ==================== Sudo Rules ====================

    def get_all_sudo_rules(self) -> List[Dict]:
        """Get all sudo rules."""
        cache_key = "all_sudo_rules"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.sudorule_find(all=True, sizelimit=0)
            return self._cache_set(cache_key, result.get('result', []))
        except Exception as e:
            print(f"Error fetching sudo rules: {e}")
            return []

    def get_sudo_rule(self, rule_name: str) -> Optional[Dict]:
        """Get detailed sudo rule information."""
        cache_key = f"sudo_rule:{rule_name}"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.sudorule_show(rule_name, all=True)
            # Unwrap the result
            if isinstance(result, dict) and 'result' in result:
                return self._cache_set(cache_key, result['result'])
            return self._cache_set(cache_key, result)
        except NotFound:
            return None

    # ==================== Hosts ====================

    def get_all_hosts(self) -> List[Dict]:
        """Get all hosts."""
        cache_key = "all_hosts"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.host_find(all=True, sizelimit=0)
            hosts = []
            for host in result.get('result', []):
                hosts.append({
                    'fqdn': host.get('fqdn', [''])[0],
                    'description': host.get('description', [''])[0] if host.get('description') else '',
                    'memberof_hostgroup': host.get('memberof_hostgroup', []),
                })
            return self._cache_set(cache_key, hosts)
        except Exception as e:
            print(f"Error fetching hosts: {e}")
            return []

    def get_hostgroup(self, hostgroup_name: str) -> Optional[Dict]:
        """Get hostgroup details."""
        cache_key = f"hostgroup:{hostgroup_name}"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.hostgroup_show(hostgroup_name, all=True)
            # Unwrap the result
            if isinstance(result, dict) and 'result' in result:
                return self._cache_set(cache_key, result['result'])
            return self._cache_set(cache_key, result)
        except NotFound:
            return None

    # ==================== Permission Analysis ====================

    def get_user_all_groups(self, username: str) -> Set[str]:
        """Get all groups a user belongs to (direct and nested)."""
        user = self.get_user(username)
        if not user:
            return set()

        all_groups = set()
        
        # Direct groups
        direct_groups = user.get('memberof_group', [])
        for group in direct_groups:
            all_groups.add(group)
        
        # Indirect groups (nested) - IDM provides this directly!
        indirect_groups = user.get('memberofindirect_group', [])
        for group in indirect_groups:
            all_groups.add(group)
        
        # Also traverse manually for group hierarchy building
        for group in direct_groups:
            nested = self.get_nested_group_membership(group)
            for n in nested:
                all_groups.add(n['parent'])

        return all_groups

        return all_groups

    def analyze_user_permissions(self, username: str, filter_rules_only: bool = False) -> Dict:
        """Complete permission analysis for a user.
        
        Args:
            username: The user to analyze
            filter_rules_only: If True, only include groups that lead to HBAC/Sudo rules
        """
        user = self.get_user(username)
        if not user:
            return {'error': f'User {username} not found'}

        # Helper to safely extract first element
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default

        # Get groups from user object directly
        direct_groups = user.get('memberof_group', [])
        indirect_groups = user.get('memberofindirect_group', [])
        all_groups = set(direct_groups) | set(indirect_groups)

        self._debug(f"User {username}: direct_groups={len(direct_groups)}, indirect_groups={len(indirect_groups)}")

        # Get HBAC rules directly from user object
        direct_hbac = user.get('memberof_hbacrule', [])
        indirect_hbac = user.get('memberofindirect_hbacrule', [])
        all_hbac_names = set(direct_hbac) | set(indirect_hbac)
        
        self._debug(f"HBAC rules: direct={direct_hbac}, indirect={indirect_hbac}")
        self._debug(f"All HBAC names to process: {all_hbac_names}")
        
        # Get Sudo rules directly from user object
        direct_sudo = user.get('memberof_sudorule', [])
        indirect_sudo = user.get('memberofindirect_sudorule', [])
        all_sudo_names = set(direct_sudo) | set(indirect_sudo)

        self._debug(f"Sudo rules: direct={direct_sudo}, indirect={indirect_sudo}")
        self._debug(f"All Sudo names to process: {all_sudo_names}")

        # Build group hierarchy
        group_hierarchy = []
        for group in direct_groups:
            nested = self.get_nested_group_membership(group)
            group_hierarchy.extend(nested)

        # Get detailed info for HBAC rules
        hbac_rules = []
        for rule_name in all_hbac_names:
            self._debug(f"Processing HBAC rule: {rule_name}")
            rule_detail = self._get_rule_details(rule_name, 'hbac', username, 
                                                  rule_name in direct_hbac, all_groups)
            if rule_detail:
                hbac_rules.append(rule_detail)
                self._debug(f"  Added HBAC rule: {rule_name}")
            else:
                self._debug(f"  HBAC rule returned None: {rule_name}")

        # Get detailed info for Sudo rules
        sudo_rules = []
        for rule_name in all_sudo_names:
            self._debug(f"Processing Sudo rule: {rule_name}")
            rule_detail = self._get_rule_details(rule_name, 'sudo', username,
                                                  rule_name in direct_sudo, all_groups)
            if rule_detail:
                sudo_rules.append(rule_detail)
                self._debug(f"  Added Sudo rule: {rule_name}")
            else:
                self._debug(f"  Sudo rule returned None: {rule_name}")

        self._debug(f"Final counts: hbac_rules={len(hbac_rules)}, sudo_rules={len(sudo_rules)}")

        # Find groups that have rules (for filtering)
        groups_with_rules = self._find_groups_with_rules(all_groups, hbac_rules, sudo_rules)
        
        # If filtering, only include relevant groups
        if filter_rules_only:
            filtered_direct = [g for g in direct_groups if g in groups_with_rules]
            filtered_indirect = [g for g in indirect_groups if g in groups_with_rules]
        else:
            filtered_direct = direct_groups
            filtered_indirect = indirect_groups

        return {
            'user': {
                'uid': safe_first(user.get('uid')),
                'cn': safe_first(user.get('cn')),
                'mail': safe_first(user.get('mail')),
            },
            'direct_groups': list(filtered_direct),
            'indirect_groups': list(filtered_indirect),
            'all_groups': list(all_groups),
            'all_groups_count': len(all_groups),
            'group_hierarchy': group_hierarchy,
            'groups_with_rules': list(groups_with_rules),
            'hbac_rules': hbac_rules,
            'sudo_rules': sudo_rules,
            'direct_hbac_rules': direct_hbac,
            'indirect_hbac_rules': indirect_hbac,
            'direct_sudo_rules': direct_sudo,
            'indirect_sudo_rules': indirect_sudo,
        }

    def _get_rule_details(self, rule_name: str, rule_type: str, username: str, 
                          is_direct: bool, user_groups: Set[str]) -> Optional[Dict]:
        """Get detailed information about an HBAC or Sudo rule."""
        
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default
        
        self._debug(f"Getting details for {rule_type} rule: {rule_name}")
        
        try:
            if rule_type == 'hbac':
                rule = self.get_hbac_rule(rule_name)
            else:
                rule = self.get_sudo_rule(rule_name)
            
            self._debug(f"  Rule data: {rule is not None}")
            
            if not rule:
                # Rule might exist but we can't fetch details - return basic info
                self._debug(f"  Could not fetch rule details, returning basic info")
                return {
                    'name': rule_name,
                    'type': rule_type,
                    'match_type': 'direct' if is_direct else 'via_group',
                    'via_groups': [],
                    'hosts': [],
                    'hostgroups': [],
                    'host_category': '',
                    'description': 'Rule details not available',
                }
            
            # Find which groups give access to this rule
            rule_groups = rule.get('memberuser_group', [])
            via_groups = list(set(rule_groups) & user_groups)
            
            self._debug(f"  Rule groups: {rule_groups}")
            self._debug(f"  Matching user groups: {via_groups}")
            
            # Determine match type
            rule_users = rule.get('memberuser_user', [])
            user_category = safe_first(rule.get('usercategory'))
            
            if user_category == 'all':
                match_type = 'all_users'
            elif username in rule_users:
                match_type = 'direct'
            elif via_groups:
                match_type = 'via_group'
            elif is_direct:
                match_type = 'direct'
            else:
                match_type = 'via_group'
            
            result = {
                'name': rule_name,
                'type': rule_type,
                'match_type': match_type,
                'via_groups': via_groups,
                'hosts': rule.get('memberhost_host', []),
                'hostgroups': rule.get('memberhost_hostgroup', []),
                'host_category': safe_first(rule.get('hostcategory')),
                'description': safe_first(rule.get('description')),
            }
            
            if rule_type == 'hbac':
                result['services'] = rule.get('memberservice_hbacsvc', [])
                result['service_groups'] = rule.get('memberservice_hbacsvcgroup', [])
                result['service_category'] = safe_first(rule.get('servicecategory'))
            else:
                result['commands'] = {
                    'allow': rule.get('memberallowcmd_sudocmd', []),
                    'allow_groups': rule.get('memberallowcmd_sudocmdgroup', []),
                    'deny': rule.get('memberdenycmd_sudocmd', []),
                    'deny_groups': rule.get('memberdenycmd_sudocmdgroup', []),
                    'cmd_category': safe_first(rule.get('cmdcategory')),
                }
                result['runas'] = {
                    'users': rule.get('ipasudorunas_user', []),
                    'groups': rule.get('ipasudorunas_group', []),
                    'user_category': safe_first(rule.get('ipasudorunasusercategory')),
                    'group_category': safe_first(rule.get('ipasudorunasgroupcategory')),
                    'extuser': safe_first(rule.get('ipasudorunasextuser')),
                }
                result['options'] = rule.get('ipasudoopt', [])
            
            self._debug(f"  Returning rule detail: {result['name']}, match: {result['match_type']}")
            return result
            
        except Exception as e:
            print(f"Error getting rule details for {rule_name}: {e}")
            import traceback
            traceback.print_exc()
            return {
                'name': rule_name,
                'type': rule_type,
                'match_type': 'direct' if is_direct else 'via_group',
                'via_groups': [],
                'hosts': [],
                'hostgroups': [],
                'host_category': '',
                'description': f'Error: {str(e)}',
            }

    def _find_groups_with_rules(self, all_groups: Set[str], hbac_rules: List[Dict], 
                                 sudo_rules: List[Dict]) -> Set[str]:
        """Find all groups that have HBAC or Sudo rules (directly or indirectly)."""
        groups_with_rules = set()
        
        # Add groups from HBAC rules
        for rule in hbac_rules:
            for group in rule.get('via_groups', []):
                groups_with_rules.add(group)
        
        # Add groups from Sudo rules
        for rule in sudo_rules:
            for group in rule.get('via_groups', []):
                groups_with_rules.add(group)
        
        # Also find parent groups that lead to groups with rules
        expanded = set(groups_with_rules)
        for group in all_groups:
            # Check if this group is an ancestor of any group with rules
            nested = self.get_nested_group_membership(group)
            for n in nested:
                if n['parent'] in groups_with_rules or n['child'] in groups_with_rules:
                    expanded.add(group)
                    expanded.add(n['parent'])
                    expanded.add(n['child'])
        
        return expanded

    def _analyze_hbac_for_user(self, username: str, user_groups: Set[str], 
                                 direct_hbac: List[str] = None, indirect_hbac: List[str] = None) -> List[Dict]:
        """Analyze which HBAC rules apply to a user and how."""
        rules = []
        all_hbac = self.get_all_hbac_rules()
        
        # Combine direct and indirect rules we know apply to this user
        known_rules = set(direct_hbac or []) | set(indirect_hbac or [])
        direct_rules_set = set(direct_hbac or [])

        # Helper to safely get first element
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default

        for rule in all_hbac:
            rule_name = safe_first(rule.get('cn'))
            enabled = safe_first(rule.get('ipaenabledflag'))

            if enabled != 'TRUE':
                continue
            
            # Check if this rule applies to the user
            is_known_rule = rule_name in known_rules
            match_info = self._check_rule_user_match(rule, username, user_groups, 'memberuser')
            
            if is_known_rule or match_info['matches']:
                # Determine match type
                if rule_name in direct_rules_set:
                    match_type = 'direct'
                    via_groups = []
                elif rule_name in known_rules:
                    match_type = 'via_group'
                    via_groups = match_info.get('via_groups', [])
                else:
                    match_type = match_info.get('match_type', 'unknown')
                    via_groups = match_info.get('via_groups', [])
                
                # Get hosts this rule applies to
                hosts = self._get_rule_hosts(rule, 'memberhost')

                rules.append({
                    'name': rule_name,
                    'type': 'hbac',
                    'match_type': match_type,
                    'via_groups': via_groups,
                    'path': match_info.get('path', []),
                    'hosts': hosts['hosts'],
                    'hostgroups': hosts['hostgroups'],
                    'host_category': safe_first(rule.get('hostcategory')),
                    'services': rule.get('memberservice_hbacsvc', []),
                    'service_groups': rule.get('memberservice_hbacsvcgroup', []),
                    'service_category': safe_first(rule.get('servicecategory')),
                    'description': safe_first(rule.get('description')),
                })

        return rules

    def _analyze_sudo_for_user(self, username: str, user_groups: Set[str],
                                 direct_sudo: List[str] = None, indirect_sudo: List[str] = None) -> List[Dict]:
        """Analyze which sudo rules apply to a user and how."""
        rules = []
        all_sudo = self.get_all_sudo_rules()
        
        # Combine direct and indirect rules we know apply to this user
        known_rules = set(direct_sudo or []) | set(indirect_sudo or [])
        direct_rules_set = set(direct_sudo or [])

        # Helper to safely get first element
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default

        for rule in all_sudo:
            rule_name = safe_first(rule.get('cn'))
            enabled = safe_first(rule.get('ipaenabledflag'))

            if enabled != 'TRUE':
                continue

            # Check if this rule applies to the user
            is_known_rule = rule_name in known_rules
            match_info = self._check_rule_user_match(rule, username, user_groups, 'memberuser')

            if is_known_rule or match_info['matches']:
                # Determine match type
                if rule_name in direct_rules_set:
                    match_type = 'direct'
                    via_groups = []
                elif rule_name in known_rules:
                    match_type = 'via_group'
                    via_groups = match_info.get('via_groups', [])
                else:
                    match_type = match_info.get('match_type', 'unknown')
                    via_groups = match_info.get('via_groups', [])
                
                # Get hosts this rule applies to
                hosts = self._get_rule_hosts(rule, 'memberhost')

                # Get commands
                commands = {
                    'allow': rule.get('memberallowcmd_sudocmd', []),
                    'allow_groups': rule.get('memberallowcmd_sudocmdgroup', []),
                    'deny': rule.get('memberdenycmd_sudocmd', []),
                    'deny_groups': rule.get('memberdenycmd_sudocmdgroup', []),
                    'cmd_category': safe_first(rule.get('cmdcategory')),
                }

                # Get runas users
                runas = {
                    'users': rule.get('ipasudorunas_user', []),
                    'groups': rule.get('ipasudorunas_group', []),
                    'user_category': safe_first(rule.get('ipasudorunasusercategory')),
                    'group_category': safe_first(rule.get('ipasudorunasgroupcategory')),
                }

                rules.append({
                    'name': rule_name,
                    'type': 'sudo',
                    'match_type': match_type,
                    'via_groups': via_groups,
                    'path': match_info.get('path', []),
                    'hosts': hosts['hosts'],
                    'hostgroups': hosts['hostgroups'],
                    'host_category': safe_first(rule.get('hostcategory')),
                    'commands': commands,
                    'runas': runas,
                    'options': rule.get('ipasudoopt', []),
                    'description': safe_first(rule.get('description')),
                })

        return rules

    def _check_rule_user_match(self, rule: Dict, username: str, user_groups: Set[str],
                                member_attr: str) -> Dict:
        """Check if a rule matches a user and return the match path."""
        result = {
            'matches': False,
            'match_type': None,
            'via_groups': [],
            'path': [],
        }

        # Check user category (all)
        user_category = rule.get('usercategory', [''])[0]
        if user_category == 'all':
            result['matches'] = True
            result['match_type'] = 'all_users'
            result['path'] = [{'type': 'category', 'name': 'all'}]
            return result

        # Check direct user membership
        rule_users = rule.get(f'{member_attr}_user', [])
        if username in rule_users:
            result['matches'] = True
            result['match_type'] = 'direct'
            result['path'] = [{'type': 'user', 'name': username}]
            return result

        # Check group membership
        rule_groups = set(rule.get(f'{member_attr}_group', []))
        matching_groups = user_groups & rule_groups

        if matching_groups:
            result['matches'] = True
            result['match_type'] = 'via_group'
            result['via_groups'] = list(matching_groups)

            # Build path for first matching group
            for group in matching_groups:
                path = self._build_group_path(username, group)
                if path:
                    result['path'] = path
                    break

            return result

        return result

    def _build_group_path(self, username: str, target_group: str) -> List[Dict]:
        """Build the path from user to a specific group."""
        user = self.get_user(username)
        if not user:
            return []

        direct_groups = user.get('memberof_group', [])

        # If target is a direct group
        if target_group in direct_groups:
            return [
                {'type': 'user', 'name': username},
                {'type': 'group', 'name': target_group},
            ]

        # Search through nested groups
        for direct_group in direct_groups:
            path = self._find_path_to_group(direct_group, target_group, [username])
            if path:
                return [{'type': 'user' if i == 0 else 'group', 'name': name}
                        for i, name in enumerate(path)]

        return []

    def _find_path_to_group(self, current: str, target: str, path: List[str]) -> Optional[List[str]]:
        """Recursively find path from current group to target group."""
        if current == target:
            return path + [current]

        if current in path:  # Avoid cycles
            return None

        group_info = self.get_group(current)
        if not group_info:
            return None

        parent_groups = group_info.get('memberof_group', [])
        for parent in parent_groups:
            result = self._find_path_to_group(parent, target, path + [current])
            if result:
                return result

        return None

    def _get_rule_hosts(self, rule: Dict, member_attr: str) -> Dict:
        """Get hosts and hostgroups from a rule."""
        return {
            'hosts': rule.get(f'{member_attr}_host', []),
            'hostgroups': rule.get(f'{member_attr}_hostgroup', []),
        }

    # ==================== Permission Tracing ====================

    def trace_full_permissions(self, username: str) -> Dict:
        """
        Build a comprehensive permission tree showing ALL paths to HBAC and Sudo rules.
        
        Returns a tree structure:
        - User
          - Direct Groups (with their rules)
            - Parent Groups (nested, with their rules)
          - Direct HBAC Rules
          - Direct Sudo Rules
          - Indirect HBAC Rules (via groups)
          - Indirect Sudo Rules (via groups)
        
        For each rule, also shows:
          - User groups in the rule
          - Host/hostgroups in the rule
        """
        user = self.get_user(username)
        if not user:
            return {'error': f'User {username} not found'}
        
        self._debug(f"Building full permission tree for {username}")
        
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default
        
        # Get all user memberships
        direct_groups = user.get('memberof_group', [])
        indirect_groups = user.get('memberofindirect_group', [])
        direct_hbac = user.get('memberof_hbacrule', [])
        indirect_hbac = user.get('memberofindirect_hbacrule', [])
        direct_sudo = user.get('memberof_sudorule', [])
        indirect_sudo = user.get('memberofindirect_sudorule', [])
        
        # Build group tree with their rules
        group_tree = []
        processed_groups = set()
        
        def get_group_details(group_name, depth=0, parent_path=None):
            """Recursively get group details including rules and parent groups."""
            if group_name in processed_groups or depth > 10:
                return None
            processed_groups.add(group_name)
            
            group_data = self.get_group(group_name)
            if not group_data:
                return {
                    'name': group_name,
                    'type': 'group',
                    'depth': depth,
                    'path': (parent_path or []) + [group_name],
                    'hbac_rules': [],
                    'sudo_rules': [],
                    'parent_groups': [],
                }
            
            # Get rules this group is directly associated with
            group_hbac = group_data.get('memberof_hbacrule', [])
            group_sudo = group_data.get('memberof_sudorule', [])
            group_indirect_hbac = group_data.get('memberofindirect_hbacrule', [])
            group_indirect_sudo = group_data.get('memberofindirect_sudorule', [])
            
            # Get parent groups
            parent_groups = group_data.get('memberof_group', [])
            
            current_path = (parent_path or []) + [group_name]
            
            # Build HBAC rule details for this group
            hbac_rules = []
            for rule_name in set(group_hbac) | set(group_indirect_hbac):
                rule_detail = self._get_rule_summary(rule_name, 'hbac', 
                                                      is_direct=(rule_name in group_hbac))
                if rule_detail:
                    rule_detail['access_path'] = current_path + [rule_name]
                    hbac_rules.append(rule_detail)
            
            # Build Sudo rule details for this group
            sudo_rules = []
            for rule_name in set(group_sudo) | set(group_indirect_sudo):
                rule_detail = self._get_rule_summary(rule_name, 'sudo',
                                                      is_direct=(rule_name in group_sudo))
                if rule_detail:
                    rule_detail['access_path'] = current_path + [rule_name]
                    sudo_rules.append(rule_detail)
            
            # Recursively get parent group details
            parent_details = []
            for parent in parent_groups:
                parent_info = get_group_details(parent, depth + 1, current_path)
                if parent_info:
                    parent_details.append(parent_info)
            
            return {
                'name': group_name,
                'type': 'group',
                'depth': depth,
                'path': current_path,
                'is_direct_member': group_name in direct_groups,
                'hbac_rules': hbac_rules,
                'sudo_rules': sudo_rules,
                'parent_groups': parent_details,
                'description': safe_first(group_data.get('description')),
            }
        
        # Process direct groups
        for group in direct_groups:
            processed_groups.clear()  # Reset for each direct group tree
            group_info = get_group_details(group, depth=0, parent_path=[username])
            if group_info:
                group_tree.append(group_info)
        
        # Build direct rule details (rules user is directly in, not via group)
        direct_hbac_details = []
        for rule_name in direct_hbac:
            rule_detail = self._get_rule_summary(rule_name, 'hbac', is_direct=True)
            if rule_detail:
                rule_detail['access_path'] = [username, rule_name]
                direct_hbac_details.append(rule_detail)
        
        direct_sudo_details = []
        for rule_name in direct_sudo:
            rule_detail = self._get_rule_summary(rule_name, 'sudo', is_direct=True)
            if rule_detail:
                rule_detail['access_path'] = [username, rule_name]
                direct_sudo_details.append(rule_detail)
        
        # Build all unique paths to rules
        all_paths = self._build_all_permission_paths(username, user)
        
        return {
            'user': {
                'uid': safe_first(user.get('uid')),
                'cn': safe_first(user.get('cn')),
            },
            'summary': {
                'total_groups': len(direct_groups) + len(indirect_groups),
                'direct_groups': len(direct_groups),
                'indirect_groups': len(indirect_groups),
                'total_hbac_rules': len(set(direct_hbac) | set(indirect_hbac)),
                'total_sudo_rules': len(set(direct_sudo) | set(indirect_sudo)),
            },
            'direct_hbac_rules': direct_hbac_details,
            'direct_sudo_rules': direct_sudo_details,
            'group_tree': group_tree,
            'all_permission_paths': all_paths,
        }
    
    def _get_rule_summary(self, rule_name: str, rule_type: str, is_direct: bool = False) -> Optional[Dict]:
        """Get a summary of a rule including its members."""
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default
        
        if rule_type == 'hbac':
            rule = self.get_hbac_rule(rule_name)
        else:
            rule = self.get_sudo_rule(rule_name)
        
        if not rule:
            return {
                'name': rule_name,
                'type': rule_type,
                'enabled': None,
                'is_direct': is_direct,
                'user_groups': [],
                'users': [],
                'hosts': [],
                'hostgroups': [],
                'description': 'Details not available',
            }
        
        # Check enabled status
        enabled_raw = rule.get('ipaenabledflag')
        enabled = safe_first(enabled_raw)
        is_enabled = enabled in ['TRUE', 'true', True]
        
        result = {
            'name': rule_name,
            'type': rule_type,
            'enabled': is_enabled,
            'is_direct': is_direct,
            'user_groups': rule.get('memberuser_group', []),
            'users': rule.get('memberuser_user', []),
            'user_category': safe_first(rule.get('usercategory')),
            'hosts': rule.get('memberhost_host', []),
            'hostgroups': rule.get('memberhost_hostgroup', []),
            'host_category': safe_first(rule.get('hostcategory')),
            'description': safe_first(rule.get('description')),
        }
        
        if rule_type == 'hbac':
            result['services'] = rule.get('memberservice_hbacsvc', [])
            result['service_groups'] = rule.get('memberservice_hbacsvcgroup', [])
            result['service_category'] = safe_first(rule.get('servicecategory'))
        else:
            result['commands'] = {
                'allow': rule.get('memberallowcmd_sudocmd', []),
                'allow_groups': rule.get('memberallowcmd_sudocmdgroup', []),
                'cmd_category': safe_first(rule.get('cmdcategory')),
            }
            result['runas'] = {
                'users': rule.get('ipasudorunas_user', []),
                'groups': rule.get('ipasudorunas_group', []),
                'ext_user': safe_first(rule.get('ipasudorunasextuser')),
            }
            result['options'] = rule.get('ipasudoopt', [])
        
        return result
    
    def _build_all_permission_paths(self, username: str, user: Dict) -> List[Dict]:
        """Build all unique paths from user to each rule."""
        paths = []
        
        direct_groups = user.get('memberof_group', [])
        indirect_groups = user.get('memberofindirect_group', [])
        all_groups = set(direct_groups) | set(indirect_groups)
        
        direct_hbac = set(user.get('memberof_hbacrule', []))
        indirect_hbac = set(user.get('memberofindirect_hbacrule', []))
        direct_sudo = set(user.get('memberof_sudorule', []))
        indirect_sudo = set(user.get('memberofindirect_sudorule', []))
        
        all_hbac = direct_hbac | indirect_hbac
        all_sudo = direct_sudo | indirect_sudo
        
        # For each rule, find all paths to it
        for rule_name in all_hbac:
            rule_paths = self._find_paths_to_rule(username, rule_name, 'hbac', 
                                                   direct_groups, all_groups,
                                                   rule_name in direct_hbac)
            paths.extend(rule_paths)
        
        for rule_name in all_sudo:
            rule_paths = self._find_paths_to_rule(username, rule_name, 'sudo',
                                                   direct_groups, all_groups,
                                                   rule_name in direct_sudo)
            paths.extend(rule_paths)
        
        return paths
    
    def _find_paths_to_rule(self, username: str, rule_name: str, rule_type: str,
                            direct_groups: List[str], all_groups: Set[str],
                            is_direct_rule: bool) -> List[Dict]:
        """Find all paths from user to a specific rule."""
        paths = []
        
        # Get rule details
        if rule_type == 'hbac':
            rule = self.get_hbac_rule(rule_name)
        else:
            rule = self.get_sudo_rule(rule_name)
        
        if not rule:
            # Can't find paths without rule details
            return [{
                'rule_name': rule_name,
                'rule_type': rule_type,
                'path': [
                    {'type': 'user', 'name': username},
                    {'type': 'rule', 'name': rule_name}
                ],
                'path_type': 'unknown',
            }]
        
        # Check enabled
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default
        
        enabled = safe_first(rule.get('ipaenabledflag')) in ['TRUE', 'true', True]
        
        # Get rule's user groups
        rule_user_groups = set(rule.get('memberuser_group', []))
        rule_users = rule.get('memberuser_user', [])
        user_category = safe_first(rule.get('usercategory'))
        
        # Path type 1: User is directly in rule
        if username in rule_users:
            paths.append({
                'rule_name': rule_name,
                'rule_type': rule_type,
                'enabled': enabled,
                'path': [
                    {'type': 'user', 'name': username},
                    {'type': 'rule', 'name': rule_name}
                ],
                'path_type': 'direct_user',
                'description': f"User '{username}' is directly added to rule",
            })
        
        # Path type 2: Rule applies to all users
        if user_category == 'all':
            paths.append({
                'rule_name': rule_name,
                'rule_type': rule_type,
                'enabled': enabled,
                'path': [
                    {'type': 'user', 'name': username},
                    {'type': 'category', 'name': 'all_users'},
                    {'type': 'rule', 'name': rule_name}
                ],
                'path_type': 'all_users',
                'description': "Rule applies to all users",
            })
        
        # Path type 3: Via group membership
        # Find which groups connect user to rule
        connecting_groups = rule_user_groups & all_groups
        
        for group in connecting_groups:
            # Find the path from user to this group
            group_path = self._trace_group_path(username, group, direct_groups)
            
            full_path = [{'type': 'user', 'name': username}]
            for g in group_path:
                full_path.append({'type': 'group', 'name': g})
            full_path.append({'type': 'rule', 'name': rule_name})
            
            paths.append({
                'rule_name': rule_name,
                'rule_type': rule_type,
                'enabled': enabled,
                'path': full_path,
                'path_type': 'via_group',
                'connecting_group': group,
                'description': f"Via group '{group}'",
            })
        
        # If no paths found, add unknown path
        if not paths:
            paths.append({
                'rule_name': rule_name,
                'rule_type': rule_type,
                'enabled': enabled,
                'path': [
                    {'type': 'user', 'name': username},
                    {'type': 'unknown', 'name': '?'},
                    {'type': 'rule', 'name': rule_name}
                ],
                'path_type': 'indirect_unknown',
                'description': "Indirect access (path not determined)",
            })
        
        return paths
    
    def _trace_group_path(self, username: str, target_group: str, 
                          direct_groups: List[str]) -> List[str]:
        """Trace the path from user to a target group through group nesting."""
        # If target is a direct group, simple path
        if target_group in direct_groups:
            return [target_group]
        
        # BFS to find path through nested groups
        from collections import deque
        
        queue = deque()
        visited = set()
        
        # Start from direct groups
        for dg in direct_groups:
            queue.append([dg])
            visited.add(dg)
        
        while queue:
            path = queue.popleft()
            current = path[-1]
            
            if current == target_group:
                return path
            
            # Get parent groups of current
            group_data = self.get_group(current)
            if group_data:
                parent_groups = group_data.get('memberof_group', [])
                for parent in parent_groups:
                    if parent not in visited:
                        visited.add(parent)
                        queue.append(path + [parent])
        
        # Fallback - just return the target
        return [target_group]

    def trace_sudo_permission(self, username: str, hostname: str = None) -> List[Dict]:
        """Trace where a user's sudo permission on a host comes from."""
        user = self.get_user(username)
        if not user:
            return []
        
        self._debug(f"Tracing sudo permissions for {username}, host filter: {hostname}")

        traces = []
        
        # Get direct and indirect sudo rules from user object
        direct_sudo = user.get('memberof_sudorule', [])
        indirect_sudo = user.get('memberofindirect_sudorule', [])
        all_sudo = set(direct_sudo) | set(indirect_sudo)
        
        self._debug(f"Found sudo rules - direct: {direct_sudo}, indirect: {indirect_sudo}")
        
        if not all_sudo:
            self._debug("No sudo rules found for user")
            return []
        
        # Get user's groups for path tracing
        user_direct_groups = user.get('memberof_group', [])
        user_indirect_groups = user.get('memberofindirect_group', [])
        all_user_groups = set(user_direct_groups) | set(user_indirect_groups)
        
        # Helper to safely get first element
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default
        
        for rule_name in all_sudo:
            self._debug(f"Processing sudo rule: {rule_name}")
            
            # Fetch rule details directly
            rule_data = self.get_sudo_rule(rule_name)
            
            if not rule_data:
                self._debug(f"  Could not fetch rule details, adding basic entry")
                # Still add an entry even without details
                traces.append({
                    'rule': rule_name,
                    'rule_type': 'sudo',
                    'match_type': 'direct' if rule_name in direct_sudo else 'via_group',
                    'via_groups': [],
                    'path': [{'type': 'user', 'name': username}, {'type': 'rule', 'name': rule_name}],
                    'hosts': [],
                    'hostgroups': [],
                    'host_category': '',
                    'commands': {'allow': [], 'deny': [], 'cmd_category': ''},
                    'runas': {'users': [], 'groups': [], 'user_category': ''},
                    'description': 'Rule details not available',
                })
                continue
            
            self._debug(f"  Got rule data with keys: {rule_data.keys()}")
            
            # Check if enabled
            enabled_raw = rule_data.get('ipaenabledflag')
            enabled = safe_first(enabled_raw)
            self._debug(f"  ipaenabledflag raw: {enabled_raw}, parsed: '{enabled}'")
            
            # Handle different possible values for enabled flag
            is_enabled = (
                enabled == 'TRUE' or 
                enabled == 'true' or 
                enabled == True or
                (isinstance(enabled_raw, list) and len(enabled_raw) > 0 and enabled_raw[0] in ['TRUE', 'true', True])
            )
            
            if not is_enabled:
                self._debug(f"  Rule appears disabled (enabled={enabled}), but including anyway for visibility")
                # Still include disabled rules but mark them
                # continue  # Commented out - show all rules
            
            # Get hosts info
            hosts = rule_data.get('memberhost_host', [])
            hostgroups = rule_data.get('memberhost_hostgroup', [])
            host_category = safe_first(rule_data.get('hostcategory'))
            
            self._debug(f"  Hosts: {hosts}, Hostgroups: {hostgroups}, Category: {host_category}")
            
            # Check if rule applies to the specified host
            if hostname:
                applies_to_host = (
                    host_category == 'all' or
                    hostname in hosts or
                    any(self._host_in_hostgroup(hostname, hg) for hg in hostgroups)
                )
                if not applies_to_host:
                    self._debug(f"  Rule doesn't apply to host {hostname}, skipping")
                    continue
            
            # Build path and determine match type
            path = [{'type': 'user', 'name': username}]
            via_groups = []
            
            if rule_name in direct_sudo:
                match_type = 'direct'
            else:
                match_type = 'via_group'
                # Find which group(s) connect to this rule
                rule_groups = set(rule_data.get('memberuser_group', []))
                connecting_groups = rule_groups & all_user_groups
                via_groups = list(connecting_groups)
                
                # Add groups to path
                for group in via_groups[:3]:  # Limit to first 3 for readability
                    path.append({'type': 'group', 'name': group})
            
            path.append({'type': 'rule', 'name': rule_name})
            
            # Get commands
            commands = {
                'allow': rule_data.get('memberallowcmd_sudocmd', []),
                'allow_groups': rule_data.get('memberallowcmd_sudocmdgroup', []),
                'deny': rule_data.get('memberdenycmd_sudocmd', []),
                'deny_groups': rule_data.get('memberdenycmd_sudocmdgroup', []),
                'cmd_category': safe_first(rule_data.get('cmdcategory')),
            }
            
            # Get runas
            runas = {
                'users': rule_data.get('ipasudorunas_user', []),
                'groups': rule_data.get('ipasudorunas_group', []),
                'ext_users': rule_data.get('ipasudorunasextuser', []),
                'user_category': safe_first(rule_data.get('ipasudorunasusercategory')),
                'group_category': safe_first(rule_data.get('ipasudorunasgroupcategory')),
            }
            
            trace_entry = {
                'rule': rule_name,
                'rule_type': 'sudo',
                'match_type': match_type,
                'enabled': is_enabled,
                'via_groups': via_groups,
                'path': path,
                'hosts': hosts if host_category != 'all' else ['ALL'],
                'hostgroups': hostgroups,
                'host_category': host_category,
                'commands': commands,
                'runas': runas,
                'options': rule_data.get('ipasudoopt', []),
                'description': safe_first(rule_data.get('description')),
            }
            
            traces.append(trace_entry)
            self._debug(f"  Added trace entry for {rule_name}")
        
        self._debug(f"Total traces found: {len(traces)}")
        return traces

    def trace_hbac_permission(self, username: str, hostname: str = None) -> List[Dict]:
        """Trace where a user's HBAC permission on a host comes from."""
        user = self.get_user(username)
        if not user:
            return []
        
        self._debug(f"Tracing HBAC permissions for {username}, host filter: {hostname}")

        traces = []
        
        # Get direct and indirect HBAC rules from user object
        direct_hbac = user.get('memberof_hbacrule', [])
        indirect_hbac = user.get('memberofindirect_hbacrule', [])
        all_hbac = set(direct_hbac) | set(indirect_hbac)
        
        self._debug(f"Found HBAC rules - direct: {direct_hbac}, indirect: {indirect_hbac}")
        
        if not all_hbac:
            self._debug("No HBAC rules found for user")
            return []
        
        # Get user's groups for path tracing
        user_direct_groups = user.get('memberof_group', [])
        user_indirect_groups = user.get('memberofindirect_group', [])
        all_user_groups = set(user_direct_groups) | set(user_indirect_groups)
        
        # Helper to safely get first element
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default
        
        for rule_name in all_hbac:
            self._debug(f"Processing HBAC rule: {rule_name}")
            
            # Fetch rule details directly
            rule_data = self.get_hbac_rule(rule_name)
            
            if not rule_data:
                self._debug(f"  Could not fetch rule details, adding basic entry")
                traces.append({
                    'rule': rule_name,
                    'rule_type': 'hbac',
                    'match_type': 'direct' if rule_name in direct_hbac else 'via_group',
                    'via_groups': [],
                    'path': [{'type': 'user', 'name': username}, {'type': 'rule', 'name': rule_name}],
                    'hosts': [],
                    'hostgroups': [],
                    'host_category': '',
                    'services': [],
                    'service_groups': [],
                    'service_category': '',
                    'description': 'Rule details not available',
                })
                continue
            
            # Check if enabled
            enabled_raw = rule_data.get('ipaenabledflag')
            enabled = safe_first(enabled_raw)
            self._debug(f"  ipaenabledflag raw: {enabled_raw}, parsed: '{enabled}'")
            
            # Handle different possible values for enabled flag
            is_enabled = (
                enabled == 'TRUE' or 
                enabled == 'true' or 
                enabled == True or
                (isinstance(enabled_raw, list) and len(enabled_raw) > 0 and enabled_raw[0] in ['TRUE', 'true', True])
            )
            
            if not is_enabled:
                self._debug(f"  Rule appears disabled (enabled={enabled}), but including anyway for visibility")
                # Still include disabled rules but mark them
            
            # Get hosts info
            hosts = rule_data.get('memberhost_host', [])
            hostgroups = rule_data.get('memberhost_hostgroup', [])
            host_category = safe_first(rule_data.get('hostcategory'))
            
            # Check if rule applies to the specified host
            if hostname:
                applies_to_host = (
                    host_category == 'all' or
                    hostname in hosts or
                    any(self._host_in_hostgroup(hostname, hg) for hg in hostgroups)
                )
                if not applies_to_host:
                    self._debug(f"  Rule doesn't apply to host {hostname}, skipping")
                    continue
            
            # Build path and determine match type
            path = [{'type': 'user', 'name': username}]
            via_groups = []
            
            if rule_name in direct_hbac:
                match_type = 'direct'
            else:
                match_type = 'via_group'
                rule_groups = set(rule_data.get('memberuser_group', []))
                connecting_groups = rule_groups & all_user_groups
                via_groups = list(connecting_groups)
                
                # Add groups to path
                for group in via_groups[:3]:  # Limit for readability
                    path.append({'type': 'group', 'name': group})
            
            path.append({'type': 'rule', 'name': rule_name})
            
            trace_entry = {
                'rule': rule_name,
                'rule_type': 'hbac',
                'match_type': match_type,
                'enabled': is_enabled,
                'via_groups': via_groups,
                'path': path,
                'hosts': hosts if host_category != 'all' else ['ALL'],
                'hostgroups': hostgroups,
                'host_category': host_category,
                'services': rule_data.get('memberservice_hbacsvc', []),
                'service_groups': rule_data.get('memberservice_hbacsvcgroup', []),
                'service_category': safe_first(rule_data.get('servicecategory')),
                'description': safe_first(rule_data.get('description')),
            }
            
            traces.append(trace_entry)
            self._debug(f"  Added trace entry for {rule_name}")

        self._debug(f"Total HBAC traces found: {len(traces)}")
        return traces

    def _host_in_hostgroup(self, hostname: str, hostgroup_name: str) -> bool:
        """Check if a host is in a hostgroup."""
        hostgroup = self.get_hostgroup(hostgroup_name)
        if not hostgroup:
            return False

        members = hostgroup.get('member_host', [])
        return hostname in members

    # ==================== User Comparison ====================

    def compare_users(self, user1: str, user2: str) -> Dict:
        """Compare permissions between two users."""
        analysis1 = self.analyze_user_permissions(user1)
        analysis2 = self.analyze_user_permissions(user2)

        if 'error' in analysis1:
            return {'error': analysis1['error']}
        if 'error' in analysis2:
            return {'error': analysis2['error']}

        # Compare groups
        groups1 = set(analysis1['all_groups'])
        groups2 = set(analysis2['all_groups'])

        # Compare HBAC rules
        hbac1 = {r['name'] for r in analysis1['hbac_rules']}
        hbac2 = {r['name'] for r in analysis2['hbac_rules']}

        # Compare Sudo rules
        sudo1 = {r['name'] for r in analysis1['sudo_rules']}
        sudo2 = {r['name'] for r in analysis2['sudo_rules']}

        return {
            'user1': analysis1['user'],
            'user2': analysis2['user'],
            'groups': {
                'only_user1': list(groups1 - groups2),
                'only_user2': list(groups2 - groups1),
                'common': list(groups1 & groups2),
            },
            'hbac_rules': {
                'only_user1': list(hbac1 - hbac2),
                'only_user2': list(hbac2 - hbac1),
                'common': list(hbac1 & hbac2),
            },
            'sudo_rules': {
                'only_user1': list(sudo1 - sudo2),
                'only_user2': list(sudo2 - sudo1),
                'common': list(sudo1 & sudo2),
            },
            'details': {
                'user1': analysis1,
                'user2': analysis2,
            }
        }

    # ==================== Graph Data Generation ====================

    def generate_graph_data(self, username: str, filter_mode: str = 'all') -> Dict:
        """
        Generate graph data for visualization.
        
        Args:
            username: User to analyze
            filter_mode: 'all' - show everything
                        'rules_only' - only show groups connected to HBAC/Sudo rules
                        'hbac' - only show HBAC rules
                        'sudo' - only show Sudo rules
        """
        analysis = self.analyze_user_permissions(username)
        if 'error' in analysis:
            return {'error': analysis['error']}

        nodes = []
        edges = []
        node_ids = set()
        
        # Track which groups are connected to rules
        groups_with_hbac = set()
        groups_with_sudo = set()
        
        # Get user object to access direct memberships
        user = self.get_user(username)

        def add_node(node_id: str, node_type: str, label: str, metadata: Dict = None):
            if node_id not in node_ids:
                node_ids.add(node_id)
                nodes.append({
                    'id': node_id,
                    'type': node_type,
                    'label': label,
                    'metadata': metadata or {},
                })

        def add_edge(source: str, target: str, edge_type: str, label: str = ''):
            edge_key = f"{source}->{target}"
            edges.append({
                'source': source,
                'target': target,
                'type': edge_type,
                'label': label,
            })

        # Add user node
        user_id = f"user_{username}"
        add_node(user_id, 'user', analysis['user']['cn'] or username, {
            'uid': analysis['user']['uid'],
            'email': analysis['user']['mail'],
        })

        # Process HBAC rules and find which groups they connect through
        direct_hbac = set(user.get('memberof_hbacrule', []) if user else [])
        indirect_hbac = set(user.get('memberofindirect_hbacrule', []) if user else [])
        all_hbac_rules = direct_hbac | indirect_hbac
        
        if filter_mode in ['all', 'rules_only', 'hbac']:
            for rule_name in all_hbac_rules:
                rule_id = f"hbac_{rule_name}"
                
                # Find the rule details
                rule_detail = None
                for r in analysis.get('hbac_rules', []):
                    if r['name'] == rule_name:
                        rule_detail = r
                        break
                
                add_node(rule_id, 'hbac', rule_name, {
                    'description': rule_detail.get('description', '') if rule_detail else '',
                    'hosts': rule_detail.get('hosts', []) if rule_detail else [],
                    'hostgroups': rule_detail.get('hostgroups', []) if rule_detail else [],
                    'host_category': rule_detail.get('host_category', '') if rule_detail else '',
                })
                
                if rule_name in direct_hbac:
                    # Direct membership
                    add_edge(user_id, rule_id, 'has_hbac', 'HBAC (direct)')
                else:
                    # Find which group(s) provide this rule
                    connecting_groups = self._find_groups_for_rule(
                        username, rule_name, 'hbacrule', analysis
                    )
                    for group in connecting_groups:
                        groups_with_hbac.add(group)
                        group_id = f"group_{group}"
                        add_node(group_id, 'group', group)
                        add_edge(group_id, rule_id, 'has_hbac', 'HBAC')
        
        # Process Sudo rules
        direct_sudo = set(user.get('memberof_sudorule', []) if user else [])
        indirect_sudo = set(user.get('memberofindirect_sudorule', []) if user else [])
        all_sudo_rules = direct_sudo | indirect_sudo
        
        if filter_mode in ['all', 'rules_only', 'sudo']:
            for rule_name in all_sudo_rules:
                rule_id = f"sudo_{rule_name}"
                
                # Find the rule details
                rule_detail = None
                for r in analysis.get('sudo_rules', []):
                    if r['name'] == rule_name:
                        rule_detail = r
                        break
                
                add_node(rule_id, 'sudo', rule_name, {
                    'description': rule_detail.get('description', '') if rule_detail else '',
                    'hosts': rule_detail.get('hosts', []) if rule_detail else [],
                    'hostgroups': rule_detail.get('hostgroups', []) if rule_detail else [],
                    'host_category': rule_detail.get('host_category', '') if rule_detail else '',
                    'commands': rule_detail.get('commands', {}) if rule_detail else {},
                    'runas': rule_detail.get('runas', {}) if rule_detail else {},
                })
                
                if rule_name in direct_sudo:
                    add_edge(user_id, rule_id, 'has_sudo', 'Sudo (direct)')
                else:
                    connecting_groups = self._find_groups_for_rule(
                        username, rule_name, 'sudorule', analysis
                    )
                    for group in connecting_groups:
                        groups_with_sudo.add(group)
                        group_id = f"group_{group}"
                        add_node(group_id, 'group', group)
                        add_edge(group_id, rule_id, 'has_sudo', 'Sudo')

        # Determine which groups to show
        groups_to_show = set()
        
        if filter_mode == 'all':
            groups_to_show = set(analysis['direct_groups']) | set(analysis.get('indirect_groups', []))
        elif filter_mode == 'rules_only':
            groups_to_show = groups_with_hbac | groups_with_sudo
        elif filter_mode == 'hbac':
            groups_to_show = groups_with_hbac
        elif filter_mode == 'sudo':
            groups_to_show = groups_with_sudo

        # Add groups and build hierarchy
        direct_groups = set(analysis['direct_groups'])
        
        for group in groups_to_show:
            group_id = f"group_{group}"
            add_node(group_id, 'group', group)
            
            if group in direct_groups:
                add_edge(user_id, group_id, 'member_of', 'member of')
            else:
                # Find path from user to this indirect group
                path = self._find_group_path(username, group, analysis)
                for i in range(len(path) - 1):
                    from_group = path[i]
                    to_group = path[i + 1]
                    from_id = f"group_{from_group}" if i > 0 else user_id
                    to_id = f"group_{to_group}"
                    add_node(to_id, 'group', to_group)
                    if from_id == user_id:
                        add_edge(user_id, to_id, 'member_of', 'member of')
                    else:
                        add_node(from_id, 'group', from_group)
                        add_edge(from_id, to_id, 'member_of', 'nested')

        return {
            'nodes': nodes,
            'edges': edges,
            'analysis': analysis,
            'filter_mode': filter_mode,
            'stats': {
                'total_groups': len(analysis['direct_groups']) + len(analysis.get('indirect_groups', [])),
                'groups_shown': len([n for n in nodes if n['type'] == 'group']),
                'hbac_rules': len(all_hbac_rules),
                'sudo_rules': len(all_sudo_rules),
            }
        }

    def _find_groups_for_rule(self, username: str, rule_name: str, rule_type: str, analysis: Dict) -> List[str]:
        """Find which groups give the user access to a specific rule."""
        connecting_groups = []
        
        # Get all HBAC/Sudo rules and check which groups are members
        if rule_type == 'hbacrule':
            all_rules = self.get_all_hbac_rules()
        else:
            all_rules = self.get_all_sudo_rules()
        
        # Helper to safely get first element
        def safe_first(val, default=''):
            if isinstance(val, list) and val:
                return val[0]
            return val if val else default
        
        for rule in all_rules:
            if safe_first(rule.get('cn')) == rule_name:
                # Get groups that are members of this rule
                rule_groups = set(rule.get('memberuser_group', []))
                
                # Find intersection with user's groups
                user_groups = set(analysis['direct_groups']) | set(analysis.get('indirect_groups', []))
                connecting = rule_groups & user_groups
                connecting_groups.extend(list(connecting))
                break
        
        return connecting_groups

    def _find_group_path(self, username: str, target_group: str, analysis: Dict) -> List[str]:
        """Find the path from user to a target group."""
        direct_groups = set(analysis['direct_groups'])
        
        if target_group in direct_groups:
            return [target_group]
        
        # BFS to find path through group hierarchy
        from collections import deque
        
        visited = set()
        queue = deque()
        
        # Start from direct groups
        for dg in direct_groups:
            queue.append([dg])
            visited.add(dg)
        
        while queue:
            path = queue.popleft()
            current = path[-1]
            
            if current == target_group:
                return path
            
            # Get children of current group (groups that have current as parent)
            group_info = self.get_group(current)
            if group_info:
                children = group_info.get('memberof_group', [])
                for child in children:
                    if child not in visited:
                        visited.add(child)
                        queue.append(path + [child])
        
        return [target_group]  # Fallback


# ==================== Flask Routes ====================

@app.route('/')
def index():
    """Main page."""
    return render_template('index.html')


@app.route('/api/users')
def api_get_users():
    """Get all users."""
    users = idm_client.get_all_users()
    return jsonify(users)


@app.route('/api/user/<username>')
def api_get_user(username: str):
    """Get user details."""
    user = idm_client.get_user(username)
    if user:
        return jsonify(user)
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/user/<username>/analyze')
def api_analyze_user(username: str):
    """Analyze user permissions."""
    analysis = idm_client.analyze_user_permissions(username)
    return jsonify(analysis)


@app.route('/api/user/<username>/graph')
def api_user_graph(username: str):
    """Get graph data for user."""
    filter_mode = request.args.get('filter', 'all')  # all, rules_only, hbac, sudo
    graph = idm_client.generate_graph_data(username, filter_mode)
    return jsonify(graph)


@app.route('/api/user/<username>/trace-sudo')
def api_trace_sudo(username: str):
    """Trace sudo permissions for a user."""
    hostname = request.args.get('host')
    traces = idm_client.trace_sudo_permission(username, hostname)
    return jsonify(traces)


@app.route('/api/user/<username>/trace-hbac')
def api_trace_hbac(username: str):
    """Trace HBAC permissions for a user."""
    hostname = request.args.get('host')
    traces = idm_client.trace_hbac_permission(username, hostname)
    return jsonify(traces)


@app.route('/api/user/<username>/trace')
def api_trace_all(username: str):
    """Trace all permissions (sudo and HBAC) for a user."""
    hostname = request.args.get('host')
    rule_type = request.args.get('type', 'all')  # all, sudo, hbac
    
    result = {
        'user': username,
        'host_filter': hostname,
        'sudo_rules': [],
        'hbac_rules': [],
    }
    
    if rule_type in ['all', 'sudo']:
        result['sudo_rules'] = idm_client.trace_sudo_permission(username, hostname)
    
    if rule_type in ['all', 'hbac']:
        result['hbac_rules'] = idm_client.trace_hbac_permission(username, hostname)
    
    return jsonify(result)


@app.route('/api/user/<username>/trace-full')
def api_trace_full(username: str):
    """Get comprehensive permission tree showing all paths to rules."""
    result = idm_client.trace_full_permissions(username)
    return jsonify(result)


@app.route('/api/compare')
def api_compare_users():
    """Compare two users."""
    user1 = request.args.get('user1')
    user2 = request.args.get('user2')

    if not user1 or not user2:
        return jsonify({'error': 'Both user1 and user2 are required'}), 400

    comparison = idm_client.compare_users(user1, user2)
    return jsonify(comparison)


@app.route('/api/groups')
def api_get_groups():
    """Get all groups."""
    groups = idm_client.get_all_groups()
    return jsonify(groups)


@app.route('/api/hosts')
def api_get_hosts():
    """Get all hosts."""
    hosts = idm_client.get_all_hosts()
    return jsonify(hosts)


@app.route('/api/hbac-rules')
def api_get_hbac_rules():
    """Get all HBAC rules."""
    rules = idm_client.get_all_hbac_rules()
    return jsonify(rules)


@app.route('/api/sudo-rules')
def api_get_sudo_rules():
    """Get all sudo rules."""
    rules = idm_client.get_all_sudo_rules()
    return jsonify(rules)


@app.route('/api/debug/user/<username>')
def api_debug_user(username: str):
    """Debug endpoint to see raw user data."""
    try:
        # Try direct API call
        result = idm_client._client.user_show(username, all=True)
        return jsonify({
            'status': 'success',
            'raw_type': str(type(result)),
            'raw_data': result
        })
    except NotFound:
        return jsonify({
            'status': 'not_found',
            'message': f'User {username} not found in IDM'
        }), 404
    except Exception as e:
        import traceback
        return jsonify({
            'status': 'error',
            'message': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/debug/search/<query>')
def api_debug_search(query: str):
    """Debug endpoint to search users."""
    try:
        result = idm_client._client.user_find(query, all=True, sizelimit=10)
        return jsonify({
            'status': 'success',
            'count': result.get('count', 0),
            'raw_data': result
        })
    except Exception as e:
        import traceback
        return jsonify({
            'status': 'error',
            'message': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/debug/user-structure/<username>')
def api_debug_user_structure(username: str):
    """Debug endpoint to see complete user structure and identify group fields."""
    try:
        result = idm_client._client.user_show(username, all=True)
        
        # Find all fields that might contain group info
        group_fields = {}
        for key, value in result.items():
            if 'group' in key.lower() or 'member' in key.lower():
                group_fields[key] = value
        
        return jsonify({
            'status': 'success',
            'all_keys': list(result.keys()),
            'group_related_fields': group_fields,
            'full_data': result
        })
    except NotFound:
        return jsonify({'status': 'not_found'}), 404
    except Exception as e:
        import traceback
        return jsonify({
            'status': 'error',
            'message': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/debug/analyze/<username>')
def api_debug_analyze(username: str):
    """Debug the analysis process step by step."""
    debug_info = {
        'steps': [],
        'errors': []
    }
    
    try:
        # Step 1: Get user
        user = idm_client.get_user(username)
        debug_info['steps'].append({
            'step': '1. Get user',
            'success': user is not None,
            'user_keys': list(user.keys()) if user else None,
        })
        
        if not user:
            debug_info['errors'].append('User not found')
            return jsonify(debug_info)
        
        # Step 2: Find memberof field
        memberof_fields = {k: v for k, v in user.items() if 'memberof' in k.lower()}
        debug_info['steps'].append({
            'step': '2. Find memberof fields',
            'fields_found': memberof_fields
        })
        
        # Step 3: Get groups using correct field
        direct_groups = user.get('memberof_group', [])
        # Also try alternate field names
        if not direct_groups:
            direct_groups = user.get('memberOf', [])
        if not direct_groups:
            # Try to find any field with groups
            for key, value in user.items():
                if 'memberof' in key.lower() and 'group' in key.lower():
                    direct_groups = value
                    break
        
        debug_info['steps'].append({
            'step': '3. Extract direct groups',
            'groups_found': direct_groups,
            'count': len(direct_groups) if direct_groups else 0
        })
        
        # Step 4: Get all groups
        all_groups = idm_client.get_user_all_groups(username)
        debug_info['steps'].append({
            'step': '4. Get all groups (including nested)',
            'all_groups': list(all_groups),
            'count': len(all_groups)
        })
        
        # Step 5: Check HBAC rules
        hbac_rules = idm_client.get_all_hbac_rules()
        debug_info['steps'].append({
            'step': '5. Get HBAC rules',
            'total_rules': len(hbac_rules),
            'sample_rule_keys': list(hbac_rules[0].keys()) if hbac_rules else None
        })
        
        # Step 6: Check Sudo rules  
        sudo_rules = idm_client.get_all_sudo_rules()
        debug_info['steps'].append({
            'step': '6. Get Sudo rules',
            'total_rules': len(sudo_rules),
            'sample_rule_keys': list(sudo_rules[0].keys()) if sudo_rules else None
        })
        
        # Step 7: Run full analysis
        analysis = idm_client.analyze_user_permissions(username)
        debug_info['steps'].append({
            'step': '7. Full analysis result',
            'has_error': 'error' in analysis,
            'direct_groups_count': len(analysis.get('direct_groups', [])),
            'all_groups_count': len(analysis.get('all_groups', [])),
            'hbac_rules_count': len(analysis.get('hbac_rules', [])),
            'sudo_rules_count': len(analysis.get('sudo_rules', [])),
        })
        
        debug_info['final_analysis'] = analysis
        
    except Exception as e:
        import traceback
        debug_info['errors'].append({
            'message': str(e),
            'traceback': traceback.format_exc()
        })
    
    return jsonify(debug_info)


# ==================== Main ====================

def main():
    global idm_client

    parser = argparse.ArgumentParser(description='IDM Permission Analyzer Web Application')
    parser.add_argument('-s', '--server', required=True, help='FreeIPA server hostname')
    parser.add_argument('-l', '--login', metavar='USERNAME', help='Login username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos')
    parser.add_argument('--port', type=int, default=5000, help='Web server port')
    parser.add_argument('--host', default='127.0.0.1', help='Web server host')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL')
    parser.add_argument('--debug', action='store_true', help='Debug mode')

    args = parser.parse_args()

    if not args.kerberos and not args.login:
        parser.error("Either --login or --kerberos must be specified")

    password = args.password
    if args.login and not password:
        import getpass
        password = getpass.getpass(f"Password for {args.login}: ")

    try:
        idm_client = IDMClient(
            server=args.server,
            username=args.login,
            password=password,
            use_kerberos=args.kerberos,
            verify_ssl=args.verify_ssl,
            debug=args.debug,
        )
        
        # Test fetching users on startup if debug mode
        if args.debug:
            print("\n[DEBUG] Testing user fetch on startup...")
            test_users = idm_client.get_all_users()
            print(f"[DEBUG] Found {len(test_users)} users")

        print(f"\n[*] Starting web server on http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=args.debug)

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
