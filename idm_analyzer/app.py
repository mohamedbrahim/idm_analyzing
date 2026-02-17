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
                 use_kerberos: bool = False, verify_ssl: bool = False):
        self.server = server
        self.verify_ssl = verify_ssl
        self._client = None
        self._cache = {}
        self._connect(username, password, use_kerberos)

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
            result = self._client.user_find(all=True, sizelimit=0)
            users = []
            for user in result.get('result', []):
                users.append({
                    'uid': user.get('uid', [''])[0],
                    'cn': user.get('cn', [''])[0],
                    'mail': user.get('mail', [''])[0] if user.get('mail') else '',
                    'memberof_group': user.get('memberof_group', []),
                })
            return self._cache_set(cache_key, users)
        except Exception as e:
            print(f"Error fetching users: {e}")
            return []

    def get_user(self, username: str) -> Optional[Dict]:
        """Get detailed user information."""
        cache_key = f"user:{username}"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.user_show(username, all=True)
            return self._cache_set(cache_key, result)
        except NotFound:
            return None
        except Exception as e:
            print(f"Error fetching user {username}: {e}")
            return None

    # ==================== Group Methods ====================

    def get_group(self, groupname: str) -> Optional[Dict]:
        """Get detailed group information."""
        cache_key = f"group:{groupname}"
        if cached := self._cache_get(cache_key):
            return cached

        try:
            result = self._client.group_show(groupname, all=True)
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
        direct_groups = user.get('memberof_group', [])

        for group in direct_groups:
            all_groups.add(group)
            # Get nested memberships
            nested = self.get_nested_group_membership(group)
            for n in nested:
                all_groups.add(n['parent'])

        return all_groups

    def analyze_user_permissions(self, username: str) -> Dict:
        """Complete permission analysis for a user."""
        user = self.get_user(username)
        if not user:
            return {'error': f'User {username} not found'}

        # Get all groups (direct and nested)
        all_groups = self.get_user_all_groups(username)
        direct_groups = set(user.get('memberof_group', []))

        # Build group hierarchy
        group_hierarchy = []
        for group in direct_groups:
            nested = self.get_nested_group_membership(group)
            group_hierarchy.extend(nested)

        # Analyze HBAC rules
        hbac_rules = self._analyze_hbac_for_user(username, all_groups)

        # Analyze Sudo rules
        sudo_rules = self._analyze_sudo_for_user(username, all_groups)

        return {
            'user': {
                'uid': user.get('uid', [''])[0],
                'cn': user.get('cn', [''])[0],
                'mail': user.get('mail', [''])[0] if user.get('mail') else '',
            },
            'direct_groups': list(direct_groups),
            'all_groups': list(all_groups),
            'group_hierarchy': group_hierarchy,
            'hbac_rules': hbac_rules,
            'sudo_rules': sudo_rules,
        }

    def _analyze_hbac_for_user(self, username: str, user_groups: Set[str]) -> List[Dict]:
        """Analyze which HBAC rules apply to a user and how."""
        rules = []
        all_hbac = self.get_all_hbac_rules()

        for rule in all_hbac:
            rule_name = rule.get('cn', [''])[0]
            enabled = rule.get('ipaenabledflag', [''])[0]

            if enabled != 'TRUE':
                continue

            match_info = self._check_rule_user_match(rule, username, user_groups, 'memberuser')

            if match_info['matches']:
                # Get hosts this rule applies to
                hosts = self._get_rule_hosts(rule, 'memberhost')

                rules.append({
                    'name': rule_name,
                    'type': 'hbac',
                    'match_type': match_info['match_type'],
                    'via_groups': match_info['via_groups'],
                    'path': match_info['path'],
                    'hosts': hosts['hosts'],
                    'hostgroups': hosts['hostgroups'],
                    'host_category': rule.get('hostcategory', [''])[0],
                    'services': rule.get('memberservice_hbacsvc', []),
                    'service_groups': rule.get('memberservice_hbacsvcgroup', []),
                    'service_category': rule.get('servicecategory', [''])[0],
                    'description': rule.get('description', [''])[0] if rule.get('description') else '',
                })

        return rules

    def _analyze_sudo_for_user(self, username: str, user_groups: Set[str]) -> List[Dict]:
        """Analyze which sudo rules apply to a user and how."""
        rules = []
        all_sudo = self.get_all_sudo_rules()

        for rule in all_sudo:
            rule_name = rule.get('cn', [''])[0]
            enabled = rule.get('ipaenabledflag', [''])[0]

            if enabled != 'TRUE':
                continue

            match_info = self._check_rule_user_match(rule, username, user_groups, 'memberuser')

            if match_info['matches']:
                # Get hosts this rule applies to
                hosts = self._get_rule_hosts(rule, 'memberhost')

                # Get commands
                commands = {
                    'allow': rule.get('memberallowcmd_sudocmd', []),
                    'allow_groups': rule.get('memberallowcmd_sudocmdgroup', []),
                    'deny': rule.get('memberdenycmd_sudocmd', []),
                    'deny_groups': rule.get('memberdenycmd_sudocmdgroup', []),
                    'cmd_category': rule.get('cmdcategory', [''])[0],
                }

                # Get runas users
                runas = {
                    'users': rule.get('ipasudorunas_user', []),
                    'groups': rule.get('ipasudorunas_group', []),
                    'user_category': rule.get('ipasudorunasusercategory', [''])[0],
                    'group_category': rule.get('ipasudorunasgroupcategory', [''])[0],
                }

                rules.append({
                    'name': rule_name,
                    'type': 'sudo',
                    'match_type': match_info['match_type'],
                    'via_groups': match_info['via_groups'],
                    'path': match_info['path'],
                    'hosts': hosts['hosts'],
                    'hostgroups': hosts['hostgroups'],
                    'host_category': rule.get('hostcategory', [''])[0],
                    'commands': commands,
                    'runas': runas,
                    'options': rule.get('ipasudoopt', []),
                    'description': rule.get('description', [''])[0] if rule.get('description') else '',
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

    def trace_sudo_permission(self, username: str, hostname: str = None) -> List[Dict]:
        """Trace where a user's sudo permission on a host comes from."""
        analysis = self.analyze_user_permissions(username)
        if 'error' in analysis:
            return []

        traces = []
        for rule in analysis['sudo_rules']:
            # Check if rule applies to the specified host
            if hostname:
                applies_to_host = (
                    rule['host_category'] == 'all' or
                    hostname in rule['hosts'] or
                    any(self._host_in_hostgroup(hostname, hg) for hg in rule['hostgroups'])
                )
                if not applies_to_host:
                    continue

            traces.append({
                'rule': rule['name'],
                'match_type': rule['match_type'],
                'via_groups': rule['via_groups'],
                'path': rule['path'],
                'hosts': rule['hosts'] if rule['host_category'] != 'all' else ['ALL'],
                'hostgroups': rule['hostgroups'],
                'commands': rule['commands'],
                'runas': rule['runas'],
            })

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

    def generate_graph_data(self, username: str) -> Dict:
        """Generate graph data for visualization."""
        analysis = self.analyze_user_permissions(username)
        if 'error' in analysis:
            return {'error': analysis['error']}

        nodes = []
        edges = []
        node_ids = set()

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

        # Add direct groups
        for group in analysis['direct_groups']:
            group_id = f"group_{group}"
            add_node(group_id, 'group', group)
            add_edge(user_id, group_id, 'member_of', 'member of')

        # Add nested group relationships
        for rel in analysis['group_hierarchy']:
            child_id = f"group_{rel['child']}"
            parent_id = f"group_{rel['parent']}"
            add_node(child_id, 'group', rel['child'])
            add_node(parent_id, 'group', rel['parent'])
            add_edge(child_id, parent_id, 'member_of', 'member of')

        # Add HBAC rules
        for rule in analysis['hbac_rules']:
            rule_id = f"hbac_{rule['name']}"
            add_node(rule_id, 'hbac', rule['name'], {
                'description': rule['description'],
                'hosts': rule['hosts'],
                'hostgroups': rule['hostgroups'],
                'host_category': rule['host_category'],
            })

            # Connect via the matching path
            if rule['match_type'] == 'direct' or rule['match_type'] == 'all_users':
                add_edge(user_id, rule_id, 'has_hbac', 'HBAC')
            elif rule['via_groups']:
                for group in rule['via_groups']:
                    group_id = f"group_{group}"
                    add_edge(group_id, rule_id, 'has_hbac', 'HBAC')

        # Add Sudo rules
        for rule in analysis['sudo_rules']:
            rule_id = f"sudo_{rule['name']}"
            add_node(rule_id, 'sudo', rule['name'], {
                'description': rule['description'],
                'hosts': rule['hosts'],
                'hostgroups': rule['hostgroups'],
                'host_category': rule['host_category'],
                'commands': rule['commands'],
                'runas': rule['runas'],
            })

            if rule['match_type'] == 'direct' or rule['match_type'] == 'all_users':
                add_edge(user_id, rule_id, 'has_sudo', 'sudo')
            elif rule['via_groups']:
                for group in rule['via_groups']:
                    group_id = f"group_{group}"
                    add_edge(group_id, rule_id, 'has_sudo', 'sudo')

        return {
            'nodes': nodes,
            'edges': edges,
            'analysis': analysis,
        }


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
    graph = idm_client.generate_graph_data(username)
    return jsonify(graph)


@app.route('/api/user/<username>/trace-sudo')
def api_trace_sudo(username: str):
    """Trace sudo permissions for a user."""
    hostname = request.args.get('host')
    traces = idm_client.trace_sudo_permission(username, hostname)
    return jsonify(traces)


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
        )

        print(f"\n[*] Starting web server on http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=args.debug)

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
