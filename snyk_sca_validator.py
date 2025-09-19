#!/usr/bin/env python3
"""
Snyk SCA File Validator - GitLab Edition

This script validates if Snyk SCA files (projects) are still actually present
in their GitLab repositories. It performs the following operations:

1. Pulls all Snyk organizations
2. Gets all targets (with remote repo URLs) for each organization
3. Finds SCA projects under each target and their specific file names
4. Checks the GitLab repository from the remote repo URL
5. Compares files between Snyk and the actual GitLab repository
6. Reports which Snyk projects need to be removed or added

Usage:
    python3 snyk_sca_validator.py --snyk-token YOUR_TOKEN
    python3 snyk_sca_validator.py --snyk-token YOUR_TOKEN --org-id ORG_ID
    python3 snyk_sca_validator.py --snyk-token YOUR_TOKEN --gitlab-token GITLAB_TOKEN
"""

import json
import argparse
import sys
import os
import csv
import requests
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse


def debug_log(message: str, debug_enabled: bool = False):
    """Helper function for debug logging."""
    if debug_enabled:
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        print(f"[{timestamp}] 🔍 DEBUG: {message}")


class SnykAPI:
    """Snyk API client for managing organizations, targets, and projects."""

    def __init__(self, token: str, region: str = "SNYK-US-01", debug: bool = False):
        self.token = token
        self.base_url = self._get_base_url(region)
        self.debug = debug
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {token}',
            'Accept': '*/*'
        })

    def _get_base_url(self, region: str) -> str:
        """Get the appropriate API base URL for the region."""
        region_urls = {
            "SNYK-US-01": "https://api.snyk.io",
            "SNYK-US-02": "https://api.us.snyk.io",
            "SNYK-EU-01": "https://api.eu.snyk.io",
            "SNYK-AU-01": "https://api.au.snyk.io"
        }
        return region_urls.get(region, "https://api.snyk.io")

    def get_organizations(self, version: str = "2024-10-15") -> List[Dict]:
        """
        Get all organizations accessible to the token.

        Args:
            version: API version

        Returns:
            List of all organizations
        """
        print("🏢 Fetching all Snyk organizations...")

        url = f"{self.base_url}/rest/orgs"
        params = {
            'version': version,
            'limit': 100
        }

        all_orgs = []
        next_url = url
        next_params = params
        page = 1

        while next_url:
            print(f"   📄 Fetching organizations page {page}...")
            debug_log(f"API Request - URL: {next_url}", self.debug)
            debug_log(f"API Request - Params: {next_params}", self.debug)
            response = self.session.get(next_url, params=next_params)
            debug_log(f"API Response - Status: {response.status_code}", self.debug)
            debug_log(f"API Response - Headers: {dict(response.headers)}", self.debug)
            if response.status_code != 200:
                debug_log(f"API Response - Error body: {response.text}", self.debug)
            response.raise_for_status()
            data = response.json()

            orgs = data.get('data', [])
            all_orgs.extend(orgs)

            # Handle pagination
            links = data.get('links', {})
            next_url = links.get('next')
            next_params = None

            if next_url:
                if next_url.startswith('http'):
                    pass  # use as-is
                elif next_url.startswith('/'):
                    next_url = self.base_url + next_url
                else:
                    next_url = self.base_url + '/' + next_url.lstrip('/')
            else:
                next_url = None

            page += 1

        print(f"   ✅ Found {len(all_orgs)} organizations")
        return all_orgs

    def validate_organization_access(self, org_id: str, version: str = "2024-10-15") -> bool:
        """
        Validate if the organization exists and is accessible.

        Args:
            org_id: Organization ID to validate
            version: API version

        Returns:
            True if organization is accessible, False otherwise
        """
        debug_log(f"Validating access to organization {org_id}", self.debug)
        
        # Try multiple API versions if the first one fails
        api_versions = [version, "2023-05-29", "2023-06-12", "2023-08-14", "2023-10-16"]
        
        for api_version in api_versions:
            try:
                url = f"{self.base_url}/rest/orgs/{org_id}"
                params = {'version': api_version}
                
                debug_log(f"API Request - URL: {url}", self.debug)
                debug_log(f"API Request - Params: {params}", self.debug)
                
                response = self.session.get(url, params=params)
                
                # Debug: Check the actual URL that was called
                debug_log(f"Actual URL called: {response.url}", self.debug)
                debug_log(f"API Response - Status: {response.status_code}", self.debug)
                debug_log(f"API Response - Headers: {dict(response.headers)}", self.debug)
                
                if response.status_code == 200:
                    debug_log(f"Organization {org_id} is accessible with API version {api_version}", self.debug)
                    print(f"   ✅ Organization {org_id} accessible with API version {api_version}")
                    return True
                elif response.status_code == 404:
                    debug_log(f"Organization {org_id} not found with API version {api_version}", self.debug)
                    if api_version == api_versions[-1]:  # Last version tried
                        print(f"   ❌ Organization {org_id} not found with any API version")
                        return False
                    else:
                        debug_log(f"Trying next API version...", self.debug)
                        continue
                elif response.status_code == 403:
                    print(f"   ❌ Access denied to organization {org_id}")
                    debug_log(f"Access denied to organization {org_id}", self.debug)
                    return False
                elif response.status_code == 401:
                    print(f"   ❌ Authentication failed for organization {org_id}")
                    debug_log(f"Authentication failed for organization {org_id}", self.debug)
                    return False
                else:
                    debug_log(f"Unexpected response for organization {org_id} with API version {api_version}: {response.status_code}", self.debug)
                    if api_version == api_versions[-1]:  # Last version tried
                        print(f"   ⚠️  Unexpected response for organization {org_id}: {response.status_code}")
                        return False
                    else:
                        debug_log(f"Trying next API version...", self.debug)
                        continue
                    
            except Exception as e:
                debug_log(f"Error validating organization {org_id} with API version {api_version}: {e}", self.debug)
                if api_version == api_versions[-1]:  # Last version tried
                    print(f"   ❌ Error validating organization {org_id}: {e}")
                    return False
                else:
                    debug_log(f"Trying next API version...", self.debug)
                    continue
        
        return False

    def get_targets_for_org(self, org_id: str, 
                           version: str = "2024-10-15") -> List[Dict]:
        """
        Get all targets for a Snyk organization, filtered for GitLab and CLI sources.

        Args:
            org_id: Organization ID
            version: API version

        Returns:
            List of all targets with their URLs and metadata
        """
        print(f"🎯 Fetching targets for organization {org_id} (GitLab and CLI only)...")

        # Try multiple API versions if the first one fails
        api_versions = [version, "2023-05-29", "2023-06-12", "2023-08-14", "2023-10-16"]
        
        for api_version in api_versions:
            try:
                debug_log(f"Trying API version {api_version} for targets", self.debug)
                targets = self._get_targets_with_version(org_id, api_version)
                if targets is not None:
                    print(f"   ✅ Successfully fetched targets with API version {api_version}")
                    return targets
                else:
                    debug_log(f"Failed to fetch targets with API version {api_version}, trying next...", self.debug)
                    continue
            except Exception as e:
                debug_log(f"Error fetching targets with API version {api_version}: {e}", self.debug)
                if api_version == api_versions[-1]:  # Last version tried
                    print(f"   ❌ Failed to fetch targets with any API version")
                    return []
                continue
        
        return []

    def _get_targets_with_version(self, org_id: str, version: str) -> Optional[List[Dict]]:
        """
        Get targets for a specific API version.

        Args:
            org_id: Organization ID
            version: API version

        Returns:
            List of targets or None if failed
        """
        url = f"{self.base_url}/rest/orgs/{org_id}/targets"
        params = {
            'version': version,
            'limit': 100,
            'source_types': 'gitlab,cli'
        }

        all_targets = []
        next_url = url
        next_params = params
        page = 1

        while next_url:
            print(f"   📄 Fetching targets page {page}...")
            debug_log(f"API Request - URL: {next_url}", self.debug)
            debug_log(f"API Request - Params: {next_params}", self.debug)
            response = self.session.get(next_url, params=next_params)
            debug_log(f"API Response - Status: {response.status_code}", self.debug)
            debug_log(f"API Response - Headers: {dict(response.headers)}", self.debug)
            if response.status_code != 200:
                debug_log(f"API Response - Error body: {response.text}", self.debug)
                
            # Handle specific error cases
            if response.status_code == 404:
                debug_log(f"Organization {org_id} not found with API version {version}", self.debug)
                return None
            elif response.status_code == 403:
                debug_log(f"Access denied to organization {org_id} with API version {version}", self.debug)
                return None
            elif response.status_code == 401:
                debug_log(f"Authentication failed with API version {version}", self.debug)
                return None
            
            response.raise_for_status()
            data = response.json()

            targets = data.get('data', [])
            all_targets.extend(targets)

            # Handle pagination
            links = data.get('links', {})
            next_url = links.get('next')
            next_params = None

            if next_url:
                if next_url.startswith('http'):
                    pass  # use as-is
                elif next_url.startswith('/'):
                    next_url = self.base_url + next_url
                else:
                    next_url = self.base_url + '/' + next_url.lstrip('/')
            else:
                next_url = None

            page += 1

        print(f"   ✅ Found {len(all_targets)} targets")
        return all_targets

    def get_projects_for_target(self, org_id: str, target_id: str,
                               version: str = "2024-10-15") -> List[Dict]:
        """
        Get all projects for a specific target.

        Args:
            org_id: Organization ID
            target_id: Target ID
            version: API version

        Returns:
            List of all projects for the target
        """
        print(f"📁 Fetching projects for target {target_id}...")

        url = f"{self.base_url}/rest/orgs/{org_id}/projects"
        params = {
            'version': version,
            'target_id': target_id,
            'limit': 100
        }

        all_projects = []
        next_url = url
        next_params = params
        page = 1

        while next_url:
            print(f"   📄 Fetching projects page {page}...")
            debug_log(f"API Request - URL: {next_url}", self.debug)
            debug_log(f"API Request - Params: {next_params}", self.debug)
            response = self.session.get(next_url, params=next_params)
            debug_log(f"API Response - Status: {response.status_code}", self.debug)
            debug_log(f"API Response - Headers: {dict(response.headers)}", self.debug)
            if response.status_code != 200:
                debug_log(f"API Response - Error body: {response.text}", self.debug)
            response.raise_for_status()
            data = response.json()

            projects = data.get('data', [])
            all_projects.extend(projects)

            # Handle pagination
            links = data.get('links', {})
            next_url = links.get('next')
            next_params = None

            if next_url:
                if next_url.startswith('http'):
                    pass  # use as-is
                elif next_url.startswith('/'):
                    next_url = self.base_url + next_url
                else:
                    next_url = self.base_url + '/' + next_url.lstrip('/')
            else:
                next_url = None

            page += 1

        print(f"   ✅ Found {len(all_projects)} projects")
        return all_projects

    def get_project_details(self, org_id: str, project_id: str, 
                           version: str = "2024-10-15") -> Optional[Dict]:
        """
        Get detailed information for a specific project.

        Args:
            org_id: Organization ID
            project_id: Project ID
            version: API version

        Returns:
            Dictionary containing the project details or None if failed
        """
        url = f"{self.base_url}/rest/orgs/{org_id}/projects/{project_id}"
        params = {
            'version': version
        }

        try:
            debug_log(f"API Request - URL: {url}", self.debug)
            debug_log(f"API Request - Params: {params}", self.debug)
            response = self.session.get(url, params=params)
            debug_log(f"API Response - Status: {response.status_code}", self.debug)
            debug_log(f"API Response - Headers: {dict(response.headers)}", self.debug)
            if response.status_code != 200:
                debug_log(f"API Response - Error body: {response.text}", self.debug)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Error fetching project details for {project_id}: {e}")
            debug_log(f"API Error - Project ID: {project_id}, Error: {e}", self.debug)
            return None


class GitLabClient:
    """Client for accessing GitLab repositories."""

    def __init__(self, gitlab_token: Optional[str] = None, gitlab_url: str = "https://gitlab.com", debug: bool = False):
        self.gitlab_token = gitlab_token
        self.gitlab_url = gitlab_url.rstrip('/')
        self.debug = debug
        self.session = requests.Session()
        
        if gitlab_token:
            self.session.headers.update({'Authorization': f'Bearer {gitlab_token}'})

    def parse_repo_url(self, url: str) -> Optional[Dict]:
        """
        Parse repository URL to extract owner, repo, and branch information.
        Supports GitLab integration projects and CLI projects with various URL formats.

        Args:
            url: Repository URL (GitLab, GitHub, Bitbucket, local paths, etc.)

        Returns:
            Dictionary with owner, repo, and branch info or None
        """
        debug_log(f"Parsing URL: {url}", self.debug)
        
        if not url:
            debug_log("URL is empty or None", self.debug)
            return None

        # Handle CLI projects with local file paths
        if url.startswith('file://'):
            debug_log("URL type detection - starts with file://", self.debug)
            result = {
                'platform': 'local',
                'host': 'local',
                'owner': 'local',
                'repo': url.replace('file://', ''),
                'branch': 'main',
                'is_local': True
            }
            debug_log(f"Successfully parsed URL - Platform: {result['platform']}, Owner: {result['owner']}, Repo: {result['repo']}", self.debug)
            return result
        
        # Handle CLI projects with absolute paths
        if url.startswith('/') and not url.startswith('//'):
            debug_log("URL type detection - starts with / (absolute path)", self.debug)
            result = {
                'platform': 'local',
                'host': 'local',
                'owner': 'local',
                'repo': url,
                'branch': 'main',
                'is_local': True
            }
            debug_log(f"Successfully parsed URL - Platform: {result['platform']}, Owner: {result['owner']}, Repo: {result['repo']}", self.debug)
            return result

        # Handle SSH URLs (git@host:owner/repo.git)
        ssh_pattern = r'git@([^:]+):([^/]+)/([^/]+?)(?:\.git)?$'
        ssh_match = re.match(ssh_pattern, url)
        debug_log(f"SSH pattern match result: {bool(ssh_match)}", self.debug)
        if ssh_match:
            host, owner, repo = ssh_match.groups()
            result = {
                'platform': 'git' if 'gitlab' in host else 'git',
                'host': host,
                'owner': owner,
                'repo': repo,
                'branch': 'main',
                'is_ssh': True
            }
            debug_log(f"Successfully parsed URL - Platform: {result['platform']}, Owner: {result['owner']}, Repo: {result['repo']}", self.debug)
            return result

        # GitHub URL patterns (for CLI projects that might reference GitHub) - check first
        github_patterns = [
            r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/tree/([^/]+))?/?$',
            r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/blob/([^/]+))?/?$',
        ]

        for i, pattern in enumerate(github_patterns):
            match = re.match(pattern, url)
            debug_log(f"GitHub pattern {i+1} match result: {bool(match)}", self.debug)
            if match:
                groups = match.groups()
                result = {
                    'platform': 'github',
                    'host': 'github.com',
                    'owner': groups[0],
                    'repo': groups[1],
                    'branch': groups[2] if len(groups) > 2 and groups[2] else 'main'
                }
                debug_log(f"Successfully parsed URL - Platform: {result['platform']}, Owner: {result['owner']}, Repo: {result['repo']}", self.debug)
                return result

        # Bitbucket URL patterns (for CLI projects that might reference Bitbucket) - check second
        bitbucket_patterns = [
            r'https?://bitbucket\.org/([^/]+)/([^/]+?)(?:\.git)?(?:/src/([^/]+))?/?$',
        ]

        for i, pattern in enumerate(bitbucket_patterns):
            match = re.match(pattern, url)
            debug_log(f"Bitbucket pattern {i+1} match result: {bool(match)}", self.debug)
            if match:
                groups = match.groups()
                result = {
                    'platform': 'bitbucket',
                    'host': 'bitbucket.org',
                    'owner': groups[0],
                    'repo': groups[1],
                    'branch': groups[2] if len(groups) > 2 and groups[2] else 'main'
                }
                debug_log(f"Successfully parsed URL - Platform: {result['platform']}, Owner: {result['owner']}, Repo: {result['repo']}", self.debug)
                return result

        # GitLab URL patterns (including new format) - check last to avoid conflicts
        gitlab_patterns = [
            # GitLab.com patterns - support subgroups (multiple path segments)
            # Pattern: host/group/subgroup/project/tree/branch
            # First try to match URLs with /tree/branch - this helps distinguish project from branch
            r'https?://gitlab\.com/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/tree/([^/]+)/?$',
            r'https?://gitlab\.com/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/-/tree/([^/]+)/?$',
            r'https?://gitlab\.com/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/-/blob/([^/]+)/.*/?$',
            # Then match URLs without /tree/branch
            r'https?://gitlab\.com/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/?$',
            # Custom GitLab instance patterns - support subgroups
            r'https?://([^/]+\.gitlab\.com)/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/tree/([^/]+)/?$',
            r'https?://([^/]+\.gitlab\.com)/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/-/tree/([^/]+)/?$',
            r'https?://([^/]+\.gitlab\.com)/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/-/blob/([^/]+)/.*/?$',
            r'https?://([^/]+\.gitlab\.com)/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/?$',
            # Generic GitLab instance patterns - support subgroups
            r'https?://(?!github\.com|bitbucket\.org)([^/]+)/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/tree/([^/]+)/?$',
            r'https?://(?!github\.com|bitbucket\.org)([^/]+)/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/-/tree/([^/]+)/?$',
            r'https?://(?!github\.com|bitbucket\.org)([^/]+)/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/-/blob/([^/]+)/.*/?$',
            r'https?://(?!github\.com|bitbucket\.org)([^/]+)/([^/]+(?:/[^/]+)*)/([^/]+?)(?:\.git)?/?$',
        ]

        for i, pattern in enumerate(gitlab_patterns):
            match = re.match(pattern, url)
            debug_log(f"GitLab pattern {i+1} match result: {bool(match)}", self.debug)
            if match:
                groups = match.groups()
                if url.startswith('https://gitlab.com/') or url.startswith('http://gitlab.com/'):
                    # For GitLab.com: groups[0] = full path (including subgroups), groups[1] = repo, groups[2] = branch
                    full_path = groups[0]  # e.g., "customer-success-engineers/business"
                    repo_name = groups[1]  # e.g., "IBM-Developer"
                    
                    # Determine if this pattern has a branch (patterns 0-2, 4-6, 8-10 have branches)
                    has_branch = i in [0, 1, 2, 4, 5, 6, 8, 9, 10]
                    branch = groups[2] if has_branch and len(groups) > 2 and groups[2] else 'main'
                    
                    result = {
                        'platform': 'gitlab',
                        'host': 'gitlab.com',
                        'owner': full_path,  # Full path including subgroups
                        'repo': repo_name,
                        'branch': branch
                    }
                    debug_log(f"Successfully parsed URL - Platform: {result['platform']}, Owner: {result['owner']}, Repo: {result['repo']}", self.debug)
                    return result
                else:
                    # For custom GitLab instances: groups[0] = host, groups[1] = full path, groups[2] = repo, groups[3] = branch
                    full_path = groups[1]  # e.g., "customer-success-engineers/business"
                    repo_name = groups[2]  # e.g., "IBM-Developer"
                    
                    # Determine if this pattern has a branch (patterns 4-6, 8-10 have branches)
                    has_branch = i in [4, 5, 6, 8, 9, 10]
                    branch = groups[3] if has_branch and len(groups) > 3 and groups[3] else 'main'
                    
                    result = {
                        'platform': 'gitlab',
                        'host': groups[0],
                        'owner': full_path,  # Full path including subgroups
                        'repo': repo_name,
                        'branch': branch
                    }
                    debug_log(f"Successfully parsed URL - Platform: {result['platform']}, Owner: {result['owner']}, Repo: {result['repo']}", self.debug)
                    return result

        debug_log(f"Failed to parse URL with any pattern - URL: {url}", self.debug)
        return None

    def get_default_branch(self, repo_info: Dict) -> str:
        """
        Get the default branch for a GitLab repository.

        Args:
            repo_info: Repository information

        Returns:
            Default branch name or 'main' as fallback
        """
        if repo_info.get('is_local'):
            return 'main'
        
        if repo_info['platform'] == 'gitlab':
            try:
                project_path = f"{repo_info['owner']}%2F{repo_info['repo']}"
                url = f"{self.gitlab_url}/api/v4/projects/{project_path}"
                debug_log(f"GitLab API Request - URL: {url}", self.debug)
                
                response = self.session.get(url)
                debug_log(f"GitLab API Response - Status: {response.status_code}", self.debug)
                debug_log(f"GitLab API Response - Headers: {dict(response.headers)}", self.debug)
                if response.status_code != 200:
                    debug_log(f"GitLab API Response - Error body: {response.text}", self.debug)
                
                if response.status_code == 200:
                    data = response.json()
                    default_branch = data.get('default_branch', 'main')
                    print(f"   🌿 Using default branch: {default_branch}")
                    debug_log(f"Successfully retrieved default branch: {default_branch}", self.debug)
                    return default_branch
                else:
                    print(f"   ⚠️  Could not get default branch, using 'main'")
                    debug_log(f"Could not get default branch, status: {response.status_code}", self.debug)
                    return 'main'
            except Exception as e:
                print(f"   ⚠️  Error getting default branch: {e}, using 'main'")
                debug_log(f"Error getting default branch: {e}", self.debug)
                return 'main'
        
        # For other platforms, return the branch from repo_info or default to 'main'
        return repo_info.get('branch', 'main')

    def get_file_content(self, repo_info: Dict, file_path: str) -> Optional[str]:
        """
        Get file content from repository (GitLab, GitHub, Bitbucket, or local).

        Args:
            repo_info: Repository information from parse_repo_url
            file_path: Path to the file in the repository

        Returns:
            File content as string or None if not found
        """
        if not repo_info:
            return None

        # Handle local files for CLI projects
        if repo_info.get('is_local'):
            try:
                import os
                full_path = os.path.join(repo_info['repo'], file_path)
                if os.path.exists(full_path):
                    with open(full_path, 'r', encoding='utf-8') as f:
                        return f.read()
                return None
            except Exception as e:
                print(f"   ❌ Error reading local file {file_path}: {e}")
                return None

        # Handle GitLab repositories
        if repo_info['platform'] == 'gitlab':
            try:
                # Use GitLab API to get file content
                # For subgroups, owner already contains the full path (e.g., "customer-success-engineers/business")
                project_path = f"{repo_info['owner']}%2F{repo_info['repo']}"
                # Get the actual default branch instead of using the hardcoded one
                default_branch = self.get_default_branch(repo_info)
                url = f"{self.gitlab_url}/api/v4/projects/{project_path}/repository/files/{file_path.replace('/', '%2F')}/raw"
                params = {
                    'ref': default_branch
                }
                debug_log(f"Attempting to access file: {file_path}", self.debug)
                debug_log(f"Using repository info: {repo_info}", self.debug)
                debug_log(f"GitLab project path: {project_path}", self.debug)
                debug_log(f"GitLab default branch: {default_branch}", self.debug)
                debug_log(f"API URL being called: {url}", self.debug)
                debug_log(f"API parameters: {params}", self.debug)

                response = self.session.get(url, params=params)
                debug_log(f"API response status: {response.status_code}", self.debug)
                debug_log(f"API response headers: {dict(response.headers)}", self.debug)
                if response.status_code != 200:
                    debug_log(f"API response error body: {response.text}", self.debug)
                
                if response.status_code == 200:
                    return response.text
                elif response.status_code == 404:
                    return None
                else:
                    response.raise_for_status()

            except Exception as e:
                print(f"   ❌ Error fetching GitLab file {file_path}: {e}")
                debug_log(f"Error fetching GitLab file {file_path}: {e}", self.debug)
                return None

        # Handle GitHub repositories (for CLI projects)
        elif repo_info['platform'] == 'github':
            try:
                url = f"https://api.github.com/repos/{repo_info['owner']}/{repo_info['repo']}/contents/{file_path}"
                params = {
                    'ref': repo_info['branch']
                }

                response = self.session.get(url, params=params)
                if response.status_code == 200:
                    import base64
                    data = response.json()
                    content = base64.b64decode(data['content']).decode('utf-8')
                    return content
                elif response.status_code == 404:
                    return None
                else:
                    response.raise_for_status()

            except Exception as e:
                print(f"   ❌ Error fetching GitHub file {file_path}: {e}")
                return None

        # Handle Bitbucket repositories (for CLI projects)
        elif repo_info['platform'] == 'bitbucket':
            try:
                url = f"https://api.bitbucket.org/2.0/repositories/{repo_info['owner']}/{repo_info['repo']}/src/{repo_info['branch']}/{file_path}"
                response = self.session.get(url)
                if response.status_code == 200:
                    return response.text
                elif response.status_code == 404:
                    return None
                else:
                    response.raise_for_status()

            except Exception as e:
                print(f"   ❌ Error fetching Bitbucket file {file_path}: {e}")
                return None

        return None

    def check_file_exists(self, repo_info: Dict, file_path: str) -> bool:
        """
        Check if a file exists in repository (GitLab, GitHub, Bitbucket, or local).

        Args:
            repo_info: Repository information from parse_repo_url
            file_path: Path to the file in the repository

        Returns:
            True if file exists, False otherwise
        """
        if not repo_info:
            return False

        # Handle local files for CLI projects
        if repo_info.get('is_local'):
            try:
                import os
                full_path = os.path.join(repo_info['repo'], file_path)
                return os.path.exists(full_path)
            except Exception as e:
                print(f"   ❌ Error checking local file {file_path}: {e}")
                return False

        # Handle GitLab repositories
        if repo_info['platform'] == 'gitlab':
            try:
                # Use GitLab API to check if file exists
                # For subgroups, owner already contains the full path (e.g., "customer-success-engineers/business")
                project_path = f"{repo_info['owner']}%2F{repo_info['repo']}"
                # Get the actual default branch instead of using the hardcoded one
                default_branch = self.get_default_branch(repo_info)
                url = f"{self.gitlab_url}/api/v4/projects/{project_path}/repository/files/{file_path.replace('/', '%2F')}"
                params = {
                    'ref': default_branch
                }
                debug_log(f"Checking if file exists: {file_path}", self.debug)
                debug_log(f"Using repository info: {repo_info}", self.debug)
                debug_log(f"GitLab project path: {project_path}", self.debug)
                debug_log(f"GitLab default branch: {default_branch}", self.debug)
                debug_log(f"API URL being called: {url}", self.debug)
                debug_log(f"API parameters: {params}", self.debug)

                response = self.session.get(url, params=params)
                debug_log(f"API response status: {response.status_code}", self.debug)
                debug_log(f"API response headers: {dict(response.headers)}", self.debug)
                if response.status_code != 200:
                    debug_log(f"API response error body: {response.text}", self.debug)
                
                if response.status_code == 200:
                    return True
                elif response.status_code == 404:
                    return False
                else:
                    response.raise_for_status()

            except Exception as e:
                print(f"   ❌ Error checking GitLab file {file_path}: {e}")
                debug_log(f"Error checking GitLab file {file_path}: {e}", self.debug)
                return False

        # Handle GitHub repositories (for CLI projects)
        elif repo_info['platform'] == 'github':
            try:
                url = f"https://api.github.com/repos/{repo_info['owner']}/{repo_info['repo']}/contents/{file_path}"
                params = {
                    'ref': repo_info['branch']
                }

                response = self.session.get(url, params=params)
                if response.status_code == 200:
                    return True
                elif response.status_code == 404:
                    return False
                else:
                    response.raise_for_status()

            except Exception as e:
                print(f"   ❌ Error checking GitHub file {file_path}: {e}")
                return False

        # Handle Bitbucket repositories (for CLI projects)
        elif repo_info['platform'] == 'bitbucket':
            try:
                url = f"https://api.bitbucket.org/2.0/repositories/{repo_info['owner']}/{repo_info['repo']}/src/{repo_info['branch']}/{file_path}"
                response = self.session.get(url)
                if response.status_code == 200:
                    return True
                elif response.status_code == 404:
                    return False
                else:
                    response.raise_for_status()

            except Exception as e:
                print(f"   ❌ Error checking Bitbucket file {file_path}: {e}")
                return False

        return False


class SCAValidator:
    """Main class for validating Snyk SCA files against GitLab repositories."""
    
    # Comprehensive matrix of all Snyk-supported files
    SNYK_SUPPORTED_FILES = {
        'sca': {
            'javascript': [
                'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
                'bower.json', '.bowerrc', 'component.json', 'bower-components.json'
            ],
            'python': [
                'requirements.txt', 'requirements-dev.txt', 'requirements-test.txt',
                'setup.py', 'pyproject.toml', 'Pipfile', 'Pipfile.lock',
                'poetry.lock', 'environment.yml', 'conda.yml'
            ],
            'java': [
                'pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.properties',
                'build.xml', 'ivy.xml', 'build.sbt', 'project/build.properties'
            ],
            'ruby': [
                'Gemfile', 'Gemfile.lock', 'gemspec', 'Gemfile.local'
            ],
            'php': [
                'composer.json', 'composer.lock', 'composer-require-checker.json'
            ],
            'dotnet': [
                'packages.config', 'project.json', '*.csproj', '*.vbproj',
                '*.fsproj', 'project.assets.json', 'packages.lock.json'
            ],
            'go': [
                'go.mod', 'go.sum', 'Gopkg.toml', 'Gopkg.lock', 'glide.yaml', 'glide.lock'
            ],
            'rust': [
                'Cargo.toml', 'Cargo.lock'
            ],
            'swift': [
                'Package.swift', 'Podfile', 'Podfile.lock', 'Cartfile', 'Cartfile.resolved'
            ],
            'scala': [
                'build.sbt', 'project/build.properties', 'project/plugins.sbt'
            ],
            'dart': [
                'pubspec.yaml', 'pubspec.lock'
            ],
            'elixir': [
                'mix.exs', 'mix.lock'
            ],
            'groovy': [
                'build.gradle', 'build.gradle.kts'
            ],
            'cpp': [
                'conanfile.txt', 'conanfile.py', 'vcpkg.json', 'vcpkg-configuration.json'
            ],
            'apex': [
                'sfdx-project.json', 'package.json'
            ]
        },
        'container': [
            'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            'Containerfile', '.dockerignore', 'docker-compose.override.yml',
            'docker-compose.override.yaml'
        ],
        'iac': {
            'terraform': [
                '*.tf', '*.tf.json', '*.tfvars', '*.tfvars.json',
                'terraform.tfvars', 'terraform.tfvars.json'
            ],
            'cloudformation': [
                '*.template', '*.template.json', '*.yaml', '*.yml',
                'template.yaml', 'template.yml'
            ],
            'kubernetes': [
                '*.yaml', '*.yml', 'kustomization.yaml', 'kustomization.yml'
            ],
            'helm': [
                'Chart.yaml', 'values.yaml', 'values.yml', 'requirements.yaml',
                'requirements.yml', 'requirements.lock'
            ],
            'arm': [
                '*.json', '*.bicep'
            ],
            'cdk': [
                'cdk.json', 'package.json', 'requirements.txt', 'Pipfile'
            ],
            'serverless': [
                'serverless.yml', 'serverless.yaml', 'serverless.json',
                'sam.yaml', 'sam.yml', 'template.yaml', 'template.yml'
            ],
            'pulumi': [
                'Pulumi.yaml', 'Pulumi.yml', 'Pulumi.*.yaml'
            ]
        }
    }

    def __init__(self, snyk_api: SnykAPI, gitlab_client: GitLabClient, debug: bool = False):
        self.snyk_api = snyk_api
        self.gitlab_client = gitlab_client
        self.debug = debug
        self.validation_results = []

    def validate_organization(self, org_id: str) -> Dict:
        """
        Validate all SCA files for a specific organization.

        Args:
            org_id: Snyk organization ID

        Returns:
            Dictionary with validation results
        """
        print(f"\n🔍 Validating organization {org_id}...")

        # First validate that the organization is accessible
        if not self.snyk_api.validate_organization_access(org_id):
            print(f"   ⚠️  Skipping organization {org_id} - not accessible")
            return {
                'org_id': org_id,
                'targets_processed': 0,
                'projects_processed': 0,
                'files_validated': 0,
                'files_missing': 0,
                'files_present': 0,
                'targets': [],
                'error': 'Organization not accessible'
            }

        # Get all targets for the organization
        targets = self.snyk_api.get_targets_for_org(org_id)
        
        org_results = {
            'org_id': org_id,
            'targets_processed': 0,
            'projects_processed': 0,
            'files_validated': 0,
            'files_missing': 0,
            'files_present': 0,
            'targets': []
        }

        for target in targets:
            target_result = self.validate_target(org_id, target)
            org_results['targets'].append(target_result)
            org_results['targets_processed'] += 1
            org_results['projects_processed'] += target_result['projects_processed']
            org_results['files_validated'] += target_result['files_validated']
            org_results['files_missing'] += target_result['files_missing']
            org_results['files_present'] += target_result['files_present']

        return org_results

    def validate_target(self, org_id: str, target: Dict) -> Dict:
        """
        Validate all SCA files for a specific target.

        Args:
            org_id: Snyk organization ID
            target: Target information from Snyk API

        Returns:
            Dictionary with validation results for the target
        """
        target_id = target.get('id')
        target_attrs = target.get('attributes', {})
        target_url = target_attrs.get('url')
        target_name = target_attrs.get('display_name', target_id)

        print(f"\n🎯 Validating target: {target_name}")
        print(f"   📍 URL: {target_url}")
        
        debug_log(f"Processing target ID: {target_id}", self.debug)
        debug_log(f"Target attributes: {target_attrs}", self.debug)
        debug_log(f"Target URL from attributes: {target_url}", self.debug)
        debug_log(f"Target display name: {target_name}", self.debug)

        # Parse repository information
        repo_info = self.gitlab_client.parse_repo_url(target_url)
        if not repo_info:
            print(f"   ⚠️  Could not parse repository URL: {target_url}")
            debug_log(f"Repository mapping FAILED for URL: {target_url}", self.debug)
            debug_log(f"This target will be skipped", self.debug)
            return {
                'target_id': target_id,
                'target_name': target_name,
                'target_url': target_url,
                'error': 'Could not parse repository URL',
                'projects_processed': 0,
                'files_validated': 0,
                'files_missing': 0,
                'files_present': 0,
                'projects': []
            }
        
        debug_log(f"Repository mapping successful", self.debug)
        debug_log(f"Mapped to platform: {repo_info['platform']}", self.debug)
        debug_log(f"Mapped to host: {repo_info['host']}", self.debug)
        debug_log(f"Mapped to owner: {repo_info['owner']}", self.debug)
        debug_log(f"Mapped to repo: {repo_info['repo']}", self.debug)
        debug_log(f"Mapped to branch: {repo_info['branch']}", self.debug)

        print(f"   🔗 Platform: {repo_info['platform']}")
        if repo_info.get('is_local'):
            print(f"   📁 Local Path: {repo_info['repo']}")
        else:
            print(f"   📂 Owner: {repo_info['owner']}")
            print(f"   📁 Repo: {repo_info['repo']}")
            print(f"   🌿 Branch: {repo_info['branch']}")
        
        # Handle different platforms
        if repo_info['platform'] == 'local':
            print(f"   ℹ️  CLI project with local files - will check local filesystem")
        elif repo_info['platform'] == 'github':
            print(f"   ℹ️  CLI project referencing GitHub - will use GitHub API")
        elif repo_info['platform'] == 'bitbucket':
            print(f"   ℹ️  CLI project referencing Bitbucket - will use Bitbucket API")
        elif repo_info['platform'] == 'gitlab':
            print(f"   ℹ️  GitLab integration project - will use GitLab API")

        # Get all projects for this target
        projects = self.snyk_api.get_projects_for_target(org_id, target_id)

        target_result = {
            'target_id': target_id,
            'target_name': target_name,
            'target_url': target_url,
            'repo_info': repo_info,
            'projects_processed': 0,
            'files_validated': 0,
            'files_missing': 0,
            'files_present': 0,
            'projects': []
        }

        for project in projects:
            project_result = self.validate_project(org_id, project, repo_info)
            target_result['projects'].append(project_result)
            target_result['projects_processed'] += 1
            target_result['files_validated'] += project_result['files_validated']
            target_result['files_missing'] += project_result['files_missing']
            target_result['files_present'] += project_result['files_present']

        # Detect missing Snyk files
        try:
            print(f"\n🔍 Scanning repository for missing Snyk files...")
            missing_files_result = self.detect_missing_snyk_files(org_id, target, repo_info)
            target_result['missing_snyk_files'] = missing_files_result
        except Exception as e:
            print(f"   ⚠️  Error detecting missing files: {e}")
            target_result['missing_snyk_files'] = {
                'error': str(e),
                'total_supported_files': 0,
                'currently_tracked': 0,
                'missing_files': [],
                'missing_count': 0
            }

        return target_result

    def validate_project(self, org_id: str, project: Dict, repo_info: Dict) -> Dict:
        """
        Validate SCA files for a specific project.

        Args:
            org_id: Snyk organization ID
            project: Project information from Snyk API
            repo_info: Repository information

        Returns:
            Dictionary with validation results for the project
        """
        project_id = project.get('id')
        project_attrs = project.get('attributes', {})
        project_name = project_attrs.get('name', project_id)
        project_type = project_attrs.get('type')

        print(f"\n📁 Validating project: {project_name} ({project_type})")
        
        debug_log(f"Validating project {project_name} against repository", self.debug)
        debug_log(f"Project type: {project_type}", self.debug)
        debug_log(f"Repository being checked: {repo_info['platform']} - {repo_info['owner']}/{repo_info['repo']}", self.debug)

        # Get detailed project information
        project_details = self.snyk_api.get_project_details(org_id, project_id)
        if not project_details:
            print(f"   ❌ Could not get project details for {project_id}")
            debug_log(f"Could not get project details for {project_id}", self.debug)
            return {
                'project_id': project_id,
                'project_name': project_name,
                'project_type': project_type,
                'error': 'Could not get project details',
                'files_validated': 0,
                'files_missing': 0,
                'files_present': 0,
                'files': []
            }

        # Extract file information from project details
        project_data = project_details.get('data', {})
        project_attributes = project_data.get('attributes', {})
        
        # Get the root directory and file paths
        root_dir = project_attributes.get('root', '')
        file_paths = self._extract_file_paths_from_project(project_attributes)
        
        debug_log(f"Project root directory: {root_dir}", self.debug)
        debug_log(f"Files to validate: {file_paths}", self.debug)

        project_result = {
            'project_id': project_id,
            'project_name': project_name,
            'project_type': project_type,
            'root_dir': root_dir,
            'files_validated': 0,
            'files_missing': 0,
            'files_present': 0,
            'files': []
        }

        for file_path in file_paths:
            file_result = self.validate_file(repo_info, file_path, root_dir)
            project_result['files'].append(file_result)
            project_result['files_validated'] += 1
            
            if file_result['exists_in_gitlab']:
                project_result['files_present'] += 1
            else:
                project_result['files_missing'] += 1

        return project_result

    def _extract_file_paths_from_project(self, project_attributes: Dict) -> List[str]:
        """
        Extract file paths from project attributes.

        Args:
            project_attributes: Project attributes from Snyk API

        Returns:
            List of file paths that Snyk is actually tracking for this project
        """
        file_paths = []

        # For SCA projects, the key field is 'target_file' which contains the actual file path
        target_file = project_attributes.get('target_file', '')
        if target_file:
            file_paths.append(target_file)
            print(f"   📄 Snyk is tracking file: {target_file}")
        else:
            print(f"   ⚠️  No target_file found in project attributes")

        # Also check for any additional files in the 'files' field if it exists
        if 'files' in project_attributes:
            additional_files = project_attributes['files']
            if isinstance(additional_files, list):
                file_paths.extend(additional_files)
            elif isinstance(additional_files, str):
                file_paths.append(additional_files)

        return list(set(file_paths))  # Remove duplicates

    def get_all_supported_files(self) -> List[str]:
        """
        Get a flat list of all supported file patterns for Snyk.
        
        Returns:
            List of all supported file patterns
        """
        all_files = []
        
        # Add SCA files
        for language, files in self.SNYK_SUPPORTED_FILES['sca'].items():
            all_files.extend(files)
        
        # Add Container files
        all_files.extend(self.SNYK_SUPPORTED_FILES['container'])
        
        # Add IaC files
        for iac_type, files in self.SNYK_SUPPORTED_FILES['iac'].items():
            all_files.extend(files)
        
        return list(set(all_files))  # Remove duplicates

    def scan_repository_for_supported_files(self, repo_info: Dict, max_depth: int = 3) -> List[Dict]:
        """
        Scan repository for all Snyk-supported files.
        
        Args:
            repo_info: Repository information
            max_depth: Maximum directory depth to scan
            
        Returns:
            List of found supported files with metadata
        """
        if repo_info.get('is_local'):
            return self._scan_local_repository(repo_info, max_depth)
        elif repo_info['platform'] == 'gitlab':
            return self._scan_gitlab_repository(repo_info, max_depth)
        elif repo_info['platform'] == 'github':
            return self._scan_github_repository(repo_info, max_depth)
        elif repo_info['platform'] == 'bitbucket':
            return self._scan_bitbucket_repository(repo_info, max_depth)
        else:
            print(f"   ⚠️  Unsupported platform for repository scanning: {repo_info['platform']}")
            return []

    def _scan_local_repository(self, repo_info: Dict, max_depth: int) -> List[Dict]:
        """Scan local repository for supported files."""
        found_files = []
        repo_path = repo_info['repo']
        
        if not os.path.exists(repo_path):
            return found_files
        
        try:
            for root, dirs, files in os.walk(repo_path):
                # Limit depth
                depth = root.replace(repo_path, '').count(os.sep)
                if depth >= max_depth:
                    dirs[:] = []  # Don't go deeper
                    continue
                
                for file in files:
                    if self._is_snyk_supported_file(file):
                        relative_path = os.path.relpath(os.path.join(root, file), repo_path)
                        found_files.append({
                            'file_path': relative_path,
                            'full_path': os.path.join(root, file),
                            'file_type': self._get_file_type(file),
                            'exists': True
                        })
        except Exception as e:
            print(f"   ❌ Error scanning local repository: {e}")
        
        return found_files

    def _scan_gitlab_repository(self, repo_info: Dict, max_depth: int) -> List[Dict]:
        """Scan GitLab repository for supported files using GitLab API."""
        found_files = []
        
        try:
            # Get repository tree
            project_path = f"{repo_info['owner']}%2F{repo_info['repo']}"
            default_branch = self.gitlab_client.get_default_branch(repo_info)
            
            # Get repository tree recursively
            url = f"{self.gitlab_client.gitlab_url}/api/v4/projects/{project_path}/repository/tree"
            params = {
                'ref': default_branch,
                'recursive': 'true',
                'per_page': 100
            }
            
            response = self.gitlab_client.session.get(url, params=params)
            if response.status_code == 200:
                tree_data = response.json()
                
                for item in tree_data:
                    if item['type'] == 'blob':  # It's a file
                        file_name = os.path.basename(item['path'])
                        if self._is_snyk_supported_file(file_name):
                            found_files.append({
                                'file_path': item['path'],
                                'full_path': item['path'],
                                'file_type': self._get_file_type(file_name),
                                'exists': True
                            })
            else:
                print(f"   ⚠️  Could not scan GitLab repository tree: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Error scanning GitLab repository: {e}")
        
        return found_files

    def _scan_github_repository(self, repo_info: Dict, max_depth: int) -> List[Dict]:
        """Scan GitHub repository for supported files using GitHub API."""
        found_files = []
        
        try:
            # Get repository contents recursively
            url = f"https://api.github.com/repos/{repo_info['owner']}/{repo_info['repo']}/git/trees/{repo_info['branch']}"
            params = {'recursive': '1'}
            
            response = self.gitlab_client.session.get(url, params=params)
            if response.status_code == 200:
                tree_data = response.json()
                
                for item in tree_data.get('tree', []):
                    if item['type'] == 'blob':  # It's a file
                        file_name = os.path.basename(item['path'])
                        if self._is_snyk_supported_file(file_name):
                            found_files.append({
                                'file_path': item['path'],
                                'full_path': item['path'],
                                'file_type': self._get_file_type(file_name),
                                'exists': True
                            })
            else:
                print(f"   ⚠️  Could not scan GitHub repository tree: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Error scanning GitHub repository: {e}")
        
        return found_files

    def _scan_bitbucket_repository(self, repo_info: Dict, max_depth: int) -> List[Dict]:
        """Scan Bitbucket repository for supported files using Bitbucket API."""
        found_files = []
        
        try:
            # Get repository files
            url = f"https://api.bitbucket.org/2.0/repositories/{repo_info['owner']}/{repo_info['repo']}/src/{repo_info['branch']}/"
            params = {'pagelen': 100}
            
            response = self.gitlab_client.session.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get('values', []):
                    if item['type'] == 'commit_file':  # It's a file
                        file_name = os.path.basename(item['path'])
                        if self._is_snyk_supported_file(file_name):
                            found_files.append({
                                'file_path': item['path'],
                                'full_path': item['path'],
                                'file_type': self._get_file_type(file_name),
                                'exists': True
                            })
            else:
                print(f"   ⚠️  Could not scan Bitbucket repository: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Error scanning Bitbucket repository: {e}")
        
        return found_files

    def _is_snyk_supported_file(self, filename: str) -> bool:
        """Check if a file is supported by Snyk."""
        all_supported = self.get_all_supported_files()
        
        for pattern in all_supported:
            if pattern.startswith('*.'):
                # Handle wildcard patterns like *.tf, *.yaml
                extension = pattern[1:]
                if filename.endswith(extension):
                    return True
            elif pattern == filename:
                # Exact match
                return True
        
        return False

    def _get_file_type(self, filename: str) -> str:
        """Determine the file type category for a filename."""
        # Check SCA files
        for language, files in self.SNYK_SUPPORTED_FILES['sca'].items():
            for pattern in files:
                if pattern.startswith('*.'):
                    extension = pattern[1:]
                    if filename.endswith(extension):
                        return f"sca_{language}"
                elif pattern == filename:
                    return f"sca_{language}"
        
        # Check Container files
        if filename in self.SNYK_SUPPORTED_FILES['container']:
            return "container"
        
        # Check IaC files
        for iac_type, files in self.SNYK_SUPPORTED_FILES['iac'].items():
            for pattern in files:
                if pattern.startswith('*.'):
                    extension = pattern[1:]
                    if filename.endswith(extension):
                        return f"iac_{iac_type}"
                elif pattern == filename:
                    return f"iac_{iac_type}"
        
        return "unknown"

    def detect_missing_snyk_files(self, org_id: str, target: Dict, repo_info: Dict) -> Dict:
        """
        Detect files that should be tracked by Snyk but are missing from projects.
        
        Args:
            org_id: Organization ID
            target: Target information
            repo_info: Repository information
            
        Returns:
            Dictionary with missing file detection results
        """
        print(f"🔍 Scanning repository for supported files...")
        
        debug_log(f"Scanning repository for supported files", self.debug)
        debug_log(f"Repository platform: {repo_info['platform']}", self.debug)
        debug_log(f"Repository path: {repo_info['owner']}/{repo_info['repo']}", self.debug)
        
        # Get all projects for this target
        projects = self.snyk_api.get_projects_for_target(org_id, target['id'])
        
        # Get all files currently tracked by Snyk
        tracked_files = set()
        for project in projects:
            file_paths = self._extract_file_paths_from_project(project.get('attributes', {}))
            for file_path in file_paths:
                tracked_files.add(file_path)
        
        debug_log(f"Currently tracked files: {list(tracked_files)}", self.debug)
        
        # Scan repository for all supported files
        repo_files = self.scan_repository_for_supported_files(repo_info)
        
        debug_log(f"Found repository files: {[f['file_path'] for f in repo_files]}", self.debug)
        
        # Find missing files
        missing_files = []
        for repo_file in repo_files:
            if repo_file['file_path'] not in tracked_files:
                missing_files.append(repo_file)
        
        debug_log(f"Missing files: {[f['file_path'] for f in missing_files]}", self.debug)
        
        print(f"   📊 Found {len(repo_files)} supported files in repository")
        print(f"   📊 Currently tracking {len(tracked_files)} files in Snyk")
        print(f"   📊 Missing from Snyk: {len(missing_files)} files")
        
        return {
            'total_supported_files': len(repo_files),
            'currently_tracked': len(tracked_files),
            'missing_files': missing_files,
            'missing_count': len(missing_files)
        }

    def validate_file(self, repo_info: Dict, file_path: str, root_dir: str = "") -> Dict:
        """
        Validate if a specific file exists in the GitLab repository.

        Args:
            repo_info: Repository information
            file_path: Path to the file
            root_dir: Root directory of the project

        Returns:
            Dictionary with file validation results
        """
        # Construct full file path
        if root_dir and not file_path.startswith(root_dir):
            full_path = f"{root_dir}/{file_path}".strip('/')
        else:
            full_path = file_path

        print(f"   📄 Checking file: {full_path}")

        # Check if file exists in GitLab
        exists_in_gitlab = self.gitlab_client.check_file_exists(repo_info, full_path)

        result = {
            'file_path': file_path,
            'full_path': full_path,
            'exists_in_gitlab': exists_in_gitlab,
            'last_checked': datetime.now().isoformat()
        }

        if exists_in_gitlab:
            print(f"      ✅ File exists in GitLab")
        else:
            print(f"      ❌ File missing from GitLab")

        return result

    def generate_report(self, results: List[Dict]) -> str:
        """
        Generate a comprehensive validation report.

        Args:
            results: List of validation results

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append("SNYK SCA FILE VALIDATION REPORT - COMPREHENSIVE EDITION")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        total_orgs = len(results)
        total_targets = sum(r['targets_processed'] for r in results)
        total_projects = sum(r['projects_processed'] for r in results)
        total_files = sum(r['files_validated'] for r in results)
        total_missing = sum(r['files_missing'] for r in results)
        total_present = sum(r['files_present'] for r in results)

        # Calculate missing Snyk files (per repository, not aggregated)
        total_missing_snyk = 0
        total_supported_files = 0
        repositories_with_coverage = 0
        total_coverage_percentage = 0
        
        for org_result in results:
            for target_result in org_result['targets']:
                if 'missing_snyk_files' in target_result and target_result['missing_snyk_files']:
                    missing_data = target_result['missing_snyk_files']
                    if 'error' not in missing_data:
                        missing_count = missing_data.get('missing_count', 0)
                        supported_count = missing_data.get('total_supported_files', 0)
                        tracked_count = missing_data.get('currently_tracked', 0)
                        
                        total_missing_snyk += missing_count
                        total_supported_files += supported_count
                        
                        # Calculate coverage for this repository
                        if supported_count > 0:
                            repositories_with_coverage += 1
                            repo_coverage = (tracked_count / supported_count) * 100
                            total_coverage_percentage += repo_coverage

        report.append("SUMMARY")
        report.append("-" * 40)
        report.append(f"Organizations processed: {total_orgs}")
        report.append(f"Targets processed: {total_targets}")
        report.append(f"Projects processed: {total_projects}")
        report.append(f"Files validated: {total_files}")
        report.append(f"Files present in GitLab: {total_present}")
        report.append(f"Files missing from GitLab: {total_missing}")
        
        if total_files > 0:
            missing_percentage = (total_missing / total_files) * 100
            report.append(f"Missing files percentage: {missing_percentage:.1f}%")
        
        report.append("")
        report.append("MISSING SNYK FILES DETECTION")
        report.append("-" * 40)
        report.append(f"Repositories with supported files: {repositories_with_coverage}")
        report.append(f"Total supported files found: {total_supported_files}")
        report.append(f"Total files missing from Snyk: {total_missing_snyk}")
        if repositories_with_coverage > 0:
            average_coverage = total_coverage_percentage / repositories_with_coverage
            report.append(f"Average Snyk coverage: {average_coverage:.1f}%")
        report.append("")
        report.append("Note: Coverage is calculated per repository. Files tracked by Snyk")
        report.append("may be from different repositories than those with missing files.")
        
        report.append("")

        # Detailed results by organization
        for org_result in results:
            report.append(f"ORGANIZATION: {org_result['org_id']}")
            report.append("-" * 40)
            report.append(f"Targets: {org_result['targets_processed']}")
            report.append(f"Projects: {org_result['projects_processed']}")
            report.append(f"Files validated: {org_result['files_validated']}")
            report.append(f"Files missing: {org_result['files_missing']}")
            report.append("")

            for target_result in org_result['targets']:
                if 'error' in target_result:
                    report.append(f"  TARGET: {target_result['target_name']} - ERROR: {target_result['error']}")
                    continue

                report.append(f"  TARGET: {target_result['target_name']}")
                report.append(f"    URL: {target_result['target_url']}")
                report.append(f"    Projects: {target_result['projects_processed']}")
                report.append(f"    Files missing: {target_result['files_missing']}")
                
                # Add missing Snyk files information
                if 'missing_snyk_files' in target_result and target_result['missing_snyk_files']:
                    missing_data = target_result['missing_snyk_files']
                    if 'error' not in missing_data:
                        report.append(f"    Supported files in repo: {missing_data.get('total_supported_files', 0)}")
                        report.append(f"    Currently tracked by Snyk: {missing_data.get('currently_tracked', 0)}")
                        report.append(f"    Missing from Snyk: {missing_data.get('missing_count', 0)}")
                        
                        # List some missing files (limit to first 10)
                        missing_files = missing_data.get('missing_files', [])
                        if missing_files:
                            report.append("    Missing Snyk files (first 10):")
                            for i, file_info in enumerate(missing_files[:10]):
                                file_type = file_info.get('file_type', 'unknown')
                                report.append(f"      - {file_info['file_path']} ({file_type})")
                            if len(missing_files) > 10:
                                report.append(f"      ... and {len(missing_files) - 10} more files")
                    else:
                        report.append(f"    Missing file detection error: {missing_data['error']}")
                
                report.append("")

                for project_result in target_result['projects']:
                    if 'error' in project_result:
                        report.append(f"    PROJECT: {project_result['project_name']} - ERROR: {project_result['error']}")
                        continue

                    report.append(f"    PROJECT: {project_result['project_name']} ({project_result['project_type']})")
                    report.append(f"      Root: {project_result['root_dir']}")
                    report.append(f"      Files missing: {project_result['files_missing']}")
                    
                    # List missing files
                    missing_files = [f for f in project_result['files'] if not f['exists_in_gitlab']]
                    if missing_files:
                        report.append("      Missing files:")
                        for file_info in missing_files:
                            report.append(f"        - {file_info['full_path']}")
                    
                    report.append("")

        return "\n".join(report)

    def save_results_to_csv(self, results: List[Dict], filename: str):
        """Save validation results to CSV file."""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'org_id', 'target_id', 'target_name', 'target_url', 'project_id',
                    'project_name', 'project_type', 'root_dir', 'file_path', 'full_path',
                    'exists_in_gitlab', 'last_checked'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for org_result in results:
                    for target_result in org_result['targets']:
                        if 'error' in target_result:
                            continue
                            
                        for project_result in target_result['projects']:
                            if 'error' in project_result:
                                continue
                                
                            for file_result in project_result['files']:
                                row = {
                                    'org_id': org_result['org_id'],
                                    'target_id': target_result['target_id'],
                                    'target_name': target_result['target_name'],
                                    'target_url': target_result['target_url'],
                                    'project_id': project_result['project_id'],
                                    'project_name': project_result['project_name'],
                                    'project_type': project_result['project_type'],
                                    'root_dir': project_result['root_dir'],
                                    'file_path': file_result['file_path'],
                                    'full_path': file_result['full_path'],
                                    'exists_in_gitlab': file_result['exists_in_gitlab'],
                                    'last_checked': file_result['last_checked']
                                }
                                writer.writerow(row)

            print(f"✅ Saved validation results to {filename}")

        except Exception as e:
            print(f"❌ Error saving CSV file: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Validate Snyk SCA files against GitLab repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

1. Validate all organizations:
  %(prog)s --snyk-token YOUR_TOKEN

2. Validate specific organization:
  %(prog)s --snyk-token YOUR_TOKEN --org-id ORG_ID

3. With GitLab token for private repos:
  %(prog)s --snyk-token YOUR_TOKEN --gitlab-token GITLAB_TOKEN

4. Custom GitLab instance:
  %(prog)s --snyk-token YOUR_TOKEN --gitlab-url https://gitlab.company.com
        """
    )

    parser.add_argument('--snyk-token', required=True,
                       help='Snyk API token')
    parser.add_argument('--org-id',
                       help='Specific Snyk organization ID to validate (optional)')
    parser.add_argument('--snyk-region', default='SNYK-US-01',
                       help='Snyk API region (default: SNYK-US-01)')
    parser.add_argument('--snyk-api-version', default='2024-10-15',
                       help='Snyk API version (default: 2024-10-15)')
    parser.add_argument('--gitlab-token',
                       help='GitLab API token for private repositories')
    parser.add_argument('--gitlab-url', default='https://gitlab.com',
                       help='GitLab instance URL (default: https://gitlab.com)')
    parser.add_argument('--output-csv', default='validation_results.csv',
                       help='Save results to CSV file (default: validation_results.csv)')
    parser.add_argument('--output-report', default='validation_report.txt',
                       help='Save detailed report to text file (default: validation_report.txt)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Simulate validation without making API calls')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed information')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging for troubleshooting repository mapping issues')
    parser.add_argument('--list-orgs', action='store_true',
                       help='List all accessible organizations and exit')

    args = parser.parse_args()

    if args.dry_run:
        print("🏃‍♂️ DRY RUN MODE - No actual API calls will be made")
        return

    # Initialize Snyk API client
    print("🔧 Initializing Snyk API client...")
    snyk_api = SnykAPI(args.snyk_token, args.snyk_region, args.debug)
    
    # Override the default API version if specified
    if hasattr(args, 'snyk_api_version'):
        print(f"🔧 Using Snyk API version: {args.snyk_api_version}")
        # Update the API version for all methods
        snyk_api.default_version = args.snyk_api_version

    # Handle --list-orgs flag
    if args.list_orgs:
        print("🏢 Fetching all accessible organizations...")
        try:
            orgs = snyk_api.get_organizations()
            print(f"\n📋 Found {len(orgs)} accessible organizations:")
            print("=" * 80)
            for org in orgs:
                org_id = org.get('id', 'Unknown')
                org_name = org.get('attributes', {}).get('name', 'Unknown')
                org_slug = org.get('attributes', {}).get('slug', 'Unknown')
                print(f"ID: {org_id}")
                print(f"Name: {org_name}")
                print(f"Slug: {org_slug}")
                print("-" * 40)
            return
        except Exception as e:
            print(f"❌ Error fetching organizations: {e}")
            return

    # Initialize GitLab client
    print("🔧 Initializing GitLab client...")
    gitlab_client = GitLabClient(args.gitlab_token, args.gitlab_url, args.debug)

    # Initialize validator
    validator = SCAValidator(snyk_api, gitlab_client, args.debug)

    # Get organizations to validate
    if args.org_id:
        print(f"🎯 Validating specific organization: {args.org_id}")
        orgs_to_validate = [{'id': args.org_id}]
    else:
        print("🏢 Getting all organizations...")
        all_orgs = snyk_api.get_organizations()
        orgs_to_validate = all_orgs

    # Validate each organization
    all_results = []
    for org in orgs_to_validate:
        org_id = org['id']
        try:
            org_result = validator.validate_organization(org_id)
            all_results.append(org_result)
        except Exception as e:
            print(f"❌ Error validating organization {org_id}: {e}")
            continue

    # Generate and display report
    print("\n" + "=" * 80)
    print("VALIDATION COMPLETE")
    print("=" * 80)

    report = validator.generate_report(all_results)
    print(report)

    # Save results to files
    if args.output_csv:
        csv_filename = args.output_csv
    else:
        csv_filename = "validation_results.csv"
    
    validator.save_results_to_csv(all_results, csv_filename)

    if args.output_report:
        report_filename = args.output_report
    else:
        report_filename = "validation_report.txt"
    
    try:
        with open(report_filename, 'w') as f:
            f.write(report)
        print(f"✅ Saved detailed report to {report_filename}")
    except Exception as e:
        print(f"❌ Error saving report file: {e}")

    print(f"\n🎉 Snyk SCA validation completed!")
    print(f"   - Organizations processed: {len(all_results)}")
    print(f"   - Results saved to: {csv_filename}")
    print(f"   - Report saved to: {report_filename}")


if __name__ == '__main__':
    main()