#!/usr/bin/env python3
"""
Core classes and utilities for Snyk SCA File Validator

This module contains the shared classes used by both streaming and batch modes.
"""

import argparse
import sys
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
import requests
import os
import re
from urllib.parse import urlparse, unquote, parse_qs


def debug_log(message: str, debug: bool = False) -> None:
    """Print debug message if debug mode is enabled"""
    if debug:
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        print(f"[{timestamp}] 🔍 DEBUG: {message}")


class SnykAPI:
    """Snyk API client for fetching organizations, targets, and projects"""
    
    def __init__(self, token: str, region: str = 'SNYK-US-01', debug: bool = False):
        self.token = token
        self.region = region
        self.debug = debug
        self.base_url = f"https://api.snyk.io/rest"
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {token}',
            'Content-Type': 'application/json'
        })
    
    def get_organizations(self) -> List[Dict]:
        """Get list of organizations accessible to the token"""
        debug_log("Fetching Snyk organizations", self.debug)
        url = f"{self.base_url}/orgs"
        resp = self.session.get(url)
        debug_log(f"Snyk organizations status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            orgs = data.get('data', [])
            debug_log(f"Found {len(orgs)} organizations", self.debug)
            return orgs
        else:
            debug_log(f"Snyk organizations error: {resp.status_code} - {resp.text}", self.debug)
            return []
    
    def get_organizations_for_group(self, group_id: str) -> List[Dict]:
        """Get list of organizations in a specific group"""
        debug_log(f"Fetching organizations for group: {group_id}", self.debug)
        
        # Try different API versions for group orgs
        versions = ['2024-10-15', '2023-05-29']
        
        for version in versions:
            debug_log(f"Trying group orgs API with version: {version}", self.debug)
            orgs = self._get_group_orgs_with_version(group_id, version)
            if orgs is not None:
                debug_log(f"Successfully fetched {len(orgs)} organizations for group {group_id} with version {version}", self.debug)
                return orgs
            else:
                debug_log(f"Failed to fetch group orgs with version {version}", self.debug)
        
        debug_log("Failed to fetch group organizations with all API versions", self.debug)
        return []
    
    def _get_group_orgs_with_version(self, group_id: str, version: str) -> Optional[List[Dict]]:
        """Get organizations for group with specific API version"""
        url = f"{self.base_url}/groups/{group_id}/orgs"
        params = {'version': version, 'limit': 100}
        
        all_orgs = []
        page = 1
        
        while True:
            debug_log(f"Group orgs API - URL: {url}, params: {params}, page: {page}", self.debug)
            resp = self.session.get(url, params=params)
            debug_log(f"Group orgs API status: {resp.status_code}", self.debug)
            
            if resp.status_code == 200:
                data = resp.json()
                orgs = data.get('data', [])
                if not orgs:
                    break
                
                all_orgs.extend(orgs)
                debug_log(f"Fetched {len(orgs)} orgs on page {page}, total: {len(all_orgs)}", self.debug)
                
                # Check for next page using links.next (cursor-based pagination)
                links = data.get('links', {})
                next_url = links.get('next')
                if next_url:
                    # Extract starting_after parameter from the URL
                    parsed = urlparse(next_url)
                    query_params = parse_qs(parsed.query)
                    starting_after = query_params.get('starting_after', [None])[0]
                    if starting_after:
                        params['starting_after'] = starting_after
                        page += 1
                        debug_log(f"Found next page, cursor: {starting_after}", self.debug)
                    else:
                        break
                else:
                    break
                
            elif resp.status_code == 404:
                debug_log(f"Group {group_id} not found with version {version}", self.debug)
                return None
            elif resp.status_code in [403, 401]:
                debug_log(f"Access denied to group {group_id} with version {version}", self.debug)
                return None
            else:
                debug_log(f"Group orgs API error {resp.status_code}: {resp.text}", self.debug)
                return None
        
        return all_orgs
    
    def validate_organization_access(self, org_id: str) -> bool:
        """Check if organization is accessible with API version fallback"""
        debug_log(f"Validating access to organization: {org_id}", self.debug)
        
        # Try different API versions
        versions = ['2024-10-15', '2023-05-29', '2023-06-18']
        
        for version in versions:
            debug_log(f"Trying API version: {version}", self.debug)
            url = f"{self.base_url}/orgs/{org_id}"
            params = {'version': version}
            
            debug_log(f"API Request - URL: {url}, params: {params}", self.debug)
            resp = self.session.get(url, params=params)
            debug_log(f"Organization access status: {resp.status_code}", self.debug)
            
            if resp.status_code == 200:
                debug_log(f"Organization access successful with version {version}", self.debug)
                return True
            elif resp.status_code == 404:
                debug_log(f"Organization not found with version {version}", self.debug)
                continue
            elif resp.status_code in [403, 401]:
                debug_log(f"Access denied to organization with version {version}", self.debug)
                return False
            else:
                debug_log(f"Unexpected error {resp.status_code} with version {version}: {resp.text}", self.debug)
                continue
        
        debug_log("Organization access failed with all API versions", self.debug)
        return False
    
    def get_targets_for_org(self, org_id: str) -> List[Dict]:
        """Get targets for organization with API version fallback"""
        debug_log(f"Fetching targets for organization: {org_id}", self.debug)
        
        # First validate organization access
        if not self.validate_organization_access(org_id):
            debug_log(f"Organization {org_id} is not accessible", self.debug)
            return []
        
        # Try different API versions for targets
        versions = ['2024-10-15', '2024-09-04', '2023-05-29', '2023-06-18']
        
        for version in versions:
            debug_log(f"Trying targets API with version: {version}", self.debug)
            targets = self._get_targets_with_version(org_id, version, source_types=['gitlab', 'cli'])
            if targets is not None:
                debug_log(f"Successfully fetched {len(targets)} targets with version {version}", self.debug)
                return targets
            else:
                debug_log(f"Failed to fetch targets with version {version}", self.debug)
        
        debug_log("Failed to fetch targets with all API versions", self.debug)
        return []
    
    def _get_targets_with_version(self, org_id: str, version: str, source_types: Optional[List[str]] = None) -> Optional[List[Dict]]:
        """Get targets for organization with specific API version"""
        url = f"{self.base_url}/orgs/{org_id}/targets"
        params = {'version': version}
        
        # Add source_types filter for gitlab and cli targets
        if source_types:
            params['source_types'] = ','.join(source_types)
            params['limit'] = 100
        
        debug_log(f"API Request - URL: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params)
        debug_log(f"Targets API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            targets = data.get('data', [])
            debug_log(f"Found {len(targets)} targets", self.debug)
            return targets
        elif resp.status_code == 404:
            debug_log(f"Organization {org_id} not found with version {version}", self.debug)
            return None
        elif resp.status_code in [403, 401]:
            debug_log(f"Access denied to organization {org_id} with version {version}", self.debug)
            return None
        else:
            debug_log(f"Targets API error {resp.status_code}: {resp.text}", self.debug)
            return None
    
    def get_projects_for_target(self, org_id: str, target_id: str) -> List[Dict]:
        """Get projects for a specific target"""
        debug_log(f"Fetching projects for target: {target_id}", self.debug)
        
        # Try the target-specific projects endpoint first
        url = f"{self.base_url}/orgs/{org_id}/targets/{target_id}/projects"
        params = {'version': '2024-10-15'}
        debug_log(f"Projects API URL: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params)
        debug_log(f"Projects API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            projects = data.get('data', [])
            debug_log(f"Found {len(projects)} projects for target {target_id}", self.debug)
            if projects:
                debug_log(f"First project sample: {projects[0] if projects else 'None'}", self.debug)
            return projects
        elif resp.status_code == 404:
            # If target-specific endpoint fails, try to get all projects and filter by target
            debug_log(f"Target-specific projects endpoint returned 404, trying general projects endpoint", self.debug)
            return self._get_projects_for_target_fallback(org_id, target_id)
        else:
            debug_log(f"Projects API error {resp.status_code}: {resp.text}", self.debug)
            return []
    
    def _get_projects_for_target_fallback(self, org_id: str, target_id: str) -> List[Dict]:
        """Fallback: get all projects and filter by target"""
        debug_log(f"Fetching all projects for org {org_id} to find target {target_id}", self.debug)
        url = f"{self.base_url}/orgs/{org_id}/projects"
        params = {'version': '2024-10-15'}
        debug_log(f"General projects API URL: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params)
        debug_log(f"General projects API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            all_projects = data.get('data', [])
            debug_log(f"Found {len(all_projects)} total projects in org", self.debug)
            
            # Debug: show what target IDs exist in projects
            project_target_ids = []
            for project in all_projects:
                attrs = project.get('attributes', {})
                relationships = project.get('relationships', {})
                target_rel = relationships.get('target', {}).get('data', {})
                
                project_target_id = attrs.get('target_id') or target_rel.get('id')
                if project_target_id:
                    project_target_ids.append(project_target_id)
            debug_log(f"Project target IDs in org: {project_target_ids[:5]}", self.debug)
            debug_log(f"Looking for target ID: {target_id}", self.debug)
            
            # Debug: show actual project structure
            if all_projects:
                debug_log(f"First project structure: {all_projects[0]}", self.debug)
            
            # Filter projects that belong to this target
            target_projects = []
            for project in all_projects:
                # Check both attributes.target_id and relationships.target.data.id
                attrs = project.get('attributes', {})
                relationships = project.get('relationships', {})
                target_rel = relationships.get('target', {}).get('data', {})
                
                project_target_id = attrs.get('target_id') or target_rel.get('id')
                if project_target_id == target_id:
                    target_projects.append(project)
            
            # If no projects found by target ID, try to match by URL
            if not target_projects:
                debug_log(f"No projects found by target ID, trying URL matching", self.debug)
                # This will be implemented in the calling function
            
            debug_log(f"Found {len(target_projects)} projects for target {target_id}", self.debug)
            return target_projects
        else:
            debug_log(f"General projects API error {resp.status_code}: {resp.text}", self.debug)
            return []
    
    def get_all_projects_for_org(self, org_id: str) -> List[Dict]:
        """Get all projects for an organization"""
        debug_log(f"Fetching all projects for org: {org_id}", self.debug)
        url = f"{self.base_url}/orgs/{org_id}/projects"
        params = {'version': '2024-10-15'}
        debug_log(f"All projects API URL: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params)
        debug_log(f"All projects API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            projects = data.get('data', [])
            debug_log(f"Found {len(projects)} total projects in org {org_id}", self.debug)
            return projects
        else:
            debug_log(f"All projects API error {resp.status_code}: {resp.text}", self.debug)
            return []
    
    def get_target_url(self, org_id: str, target_id: str) -> Optional[str]:
        """Get target URL by target ID"""
        debug_log(f"Fetching target URL for target: {target_id}", self.debug)
        url = f"{self.base_url}/orgs/{org_id}/targets/{target_id}"
        params = {'version': '2024-10-15'}
        debug_log(f"Target URL API: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params)
        debug_log(f"Target URL API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            target_data = data.get('data', {})
            target_url = target_data.get('attributes', {}).get('url')
            debug_log(f"Target URL: {target_url}", self.debug)
            return target_url
        else:
            debug_log(f"Target URL API error {resp.status_code}: {resp.text}", self.debug)
            return None
    
    def get_organization_name(self, org_id: str) -> str:
        """Get organization name by ID"""
        debug_log(f"Fetching organization name for: {org_id}", self.debug)
        url = f"{self.base_url}/orgs/{org_id}"
        params = {'version': '2024-10-15'}
        debug_log(f"Org name API: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params)
        debug_log(f"Org name API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            org_data = data.get('data', {})
            org_name = org_data.get('attributes', {}).get('name', org_id)
            debug_log(f"Organization name: {org_name}", self.debug)
            return org_name
        else:
            debug_log(f"Org name API error {resp.status_code}: {resp.text}", self.debug)
            return org_id  # Fallback to org_id if name can't be fetched
    
    def get_organization_url(self, org_id: str) -> str:
        """Get organization URL for Snyk web interface"""
        org_name = self.get_organization_name(org_id)
        # Convert org name to URL-friendly format (lowercase, replace spaces with hyphens)
        org_slug = org_name.lower().replace(' ', '-').replace('_', '-')
        return f"https://app.snyk.io/org/{org_slug}/"
    
    def get_project_url(self, org_id: str, project_id: str) -> str:
        """Get project URL for Snyk web interface"""
        org_name = self.get_organization_name(org_id)
        org_slug = org_name.lower().replace(' ', '-').replace('_', '-')
        return f"https://app.snyk.io/org/{org_slug}/project/{project_id}"
    
    def get_project_details(self, org_id: str, project_id: str) -> Optional[Dict]:
        """Get detailed information about a specific project"""
        debug_log(f"Fetching project details: {project_id}", self.debug)
        url = f"{self.base_url}/orgs/{org_id}/projects/{project_id}"
        resp = self.session.get(url)
        debug_log(f"Project details API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            debug_log(f"Retrieved project details for {project_id}", self.debug)
            return data.get('data')
        else:
            debug_log(f"Project details API error {resp.status_code}: {resp.text}", self.debug)
            return None


class GitLabClient:
    """GitLab API client for repository operations"""
    
    def __init__(self, token: Optional[str] = None, gitlab_url: str = 'https://gitlab.com', debug: bool = False, verify_ssl: bool = True):
        self.token = token
        self.gitlab_url = gitlab_url.rstrip('/')
        self.debug = debug
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        if token:
            self.session.headers.update({'Authorization': f'Bearer {token}'})
    
    def parse_repo_url(self, url: str) -> Optional[Dict]:
        """Parse repository URL and extract platform, host, owner, repo info"""
        if not url:
            return None
        
        debug_log(f"Parsing repo URL: {url}", self.debug)
        
        # Normalize http to https for consistency
        if url.startswith('http://'):
            url = url.replace('http://', 'https://', 1)
            debug_log(f"Normalized http to https: {url}", self.debug)
        
        # Handle different URL formats
        if url.startswith('git@'):
            # SSH format: git@gitlab.com:owner/repo.git
            parts = url.replace('git@', '').replace('.git', '').split(':')
            if len(parts) == 2:
                host = parts[0]
                path = parts[1]
                path_parts = path.split('/')
                if len(path_parts) >= 2:
                    owner = '/'.join(path_parts[:-1])
                    repo = path_parts[-1]
                    platform = 'gitlab' if 'gitlab' in host else 'github' if 'github' in host else 'bitbucket'
                    debug_log(f"Parsed SSH URL - Platform: {platform}, Host: {host}, Owner: {owner}, Repo: {repo}", self.debug)
                    return {
                        'platform': platform,
                        'host': host,
                        'owner': owner,
                        'repo': repo,
                        'url': url
                    }
        
        # HTTP/HTTPS format
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path.strip('/')
            
            # Remove .git suffix
            if path.endswith('.git'):
                path = path[:-4]
            
            # Split path into owner/repo
            path_parts = path.split('/')
            if len(path_parts) >= 2:
                owner = '/'.join(path_parts[:-1])
                repo = path_parts[-1]
                
                # Determine platform
                if 'gitlab' in host:
                    platform = 'gitlab'
                elif 'github' in host:
                    platform = 'github'
                elif 'bitbucket' in host:
                    platform = 'bitbucket'
                else:
                    platform = 'unknown'
                
                debug_log(f"Parsed HTTP URL - Platform: {platform}, Host: {host}, Owner: {owner}, Repo: {repo}", self.debug)
                return {
                    'platform': platform,
                    'host': host,
                    'owner': owner,
                    'repo': repo,
                    'url': url
                }
        except Exception as e:
            debug_log(f"Error parsing URL {url}: {e}", self.debug)
        
        debug_log(f"Could not parse URL: {url}", self.debug)
        return None
    
    def get_default_branch(self, repo_info: Dict) -> str:
        """Get default branch for repository"""
        if not repo_info or repo_info.get('platform') != 'gitlab':
            return 'main'
        
        debug_log(f"Getting default branch for {repo_info.get('owner')}/{repo_info.get('repo')}", self.debug)
        
        # Use path_with_namespace if available (from GitLab catalog)
        path_with_namespace = repo_info.get('path_with_namespace')
        if path_with_namespace:
            url = f"{self.gitlab_url}/api/v4/projects/{path_with_namespace.replace('/', '%2F')}"
        else:
            owner = repo_info.get('owner', '')
            repo = repo_info.get('repo', '')
            url = f"{self.gitlab_url}/api/v4/projects/{owner}%2F{repo}"
        
        debug_log(f"GitLab API URL: {url}", self.debug)
        resp = self.session.get(url, verify=self.verify_ssl)
        debug_log(f"GitLab API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            data = resp.json()
            default_branch = data.get('default_branch', 'main')
            debug_log(f"Default branch: {default_branch}", self.debug)
            return default_branch
        else:
            debug_log(f"Could not get default branch, using 'main'", self.debug)
            return 'main'
    
    def get_file_content(self, repo_info: Dict, file_path: str, branch: str = None) -> Optional[str]:
        """Get file content from GitLab repository"""
        if not repo_info or repo_info.get('platform') != 'gitlab':
            return None
        
        if not branch:
            branch = repo_info.get('branch', 'main')
        
        debug_log(f"Getting file content: {file_path} from branch {branch}", self.debug)
        
        # Use path_with_namespace if available (from GitLab catalog)
        path_with_namespace = repo_info.get('path_with_namespace')
        if path_with_namespace:
            url = f"{self.gitlab_url}/api/v4/projects/{path_with_namespace.replace('/', '%2F')}/repository/files/{file_path.replace('/', '%2F')}/raw"
        else:
            owner = repo_info.get('owner', '')
            repo = repo_info.get('repo', '')
            url = f"{self.gitlab_url}/api/v4/projects/{owner}%2F{repo}/repository/files/{file_path.replace('/', '%2F')}/raw"
        
        params = {'ref': branch}
        debug_log(f"GitLab file API URL: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params, verify=self.verify_ssl)
        debug_log(f"GitLab file API status: {resp.status_code}", self.debug)
        
        if resp.status_code == 200:
            debug_log(f"Successfully retrieved file content for {file_path}", self.debug)
            return resp.text
        else:
            debug_log(f"Could not get file content for {file_path}: {resp.status_code}", self.debug)
            return None
    
    def check_file_exists(self, repo_info: Dict, file_path: str, branch: str = None) -> bool:
        """Check if file exists in GitLab repository"""
        if not repo_info or repo_info.get('platform') != 'gitlab':
            return False
        
        if not branch:
            branch = repo_info.get('branch', 'main')
        
        debug_log(f"Checking file existence: {file_path} in branch {branch}", self.debug)
        
        # Use path_with_namespace if available (from GitLab catalog)
        path_with_namespace = repo_info.get('path_with_namespace')
        if path_with_namespace:
            url = f"{self.gitlab_url}/api/v4/projects/{path_with_namespace.replace('/', '%2F')}/repository/files/{file_path.replace('/', '%2F')}"
        else:
            owner = repo_info.get('owner', '')
            repo = repo_info.get('repo', '')
            url = f"{self.gitlab_url}/api/v4/projects/{owner}%2F{repo}/repository/files/{file_path.replace('/', '%2F')}"
        
        params = {'ref': branch}
        debug_log(f"GitLab file check API URL: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params, verify=self.verify_ssl)
        debug_log(f"GitLab file check API status: {resp.status_code}", self.debug)
        
        exists = resp.status_code == 200
        debug_log(f"File {file_path} exists: {exists}", self.debug)
        return exists
    
    def scan_repository_for_supported_files(self, repo_info: Dict) -> List[Dict]:
        """Scan repository for Snyk-supported files"""
        if not repo_info or repo_info.get('platform') != 'gitlab':
            return []
        
        debug_log(f"Scanning repository for supported files", self.debug)
        
        # Use path_with_namespace if available (from GitLab catalog)
        path_with_namespace = repo_info.get('path_with_namespace')
        if path_with_namespace:
            url = f"{self.gitlab_url}/api/v4/projects/{path_with_namespace.replace('/', '%2F')}/repository/tree"
        else:
            owner = repo_info.get('owner', '')
            repo = repo_info.get('repo', '')
            url = f"{self.gitlab_url}/api/v4/projects/{owner}%2F{repo}/repository/tree"
        
        branch = repo_info.get('branch', 'main')
        params = {'ref': branch, 'recursive': 'true'}
        debug_log(f"GitLab tree API URL: {url}, params: {params}", self.debug)
        resp = self.session.get(url, params=params, verify=self.verify_ssl)
        debug_log(f"GitLab tree API status: {resp.status_code}", self.debug)
        
        if resp.status_code != 200:
            debug_log(f"Could not scan GitLab repository tree: {resp.status_code}", self.debug)
            return []
        
        files = resp.json()
        supported_files = []
        
        # Define supported file patterns
        supported_patterns = [
            r'package\.json$',
            r'package-lock\.json$',
            r'yarn\.lock$',
            r'requirements\.txt$',
            r'Pipfile$',
            r'Pipfile\.lock$',
            r'poetry\.lock$',
            r'pyproject\.toml$',
            r'pom\.xml$',
            r'build\.gradle$',
            r'build\.gradle\.kts$',
            r'composer\.json$',
            r'composer\.lock$',
            r'Gemfile$',
            r'Gemfile\.lock$',
            r'go\.mod$',
            r'go\.sum$',
            r'Cargo\.toml$',
            r'Cargo\.lock$',
            r'nuget\.config$',
            r'packages\.config$',
            r'\.csproj$',
            r'\.vbproj$',
            r'\.fsproj$',
            r'Dockerfile$',
            r'\.dockerignore$',
            r'docker-compose\.yml$',
            r'docker-compose\.yaml$',
            r'\.nvmrc$',
            r'\.node-version$',
            r'\.python-version$',
            r'\.ruby-version$',
            r'\.java-version$',
            r'\.sbt$',
            r'build\.sbt$',
            r'project/plugins\.sbt$',
            r'project/build\.properties$'
        ]
        
        for file_info in files:
            if file_info.get('type') == 'blob':
                file_path = file_info.get('path', '')
                for pattern in supported_patterns:
                    if re.search(pattern, file_path, re.IGNORECASE):
                        supported_files.append({
                            'file_path': file_path,
                            'pattern': pattern
                        })
                        break
        
        debug_log(f"Found {len(supported_files)} supported files", self.debug)
        return supported_files


class SCAValidator:
    """SCA file validator for checking Snyk project files"""
    
    def __init__(self, snyk: SnykAPI, gitlab: GitLabClient, debug: bool = False):
        self.snyk = snyk
        self.gitlab = gitlab
        self.debug = debug
    
    def validate_file(self, repo_info: Dict, file_path: str, root: str = '') -> Dict:
        """Validate a single file exists in the repository"""
        debug_log(f"Validating file: {file_path} (root: {root})", self.debug)
        
        # Construct full path
        full_path = os.path.join(root, file_path).replace('\\', '/').strip('/')
        
        # Check if file exists
        exists = self.gitlab.check_file_exists(repo_info, full_path)
        
        result = {
            'file_path': full_path,
            'exists': exists,
            'root': root
        }
        
        debug_log(f"File validation result: {result}", self.debug)
        return result
    
    def _extract_file_paths_from_project(self, project_attrs: Dict) -> List[str]:
        """Extract file paths from Snyk project attributes"""
        debug_log(f"Extracting file paths from project attributes", self.debug)
        
        file_paths = []
        
        # Check for various file path attributes
        for attr in ['target_file', 'target_file_path', 'file_path', 'path']:
            if attr in project_attrs and project_attrs[attr]:
                file_paths.append(project_attrs[attr])
        
        # Check for multiple files in some attributes
        if 'target_files' in project_attrs and isinstance(project_attrs['target_files'], list):
            file_paths.extend(project_attrs['target_files'])
        
        debug_log(f"Extracted file paths: {file_paths}", self.debug)
        return file_paths
    
    def scan_repository_for_supported_files(self, repo_info: Dict) -> List[Dict]:
        """Scan repository for Snyk-supported files"""
        debug_log(f"Scanning repository for supported files", self.debug)
        return self.gitlab.scan_repository_for_supported_files(repo_info)
    
    def detect_duplicate_projects_by_name_pattern(self, all_projects: List[Dict]) -> List[Dict]:
        """
        Detect duplicate projects based on name pattern analysis.
        Uses existing project data - no additional API calls needed!
        
        Looks for projects with the same unique identifier (part after ':') 
        within the same target (repository).
        """
        debug_log(f"Detecting duplicate projects from {len(all_projects)} total projects", self.debug)
        duplicates = []
        
        # Group projects by target_id and unique identifier after ':'
        target_groups = {}
        
        for project in all_projects:
            attrs = project.get('attributes', {})
            project_name = attrs.get('name', '')
            target_id = project.get('relationships', {}).get('target', {}).get('data', {}).get('id')
            
            if not target_id or ':' not in project_name:
                continue
                
            # Extract unique identifier after ':' and normalize path
            unique_part = project_name.split(':', 1)[1].strip()
            # Normalize path to handle ./ and ../ variations
            import os
            unique_part = os.path.normpath(unique_part)
            
            if target_id not in target_groups:
                target_groups[target_id] = {}
            if unique_part not in target_groups[target_id]:
                target_groups[target_id][unique_part] = []
                
            target_groups[target_id][unique_part].append({
                'project_id': project.get('id'),
                'project_name': project_name,
                'created': attrs.get('created', ''),
                'org_id': project.get('relationships', {}).get('organization', {}).get('data', {}).get('id'),
                'target_id': target_id,
                'project_type': attrs.get('type', 'unknown')
            })
        
        # Check for duplicates within each target
        for target_id, unique_groups in target_groups.items():
            debug_log(f"Checking target {target_id} with {len(unique_groups)} unique identifiers", self.debug)
            for unique_part, projects in unique_groups.items():
                if len(projects) > 1:
                    debug_log(f"Found {len(projects)} projects with same unique identifier: {unique_part}", self.debug)
                    # Multiple projects with same unique identifier in same target
                    stale_projects = self._analyze_name_pattern_duplicates(projects, unique_part)
                    if stale_projects:
                        duplicates.extend(stale_projects)
        
        debug_log(f"Found {len(duplicates)} duplicate projects", self.debug)
        return duplicates
    
    def _analyze_name_pattern_duplicates(self, projects: List[Dict], unique_part: str) -> List[Dict]:
        """Analyze projects with same unique identifier to find stale ones"""
        stale_projects = []
        
        # Sort by creation date (newest first)
        projects.sort(key=lambda x: x.get('created', ''), reverse=True)
        
        debug_log(f"Analyzing {len(projects)} projects with unique identifier: {unique_part}", self.debug)
        for i, project in enumerate(projects):
            debug_log(f"  Project {i+1}: {project['project_name']} (created: {project['created']})", self.debug)
        
        # Keep the newest project, mark others as stale
        for i, project in enumerate(projects):
            if i > 0:  # Skip the first (newest) project
                stale_projects.append({
                    'project_id': project['project_id'],
                    'project_name': project['project_name'],
                    'unique_identifier': unique_part,
                    'reason': 'Duplicate project - newer version exists',
                    'duplicate_of': projects[0]['project_id'],
                    'duplicate_of_name': projects[0]['project_name'],
                    'org_id': project['org_id'],
                    'target_id': project['target_id'],
                    'created': project['created'],
                    'duplicate_created': projects[0]['created'],
                    'project_type': project['project_type']
                })
                debug_log(f"Marking as stale: {project['project_name']} (duplicate of: {projects[0]['project_name']})", self.debug)
        
        return stale_projects