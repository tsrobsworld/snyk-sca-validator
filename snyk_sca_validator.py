#!/usr/bin/env python3
"""
Snyk SCA File Validator - GitLab Batch Join Mode

This script implements a batch, join-based workflow alongside the original
streaming validator. It does not replace the original flow. It:

1) Collects a catalog of GitLab repositories available to the token
2) Collects Snyk targets (GitLab + CLI) and normalizes their repo URLs
3) Joins the two sets on a canonical repo key (host + full path)
4) For matched repos: validates Snyk-tracked files exist in GitLab
5) Detects supported files in the repo that are not tracked by Snyk
6) Reports Snyk-only (stale target) and GitLab-only (no Snyk target) cases

Usage:
  python3 snyk_sca_validator_batch.py --snyk-token <TOKEN> [--org-id <ORG>]
                                      [--gitlab-token <GL_TOKEN>] 
                                      [--gitlab-url https://gitlab.com]
                                      [--snyk-region SNYK-US-01]
                                      [--output-report batch_report.txt]
                                      [--debug]
"""

import argparse
import sys
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
import requests
import os
import json

try:
    # Import core classes from separate module
    from snyk_sca_validator_core import SnykAPI, GitLabClient, SCAValidator, debug_log
except Exception as e:
    print(f"❌ Could not import from snyk_sca_validator_core.py: {e}")
    sys.exit(1)


def build_gitlab_repo_catalog(gitlab: GitLabClient, debug: bool = False, timeout: int = 60, max_retries: int = 3) -> Dict[str, Dict]:
    """
    List GitLab projects the token can access and return a mapping keyed by
    canonical repo key: f"{host}/{full_path}" where full_path is group[/subgroup]/project.

    Uses /projects?membership=true to approximate the accessible catalog.
    """
    session = gitlab.session
    base = gitlab.gitlab_url.rstrip('/')
    url = f"{base}/api/v4/projects"
    params = {
        'membership': 'true',  # projects the authenticated user is a member of
        'simple': 'true',
        'archived': 'false',
        'per_page': 100,
        'order_by': 'path'
    }

    catalog: Dict[str, Dict] = {}
    page = 1
    
    while True:
        debug_log(f"GitLab list projects page {page} - URL: {url}, params: {params}", debug)
        
        # Retry logic for network issues with rate limiting support
        for attempt in range(max_retries):
            try:
                # Increased timeout for slow networks (connect and read)
                resp = session.get(url, params=params, timeout=(timeout, timeout), verify=gitlab.verify_ssl)  # (connect, read) timeout in seconds
                
                # Check for rate limiting
                if resp.status_code == 429:
                    retry_after = resp.headers.get('Retry-After', '30')
                    try:
                        wait_time = int(retry_after)
                    except ValueError:
                        wait_time = 30
                    debug_log(f"GitLab API rate limited. Waiting {wait_time} seconds...", debug)
                    import time
                    time.sleep(wait_time)
                    continue
                
                debug_log(f"GitLab list projects status: {resp.status_code}", debug)
                break
            except (requests.exceptions.ChunkedEncodingError, 
                    requests.exceptions.ConnectionError, 
                    requests.exceptions.Timeout) as e:
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                debug_log(f"GitLab API attempt {attempt + 1} failed: {e}", debug)
                if attempt < max_retries - 1:
                    import time
                    debug_log(f"Waiting {wait_time} seconds before retry...", debug)
                    time.sleep(wait_time)
                    continue
                else:
                    debug_log(f"GitLab API failed after {max_retries} attempts", debug)
                    return catalog
        
        if resp.status_code != 200:
            debug_log(f"GitLab list projects error body: {resp.text}", debug)
            break

        try:
            projects = resp.json()
        except ValueError as e:
            debug_log(f"GitLab API response not valid JSON: {e}", debug)
            break
            
        if not projects:
            break

        for p in projects:
            # path_with_namespace: group/subgroup/project
            full_path = p.get('path_with_namespace')
            if not full_path:
                continue
            key = f"{gitlab.gitlab_url.replace('https://', '').replace('http://', '').rstrip('/')}/{full_path}"
            web_url = p.get('web_url', '')
            # Store normalized URL for flexible matching
            catalog[key] = {
                'id': p.get('id'),
                'default_branch': p.get('default_branch'),
                'path_with_namespace': full_path,
                'web_url': web_url,
                'normalized_web_url': normalize_url_for_matching(web_url) if web_url else ''
            }

        # pagination
        next_page = resp.headers.get('X-Next-Page')
        if not next_page:
            break
        params['page'] = next_page
        page += 1

    return catalog


def build_snyk_target_catalog(snyk: SnykAPI, org_ids: List[str], gitlab: GitLabClient, debug: bool = False) -> Dict[str, List[Dict]]:
    """
    Fetch Snyk targets for the given orgs and group them by canonical repo key.
    Includes both GitLab and CLI targets, with CLI targets marked appropriately.
    """
    catalog: Dict[str, List[Dict]] = {}
    cli_targets_without_repo = []
    
    debug_log(f"Building Snyk target catalog for {len(org_ids)} organizations", debug)
    
    for i, org_id in enumerate(org_ids, 1):
        debug_log(f"Processing organization {i}/{len(org_ids)}: {org_id}", debug)
        targets = snyk.get_targets_for_org(org_id)
        debug_log(f"Found {len(targets)} targets for org {org_id}", debug)
        
        for t in targets:
            attrs = t.get('attributes', {})
            url = attrs.get('url')
            # Get integration type from relationships, not attributes.type
            integration_rel = t.get('relationships', {}).get('integration', {}).get('data', {})
            integration_type = integration_rel.get('attributes', {}).get('integration_type', 'unknown')
            
            debug_log(f"Processing target: {t.get('id')}, integration_type: {integration_type}, url: {url}", debug)
            debug_log(f"Full target structure: {t}", debug)
            
            # Handle GitLab and CLI targets - process any that have GitLab URLs
            # integration_type can be 'gitlab' (GitLab integration) or 'cli' (CLI import of GitLab repo)
            if integration_type in ['gitlab', 'cli']:
                if url:
                    # Try to parse the URL to see if it's a GitLab repo
                    repo_info = gitlab.parse_repo_url(url)
                    
                    if repo_info and repo_info.get('platform') == 'gitlab':
                        # This is a GitLab repo (either from GitLab integration or CLI import)
                        host = repo_info.get('host', 'gitlab.com')
                        owner = repo_info.get('owner', '')
                        repo = repo_info.get('repo', '')
                        full_path = f"{owner}/{repo}" if owner else repo
                        key = f"{host}/{full_path}"
                        catalog.setdefault(key, []).append({
                            'org_id': org_id,
                            'target_id': t.get('id'),
                            'target_name': attrs.get('display_name', t.get('id')),
                            'target_url': url,
                            'target_type': integration_type,
                            'repo_info': repo_info
                        })
                        debug_log(f"Added {integration_type} target with GitLab URL: {key}", debug)
                    else:
                        # Not a GitLab repo - skip GitHub, Bitbucket, etc.
                        debug_log(f"Skipping non-GitLab target: {url}", debug)
                else:
                    # CLI target without URL - store for later matching via projects
                    cli_info = {
                        'org_id': org_id,
                        'target_id': t.get('id'),
                        'target_name': attrs.get('display_name', t.get('id')),
                        'target_type': 'cli',
                        'full_target_data': t  # Store full target data for inspection
                    }
                    cli_targets_without_repo.append(cli_info)
                    debug_log(f"Added CLI target without repo URL: {t.get('id')}", debug)
                    debug_log(f"Full CLI target data: {json.dumps(t, indent=2)}", debug)
            else:
                debug_log(f"Skipping target {t.get('id')} with integration_type '{integration_type}' and url '{url}'", debug)
    
    debug_log(f"Built catalog with {len(catalog)} repo keys and {len(cli_targets_without_repo)} CLI targets without repo URLs", debug)
    
    # Store CLI targets without repo for reporting
    if cli_targets_without_repo:
        catalog['__CLI_WITHOUT_REPO__'] = cli_targets_without_repo
    
    return catalog


def normalize_key(host: str, full_path: str) -> str:
    # Keep case as-is to respect GitLab path semantics; trim slashes
    return f"{host.rstrip('/')}/{full_path.strip('/')}"


def normalize_url_for_matching(url: str) -> str:
    """
    Normalize URLs to handle http/https and .git suffix variations
    Ensures both http://gitlab.com/repo.git and https://gitlab.com/repo match
    """
    if not url:
        return url
    
    # Convert to lowercase for case-insensitive matching
    normalized = url.lower()
    
    # Normalize http to https
    if normalized.startswith('http://'):
        normalized = normalized.replace('http://', 'https://', 1)
    
    # Remove .git suffix if present
    if normalized.endswith('.git'):
        normalized = normalized[:-4]
    
    # Remove trailing slash
    normalized = normalized.rstrip('/')
    
    return normalized


def extract_org_ids(args, snyk: SnykAPI) -> List[str]:
    """Extract organization IDs from args, preferring group-id over org-id"""
    if args.group_id:
        debug_log(f"Using group-id: {args.group_id}", args.debug)
        orgs = snyk.get_organizations_for_group(args.group_id)
        if not orgs:
            print(f"❌ No organizations found for group {args.group_id}")
            return []
        org_ids = [o.get('id') for o in orgs if o.get('id')]
        debug_log(f"Found {len(org_ids)} organizations in group {args.group_id}", args.debug)
        return org_ids
    elif args.org_id:
        debug_log(f"Using org-id: {args.org_id}", args.debug)
        return [args.org_id]
    else:
        debug_log("No group-id or org-id specified, fetching all accessible organizations", args.debug)
        orgs = snyk.get_organizations()
        return [o.get('id') for o in orgs if o.get('id')]


def evaluate_matches(
    snyk: SnykAPI,
    gitlab: GitLabClient,
    validator: SCAValidator,
    gitlab_catalog: Dict[str, Dict],
    snyk_targets_by_key: Dict[str, List[Dict]],
    debug: bool = False
) -> Dict:
    # Separate CLI targets without repo from regular targets
    cli_without_repo = snyk_targets_by_key.pop('__CLI_WITHOUT_REPO__', [])
    
    matched_keys: Set[str] = set(gitlab_catalog.keys()) & set(snyk_targets_by_key.keys())
    snyk_only_keys: Set[str] = set(snyk_targets_by_key.keys()) - set(gitlab_catalog.keys())
    gitlab_only_keys: Set[str] = set(gitlab_catalog.keys()) - set(snyk_targets_by_key.keys())

    results = {
        'matched': [],
        'snyk_only': [],
        'gitlab_only': [],
        'cli_without_repo': cli_without_repo,
        'stale_files': [],  # Files tracked in Snyk but missing from GitLab
        'duplicate_projects': []  # Duplicate projects detected by name pattern analysis
    }

    # Snyk-only: stale Snyk targets (repo missing)
    for k in sorted(snyk_only_keys):
        results['snyk_only'].append({
            'repo_key': k,
            'targets': snyk_targets_by_key.get(k, [])
        })

    # GitLab-only: repos with no Snyk target
    for k in sorted(gitlab_only_keys):
        results['gitlab_only'].append({
            'repo_key': k,
            'gitlab': gitlab_catalog[k]
        })

    # Matched: validate tracked files and detect untracked supported files
    for k in sorted(matched_keys):
        gitlab_meta = gitlab_catalog[k]
        targets = snyk_targets_by_key[k]

        # Build GitLab repo info once for this repository
        # Use the default branch from the GitLab catalog (already fetched)
        default_branch = gitlab_meta.get('default_branch', 'main')
        gitlab_repo_info = {
            'platform': 'gitlab',
            'host': gitlab.gitlab_url.replace('https://', '').replace('http://', '').rstrip('/'),
            'owner': gitlab_meta['path_with_namespace'].rsplit('/', 1)[0] if '/' in gitlab_meta['path_with_namespace'] else gitlab_meta['path_with_namespace'],
            'repo': gitlab_meta['path_with_namespace'].rsplit('/', 1)[-1],
            'branch': default_branch,
            'path_with_namespace': gitlab_meta['path_with_namespace']  # Add this for GitLab API calls
        }

        # Aggregate across all targets for this repo
        tracked_files: Set[str] = set()
        tracked_file_details: List[Dict] = []  # Store file details for reporting
        stale_file_details: List[Dict] = []  # Store stale file details for reporting
        per_target_results = []
        
        # Get all projects for all organizations and match by URL
        all_orgs = set(t['org_id'] for t in targets)
        for org_id in all_orgs:
            debug_log(f"Fetching all projects for org {org_id} to match by URL", debug)
            all_projects = snyk.get_all_projects_for_org(org_id)
            debug_log(f"Found {len(all_projects)} total projects in org {org_id}", debug)
            
            # Detect duplicate projects using name pattern analysis
            duplicate_projects = validator.detect_duplicate_projects_by_name_pattern(all_projects)
            if duplicate_projects:
                # Add URLs to duplicate projects
                for duplicate in duplicate_projects:
                    duplicate['org_url'] = snyk.get_organization_url(duplicate['org_id'])
                    duplicate['project_url'] = snyk.get_project_url(duplicate['org_id'], duplicate['project_id'])
                    duplicate['newer_project_url'] = snyk.get_project_url(duplicate['org_id'], duplicate['duplicate_of'])
                
                results['duplicate_projects'] = results.get('duplicate_projects', [])
                results['duplicate_projects'].extend(duplicate_projects)
                debug_log(f"Found {len(duplicate_projects)} duplicate projects in org {org_id}", debug)
            
            # Match projects to this GitLab repo by URL
            repo_url = gitlab_meta.get('web_url', '')
            debug_log(f"Looking for projects matching GitLab repo URL: {repo_url}", debug)
            matching_projects = []
            for project in all_projects:
                attrs = project.get('attributes', {})
                relationships = project.get('relationships', {})
                target_rel = relationships.get('target', {}).get('data', {})
                
                # Try to get the target URL from the target relationship
                project_target_id = target_rel.get('id')
                if project_target_id:
                    # Get target details to find the URL
                    target_url = snyk.get_target_url(org_id, project_target_id)
                    debug_log(f"Project {project.get('id')} belongs to target {project_target_id} with URL: {target_url}", debug)
                    if target_url and repo_url and target_url == repo_url:
                        matching_projects.append(project)
                        debug_log(f"Matched project {project.get('id')} to repo by target URL: {target_url}", debug)
                else:
                    # Fallback to project attributes
                    project_url = attrs.get('target_reference', '') or attrs.get('url', '')
                    debug_log(f"Checking project {project.get('id')} with URL: {project_url}", debug)
                    if project_url and repo_url and (project_url in repo_url or repo_url in project_url):
                        matching_projects.append(project)
                        debug_log(f"Matched project {project.get('id')} to repo by URL: {project_url}", debug)
            
            debug_log(f"Found {len(matching_projects)} projects matching this GitLab repo", debug)
            
            # Extract file paths from matching projects
            project_file_checks: List[Dict] = []
            for p in matching_projects:
                attrs = p.get('attributes', {})
                debug_log(f"Project attributes: {attrs}", debug)
                file_paths = validator._extract_file_paths_from_project(attrs)
                debug_log(f"Extracted file paths: {file_paths}", debug)
                if not file_paths:
                    debug_log(f"No file paths found in project {p.get('id')}", debug)
                    continue
                for fp in file_paths:
                    tracked_files.add(fp)
                    check = validator.validate_file(gitlab_repo_info, fp, attrs.get('root', ''))
                    project_file_checks.append(check)
                    
                    # Store file details for reporting - separate valid and stale files
                    file_detail = {
                        'file_path': fp,
                        'project_id': p.get('id'),
                        'project_name': attrs.get('name', ''),
                        'root': attrs.get('root', ''),
                        'exists': check.get('exists', False),
                        'validation_status': check.get('status', 'unknown'),
                        'repo_key': k,
                        'gitlab_url': gitlab_meta.get('web_url', ''),
                        'org_id': org_id,
                        'org_name': snyk.get_organization_name(org_id),
                        'project_url': f"https://app.snyk.io/org/{snyk.get_organization_name(org_id)}/project/{p.get('id')}"
                    }
                    
                    if check.get('exists', False):
                        tracked_file_details.append(file_detail)
                    else:
                        stale_file_details.append(file_detail)
            
            if matching_projects:
                per_target_results.append({
                    'org_id': org_id,
                    'target_id': 'multiple',  # Multiple targets might match
                    'target_name': f"Matched {len(matching_projects)} projects",
                    'target_url': repo_url,
                    'projects_file_checks': project_file_checks
                })
        
        # Scan repo to find supported files and compare with tracked_files
        repo_supported = validator.scan_repository_for_supported_files(gitlab_repo_info) if targets else []
        supported_paths = {f['file_path'] for f in repo_supported}
        untracked_supported = sorted(list(supported_paths - tracked_files))

        results['matched'].append({
            'repo_key': k,
            'gitlab': gitlab_meta,
            'targets': per_target_results,
            'tracked_files_count': len(tracked_file_details),  # Only count valid files
            'stale_files_count': len(stale_file_details),  # Count stale files
            'supported_files_count': len(supported_paths),
            'untracked_supported_files': untracked_supported[:200],  # limit to keep report reasonable
            'tracked_file_details': tracked_file_details[:50],  # limit to keep report reasonable
            'stale_file_details': stale_file_details[:50]  # limit to keep report reasonable
        })

    return results


def render_report(results: Dict) -> str:
    lines: List[str] = []
    lines.append("=" * 80)
    lines.append("SNYK SCA FILE VALIDATION - BATCH JOIN REPORT")
    lines.append("=" * 80)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Matched repos: {len(results['matched'])}")
    lines.append(f"Snyk-only repos (stale targets): {len(results['snyk_only'])}")
    lines.append(f"GitLab-only repos (no Snyk targets): {len(results['gitlab_only'])}")
    lines.append(f"CLI targets without repo URLs: {len(results.get('cli_without_repo', []))}")
    lines.append(f"Duplicate projects detected: {len(results.get('duplicate_projects', []))}")
    lines.append("")

    lines.append("SNYK-ONLY (NO GITLAB TARGETS FOUND)")
    lines.append("-" * 40)
    for item in results['snyk_only'][:200]:
        lines.append(f"Repo key: {item['repo_key']}")
        for t in item['targets'][:5]:
            lines.append(f"  - {t['target_name']} ({t['target_url']})")
        if len(item['targets']) > 5:
            lines.append(f"  ... and {len(item['targets']) - 5} more targets")
    lines.append("")

    lines.append("GITLAB-ONLY (NO SNYK TARGETS)")
    lines.append("-" * 40)
    for item in results['gitlab_only'][:200]:
        lines.append(f"Repo key: {item['repo_key']}  URL: {item['gitlab'].get('web_url', '')}")
    lines.append("")

    lines.append("CLI TARGETS WITHOUT REPO URLs")
    lines.append("-" * 40)
    for item in results.get('cli_without_repo', [])[:200]:
        lines.append(f"Target: {item['target_name']} (Org: {item['org_id']})")
    lines.append("")

    lines.append("DUPLICATE PROJECTS")
    lines.append("-" * 40)
    
    # Group duplicates by unique identifier for better display
    duplicate_groups = {}
    for duplicate in results.get('duplicate_projects', []):
        key = duplicate['unique_identifier']
        if key not in duplicate_groups:
            duplicate_groups[key] = {
                'newer_project': None,
                'stale_projects': []
            }
        duplicate_groups[key]['stale_projects'].append(duplicate)
    
    for unique_id, group in list(duplicate_groups.items())[:50]:  # Limit to 50 groups
        lines.append(f"Unique Identifier: {unique_id}")
        lines.append("")
        
        # Show newer project (keep this one)
        if group['stale_projects']:
            newer_project = group['stale_projects'][0]  # First one is the newer one
            lines.append(f"✅ KEEP: {newer_project['duplicate_of_name']} ({newer_project['duplicate_of']})")
            lines.append(f"   Type: {newer_project['project_type']}")
            lines.append(f"   Created: {newer_project['duplicate_created']}")
            lines.append(f"   Org: {newer_project['org_id']}")
            lines.append(f"   Project URL: {newer_project.get('newer_project_url', 'N/A')}")
            lines.append("")
            
            # Show stale projects (remove these)
            lines.append("❌ REMOVE (Stale Duplicates):")
            for stale in group['stale_projects']:
                lines.append(f"   • {stale['project_name']} ({stale['project_id']})")
                lines.append(f"     Type: {stale['project_type']}")
                lines.append(f"     Created: {stale['created']}")
                lines.append(f"     Reason: {stale['reason']}")
                lines.append(f"     Project URL: {stale.get('project_url', 'N/A')}")
                lines.append("")
        
        lines.append("-" * 40)

    lines.append("MATCHED REPOSITORIES")
    lines.append("-" * 40)
    for m in results['matched'][:200]:
        lines.append(f"Repo key: {m['repo_key']}")
        lines.append(f"  Tracked files in Snyk: {m['tracked_files_count']}  Stale files in Snyk: {m['stale_files_count']}  Snyk supported files: {m['supported_files_count']}")
        
        # Show tracked files in Snyk (valid files)
        if m['tracked_file_details']:
            lines.append("  Tracked files in Snyk:")
            for file_detail in m['tracked_file_details']:
                lines.append(f"    ✅ {file_detail['file_path']}")
                if file_detail['project_name']:
                    lines.append(f"      Project: {file_detail['project_name']}")
                    lines.append(f"      Org: {file_detail['org_name']} ({file_detail['org_id']})")
                    lines.append(f"      URL: {file_detail['project_url']}")
        
        # Show stale files in Snyk (missing files)
        if m['stale_file_details']:
            lines.append("  Stale files in Snyk:")
            for file_detail in m['stale_file_details']:
                lines.append(f"    ❌ {file_detail['file_path']}")
                if file_detail['project_name']:
                    lines.append(f"      Project: {file_detail['project_name']}")
                    lines.append(f"      Org: {file_detail['org_name']} ({file_detail['org_id']})")
                    lines.append(f"      URL: {file_detail['project_url']}")
        
        # Show supported files not tracked by Snyk
        if m['untracked_supported_files']:
            lines.append("  Supported files not tracked by Snyk:")
            for fp in m['untracked_supported_files']:
                lines.append(f"    - {fp}")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Batch join-mode Snyk/GitLab validator")
    parser.add_argument('--snyk-token', required=True, help='Snyk API token')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--group-id', help='Snyk group ID to process all organizations in group')
    group.add_argument('--org-id', help='Specific Snyk organization ID (optional)')
    parser.add_argument('--snyk-region', default='SNYK-US-01', help='Snyk API region')
    parser.add_argument('--gitlab-token', help='GitLab API token for private repositories')
    parser.add_argument('--gitlab-url', default='https://gitlab.com', help='GitLab instance URL')
    parser.add_argument('--output-report', default='batch_report.txt', help='Output report filename')
    parser.add_argument('--timeout', type=int, default=60, help='HTTP request timeout in seconds (default: 60)')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retry attempts for failed requests (default: 3)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification for GitLab API calls')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    # Validate that at least one of group-id or org-id is provided
    if not args.group_id and not args.org_id:
        print("❌ Either --group-id or --org-id must be specified")
        sys.exit(1)

    # Initialize clients
    snyk = SnykAPI(args.snyk_token, args.snyk_region, args.debug)
    gitlab = GitLabClient(args.gitlab_token, args.gitlab_url, args.debug, verify_ssl=not args.no_ssl_verify)
    validator = SCAValidator(snyk, gitlab, args.debug)

    # Determine organizations to process
    org_ids = extract_org_ids(args, snyk)
    if not org_ids:
        print("❌ No organizations to process")
        sys.exit(1)

    # Build catalogs
    print("📚 Building GitLab repository catalog...")
    gl_catalog = build_gitlab_repo_catalog(gitlab, args.debug, args.timeout, args.max_retries)
    print(f"   ✅ GitLab repos discovered: {len(gl_catalog)}")

    print("🎯 Collecting Snyk targets...")
    snyk_catalog = build_snyk_target_catalog(snyk, org_ids, gitlab, args.debug)
    print(f"   ✅ Snyk target repo references: {len(snyk_catalog)} (unique repos)")

    # Evaluate matches
    print("🔗 Joining catalogs and evaluating...")
    results = evaluate_matches(snyk, gitlab, validator, gl_catalog, snyk_catalog, args.debug)

    # Render and save report
    report = render_report(results)
    print("\n" + "=" * 80)
    print("BATCH JOIN VALIDATION COMPLETE")
    print("=" * 80)
    print(report)

    try:
        with open(args.output_report, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"✅ Saved batch report to {args.output_report}")
    except Exception as e:
        print(f"❌ Error saving batch report: {e}")


if __name__ == '__main__':
    main()

