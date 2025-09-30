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

try:
    # Reuse existing clients and supported file logic
    from snyk_sca_validator import SnykAPI, GitLabClient, SCAValidator, debug_log
except Exception:
    print("❌ Could not import from snyk_sca_validator.py. Ensure it exists in the same directory.")
    sys.exit(1)


def build_gitlab_repo_catalog(gitlab: GitLabClient, debug: bool = False) -> Dict[str, Dict]:
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
        resp = session.get(url, params=params)
        debug_log(f"GitLab list projects status: {resp.status_code}", debug)
        if resp.status_code != 200:
            debug_log(f"GitLab list projects error body: {resp.text}", debug)
            break

        projects = resp.json()
        if not projects:
            break

        for p in projects:
            # path_with_namespace: group/subgroup/project
            full_path = p.get('path_with_namespace')
            if not full_path:
                continue
            key = f"{gitlab.gitlab_url.replace('https://', '').replace('http://', '').rstrip('/')}/{full_path}"
            catalog[key] = {
                'id': p.get('id'),
                'default_branch': p.get('default_branch'),
                'path_with_namespace': full_path,
                'web_url': p.get('web_url')
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
    Only GitLab targets are included in the catalog.
    """
    catalog: Dict[str, List[Dict]] = {}
    for org_id in org_ids:
        targets = snyk.get_targets_for_org(org_id)
        for t in targets:
            attrs = t.get('attributes', {})
            url = attrs.get('url')
            repo_info = gitlab.parse_repo_url(url)
            if not repo_info or repo_info.get('platform') != 'gitlab':
                continue
            # canonical key must match GitLab catalog key build
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
                'repo_info': repo_info
            })
    return catalog


def normalize_key(host: str, full_path: str) -> str:
    # Keep case as-is to respect GitLab path semantics; trim slashes
    return f"{host.rstrip('/')}/{full_path.strip('/')}"


def extract_org_ids(args, snyk: SnykAPI) -> List[str]:
    if args.org_id:
        return [args.org_id]
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
    matched_keys: Set[str] = set(gitlab_catalog.keys()) & set(snyk_targets_by_key.keys())
    snyk_only_keys: Set[str] = set(snyk_targets_by_key.keys()) - set(gitlab_catalog.keys())
    gitlab_only_keys: Set[str] = set(gitlab_catalog.keys()) - set(snyk_targets_by_key.keys())

    results = {
        'matched': [],
        'snyk_only': [],
        'gitlab_only': []
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
        per_target_results = []
        for t in targets:
            org_id = t['org_id']
            target_id = t['target_id']
            projects = snyk.get_projects_for_target(org_id, target_id)

            project_file_checks: List[Dict] = []
            for p in projects:
                attrs = p.get('attributes', {})
                file_paths = validator._extract_file_paths_from_project(attrs)
                if not file_paths:
                    continue
                for fp in file_paths:
                    tracked_files.add(fp)
                    check = validator.validate_file(gitlab_repo_info, fp, attrs.get('root', ''))
                    project_file_checks.append(check)

            per_target_results.append({
                'org_id': org_id,
                'target_id': target_id,
                'target_name': t['target_name'],
                'target_url': t['target_url'],
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
            'tracked_files_count': len(tracked_files),
            'supported_files_count': len(supported_paths),
            'untracked_supported_files': untracked_supported[:200]  # limit to keep report reasonable
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
    lines.append("")

    lines.append("SNYK-ONLY (STALE TARGETS)")
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

    lines.append("MATCHED REPOSITORIES")
    lines.append("-" * 40)
    for m in results['matched'][:200]:
        lines.append(f"Repo key: {m['repo_key']}")
        lines.append(f"  Tracked files in Snyk: {m['tracked_files_count']}  Snyk supported files: {m['supported_files_count']}")
        if m['untracked_supported_files']:
            lines.append("  Supported files not tracked by Snyk:")
            for fp in m['untracked_supported_files']:
                lines.append(f"    - {fp}")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Batch join-mode Snyk/GitLab validator")
    parser.add_argument('--snyk-token', required=True, help='Snyk API token')
    parser.add_argument('--org-id', help='Specific Snyk organization ID (optional)')
    parser.add_argument('--snyk-region', default='SNYK-US-01', help='Snyk API region')
    parser.add_argument('--gitlab-token', help='GitLab API token for private repositories')
    parser.add_argument('--gitlab-url', default='https://gitlab.com', help='GitLab instance URL')
    parser.add_argument('--output-report', default='batch_report.txt', help='Output report filename')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    # Initialize clients
    snyk = SnykAPI(args.snyk_token, args.snyk_region, args.debug)
    gitlab = GitLabClient(args.gitlab_token, args.gitlab_url, args.debug)
    validator = SCAValidator(snyk, gitlab, args.debug)

    # Determine organizations to process
    org_ids = extract_org_ids(args, snyk)
    if not org_ids:
        print("❌ No organizations to process")
        sys.exit(1)

    # Build catalogs
    print("📚 Building GitLab repository catalog...")
    gl_catalog = build_gitlab_repo_catalog(gitlab, args.debug)
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

