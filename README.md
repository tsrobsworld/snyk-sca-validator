# Snyk SCA File Validator

A comprehensive tool for validating Snyk SCA (Software Composition Analysis) files against their actual repository sources. This validator uses an efficient join-based approach to match GitLab repositories with Snyk targets, ensuring that Snyk projects reference files that actually exist in the source repositories.

## How It Works

The validator uses a batch join approach for efficient validation:

1. **Builds a GitLab Repository Catalog**: Lists all accessible GitLab repositories with their metadata (default branch, project path, etc.)
2. **Collects Snyk Targets**: Gathers all Snyk targets from specified organizations and normalizes their repository URLs
3. **Joins the Datasets**: Matches GitLab repositories with Snyk targets using canonical repository keys
4. **Validates and Reports**: 
   - Validates that Snyk-tracked files exist in GitLab repositories
   - Identifies Snyk-supported files that aren't being tracked by Snyk
   - Reports on stale Snyk targets (repositories no longer in GitLab)
   - Reports on GitLab repositories with no Snyk coverage

## Features

- **Comprehensive Coverage Analysis**: Identifies matched repos, stale Snyk targets, and untracked GitLab repositories
- **Detailed Reporting**: Generates comprehensive reports showing:
  - Matched repositories with file validation results
  - Stale Snyk targets (repositories no longer in GitLab)
  - GitLab repositories with no Snyk coverage
  - Snyk-supported files not being tracked
  - Duplicate projects with KEEP/REMOVE recommendations
- **CSV Export**: Generate filterable CSV reports for duplicate projects
- **Flexible Configuration**: Supports different Snyk regions and GitLab instances
- **Debug Mode**: Optional detailed logging for troubleshooting

## Supported Repository Types

### GitLab Integration Projects
- Standard GitLab.com repositories
- Custom GitLab instances

### CLI Projects
- Local file paths (`file://` and absolute paths)
- SSH URLs (`git@host:owner/repo.git`)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/tsrobsworld/snyk-sca-validator
cd snyk_sca_validator
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Validate all organizations:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN
```

Validate a specific organization:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --org-id ORG_ID
```

Validate all organizations in a group:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --group-id GROUP_ID
```

With GitLab token for private repositories:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --gitlab-token YOUR_GITLAB_TOKEN
```

Generate CSV report for duplicate projects:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --org-id ORG_ID --duplicates-csv duplicates.csv
```

### Advanced Usage

Custom GitLab instance:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --gitlab-url https://gitlab.company.com
```

Different Snyk region:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --snyk-region SNYK-EU-01
```

Custom output report:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --output-report my_report.txt
```

Debug logging for troubleshooting:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --debug
```

## Command Line Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `--snyk-token` | Snyk API token | Yes | - |
| `--org-id` | Specific Snyk organization ID (mutually exclusive with --group-id) | No | All organizations |
| `--group-id` | Snyk group ID to process all organizations in group (mutually exclusive with --org-id) | No | - |
| `--snyk-region` | Snyk API region | No | SNYK-US-01 |
| `--gitlab-token` | GitLab API token for private repos | No | - |
| `--gitlab-url` | GitLab instance URL | No | https://gitlab.com |
| `--output-report` | Custom report filename | No | batch_report.txt |
| `--duplicates-csv` | Generate CSV file with duplicate projects (KEEP and REMOVE) | No | - |
| `--timeout` | HTTP request timeout in seconds | No | 60 |
| `--max-retries` | Maximum retry attempts for failed requests | No | 3 |
| `--no-ssl-verify` | Disable SSL certificate verification for GitLab API calls | No | False |
| `--skip-org-validation` | Skip Snyk org access validation and fetch targets directly | No | False |
| `--debug` | Enable debug logging for troubleshooting | No | False |

## Supported Snyk Regions

- `SNYK-US-01` (default): https://api.snyk.io
- `SNYK-US-02`: https://api.us.snyk.io
- `SNYK-EU-01`: https://api.eu.snyk.io
- `SNYK-AU-01`: https://api.au.snyk.io

## Output Files

### Batch Report
The validator generates a comprehensive text report (`batch_report.txt` by default) containing:

**Summary Section:**
- Total number of matched repositories
- Number of stale Snyk targets (repositories no longer in GitLab)
- Number of GitLab repositories with no Snyk coverage

**Snyk-Only (Stale Targets) Section:**
- Lists repositories that have Snyk targets but are no longer accessible in GitLab
- Useful for cleaning up old Snyk projects

**GitLab-Only (No Snyk Targets) Section:**
- Lists GitLab repositories that have no Snyk coverage
- Useful for identifying repositories that should be imported into Snyk

**Matched Repositories Section:**
- For each matched repository:
  - Number of files tracked by Snyk
  - Number of Snyk-supported files found in the repository
  - List of supported files not being tracked by Snyk (potential missing projects)

**Duplicate Projects Section:**
- Lists duplicate Snyk projects detected within the same target
- Shows which project to KEEP (newest) and which to REMOVE (stale duplicates)
- For Maven projects, includes artifactId validation:
  - Expected artifactId (from project name suffix after ':')
  - Found artifactId (from pom.xml in repository)
  - Match status (MATCH/MISMATCH)
  - Discovered pom.xml paths and their artifactIds

### CSV Duplicate Report

When using the `--duplicates-csv` flag, a CSV file is generated with all duplicate projects in a filterable format. The CSV includes:

- **Action**: KEEP or REMOVE
- **Unique Identifier**: The part of the project name after ':'
- **Project Name**: Full Snyk project name
- **Project ID**: Snyk project UUID
- **Type**: Project type (maven, npm, etc.)
- **Created Date**: When the project was created
- **Org ID**: Snyk organization ID
- **Project URL**: Direct link to the Snyk project
- **Expected ArtifactId**: For Maven projects, the expected artifactId
- **Found ArtifactId**: The actual artifactId found in pom.xml
- **ArtifactId Match Status**: MATCH or MISMATCH
- **Reason**: Why the project should be kept or removed

This CSV format makes it easy to filter and sort duplicate projects for review and cleanup.

## Repository URL Support

### GitLab URLs
- `https://gitlab.com/owner/repo`
- `https://gitlab.com/owner/repo/tree/branch`
- `https://gitlab.com/owner/repo/-/tree/branch`
- `https://gitlab.com/owner/repo/-/blob/branch/file`
- Custom instances: `https://gitlab.company.com/owner/repo`

### CLI Project URLs
- Local paths: `file:///path/to/repo` or `/path/to/repo`
- SSH URLs: `git@gitlab.com:owner/repo.git`
- GitHub: `https://github.com/owner/repo`
- Bitbucket: `https://bitbucket.org/owner/repo`

## Debug Logging

The `--debug` flag enables comprehensive debug logging to help troubleshoot repository mapping issues. When enabled, the script will log:

- **URL Parsing**: Detailed information about how repository URLs are parsed and which patterns match/fail
- **Repository Mapping**: Shows the mapping from Snyk target URLs to parsed repository information
- **API Calls**: Complete request/response details for all API calls to Snyk, GitLab, GitHub, and Bitbucket
- **File Validation**: Shows which repository each file validation is being performed against
- **Missing File Detection**: Details about what files are found in repos vs. what Snyk is tracking


## Use Cases

### 1. Repository Cleanup
Identify Snyk projects that reference files no longer present in repositories, allowing you to clean up stale projects.

### 2. Migration Validation
After migrating repositories or changing file structures, validate that Snyk projects still reference the correct files.

### 3. Compliance Auditing
Ensure that all SCA files tracked by Snyk are actually present in the source repositories for compliance purposes.

### 4. Project Synchronization
Identify discrepancies between Snyk project configurations and actual repository contents.

## Limitations

1. **File Content Validation**: Currently only checks file existence, not content differences
2. **Branch Detection**: Uses default branch detection logic; may need adjustment for specific workflows
3. **Private Repository Access**: Requires appropriate API tokens for private repositories
4. **Rate Limiting**: Subject to API rate limits of the respective platforms

## Requirements

- Python 3.7+
- Snyk API token
- GitLab API token (for private GitLab repositories)
- Internet access for API calls

## Dependencies

- `requests`: HTTP library for API calls
- `argparse`: Command-line argument parsing
- `csv`: CSV file handling
- `json`: JSON data processing
- `re`: Regular expressions for URL parsing
- `os`: Operating system interface
- `datetime`: Date and time handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Changelog

### Version 2.1
- Added duplicate project detection based on name patterns
- Implemented Maven artifactId validation for duplicate projects
- Added CSV export for duplicate projects (`--duplicates-csv` flag)
- Added support for processing all organizations in a group (`--group-id`)
- Added `--skip-org-validation` flag for organizations with validation endpoint issues
- Improved GitLab API pagination for nested file discovery
- Enhanced pom.xml discovery with recursive repository scanning

### Version 2.0
- Added support for CLI projects
- Enhanced URL parsing for multiple platforms
- Improved API efficiency with source filtering
- Added support for GitHub and Bitbucket repositories
- Better error handling and logging

### Version 1.0
- Initial release with GitLab integration support
- Basic file validation functionality
- CSV and text report generation

## Contributing

We welcome contributions! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/snyk-sca-validator.git`
3. Install dependencies: `pip install -r requirements.txt`
4. Create a feature branch: `git checkout -b feature/amazing-feature`
5. Make your changes and test them
6. Commit your changes: `git commit -m 'Add some amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

### Code Style

- Follow PEP 8 for Python code
- Add type hints where appropriate
- Include docstrings for new functions
- Add tests for new functionality

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is not officially affiliated with Snyk. It's a community-driven utility for validating Snyk SCA file tracking. Use at your own discretion and ensure you comply with Snyk's terms of service and API usage policies.