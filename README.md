# Snyk SCA File Validator

A comprehensive tool for validating Snyk SCA (Software Composition Analysis) files against their actual repository sources. This validator supports both GitLab integration projects and CLI-created projects, ensuring that Snyk projects reference files that actually exist in the source repositories.

## Features

- **Multi-Platform Support**: Works with GitLab, GitHub, Bitbucket, and local repositories
- **Efficient API Usage**: Uses `source_types` filtering to only process GitLab and CLI projects
- **Comprehensive Validation**: Checks file existence and content across different platforms
- **Detailed Reporting**: Generates both CSV and human-readable reports
- **Flexible Configuration**: Supports different Snyk regions and GitLab instances

## Supported Repository Types

### GitLab Integration Projects
- Standard GitLab.com repositories
- Custom GitLab instances
- Both old and new GitLab URL formats (`/tree/` and `/-/tree/`)

### CLI Projects
- Local file paths (`file://` and absolute paths)
- SSH URLs (`git@host:owner/repo.git`)
- GitHub repository references
- Bitbucket repository references

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
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

### Advanced Usage

With GitLab token for private repositories:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --gitlab-token YOUR_GITLAB_TOKEN
```

Custom GitLab instance:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --gitlab-url https://gitlab.company.com
```

Different Snyk region:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --snyk-region SNYK-EU-01
```

Custom output files:
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --output-csv results.csv --output-report report.txt
```

Dry run (simulation only):
```bash
python3 snyk_sca_validator.py --snyk-token YOUR_SNYK_TOKEN --dry-run
```

## Command Line Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `--snyk-token` | Snyk API token | Yes | - |
| `--org-id` | Specific Snyk organization ID | No | All organizations |
| `--snyk-region` | Snyk API region | No | SNYK-US-01 |
| `--gitlab-token` | GitLab API token for private repos | No | - |
| `--gitlab-url` | GitLab instance URL | No | https://gitlab.com |
| `--output-csv` | Custom CSV output filename | No | Auto-generated |
| `--output-report` | Custom report filename | No | Auto-generated |
| `--dry-run` | Simulation mode (no API calls) | No | False |
| `--verbose` | Detailed output | No | False |
| `--debug` | Enable debug logging for troubleshooting repository mapping issues | No | False |
| `--list-orgs` | List all accessible organizations and exit | No | False |

## Supported Snyk Regions

- `SNYK-US-01` (default): https://api.snyk.io
- `SNYK-US-02`: https://api.us.snyk.io
- `SNYK-EU-01`: https://api.eu.snyk.io
- `SNYK-AU-01`: https://api.au.snyk.io

## Output Files

### CSV Report
Contains detailed validation results with columns:
- `org_id`: Snyk organization ID
- `target_id`: Snyk target ID
- `target_name`: Target display name
- `target_url`: Repository URL
- `project_id`: Snyk project ID
- `project_name`: Project name
- `project_type`: Project type (npm, maven, etc.)
- `root_dir`: Project root directory
- `file_path`: File path in Snyk
- `full_path`: Full file path in repository
- `exists_in_gitlab`: Boolean indicating if file exists
- `last_checked`: Timestamp of validation

### Text Report
Contains a human-readable summary including:
- Overall statistics
- Organization-level summaries
- Target-level details
- Project-level validation results
- List of missing files

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

## How It Works

1. **Fetch Organizations**: Retrieves all accessible Snyk organizations
2. **Filter Targets**: Uses `source_types=gitlab,cli` to only get relevant targets
3. **Parse URLs**: Extracts repository information from target URLs
4. **Validate Files**: Checks if Snyk-tracked files exist in the actual repositories
5. **Generate Reports**: Creates detailed CSV and text reports

## Debug Logging

The `--debug` flag enables comprehensive debug logging to help troubleshoot repository mapping issues. When enabled, the script will log:

- **URL Parsing**: Detailed information about how repository URLs are parsed and which patterns match/fail
- **Repository Mapping**: Shows the mapping from Snyk target URLs to parsed repository information
- **API Calls**: Complete request/response details for all API calls to Snyk, GitLab, GitHub, and Bitbucket
- **File Validation**: Shows which repository each file validation is being performed against
- **Missing File Detection**: Details about what files are found in repos vs. what Snyk is tracking

Example debug output:
```
[14:23:45.123] 🔍 DEBUG: Parsing URL: https://gitlab.com/owner/repo
[14:23:45.124] 🔍 DEBUG: GitLab pattern 1 match result: True
[14:23:45.125] 🔍 DEBUG: Successfully parsed URL - Platform: gitlab, Owner: owner, Repo: repo
[14:23:45.126] 🔍 DEBUG: Repository mapping successful
[14:23:45.127] 🔍 DEBUG: Mapped to platform: gitlab
[14:23:45.128] 🔍 DEBUG: API Request - URL: https://api.gitlab.com/api/v4/projects/owner%2Frepo
```

## Error Handling

The script includes comprehensive error handling for:
- Invalid repository URLs
- Network connectivity issues
- API rate limiting
- Missing or invalid tokens
- Repository access permissions
- File not found errors

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

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Troubleshooting

### Common Issues

#### 404 Organization Not Found
If you get a 404 error when trying to access an organization:

```bash
Error validating organization 03c78318-dfc6-4b48-9fd4-76a8254aa225: 404 Client Error: Not Found
```

This usually means:
1. **Invalid Organization ID** - The organization ID doesn't exist
2. **Access Denied** - Your token doesn't have access to this organization
3. **Organization Deleted** - The organization was deleted or moved

**Solutions:**
1. **List accessible organizations:**
   ```bash
   python3 snyk_sca_validator.py --snyk-token YOUR_TOKEN --list-orgs
   ```

2. **Use debug mode to see detailed error information:**
   ```bash
   python3 snyk_sca_validator.py --snyk-token YOUR_TOKEN --org-id ORG_ID --debug
   ```

3. **Verify your token has the correct permissions** - Check that your Snyk token has access to the organization you're trying to validate

#### Authentication Issues
If you get 401 or 403 errors:
- Verify your Snyk token is valid and not expired
- Check that your token has the necessary permissions
- Ensure you're using the correct Snyk region

#### Repository Access Issues
If repository files can't be accessed:
- For private GitLab repositories, provide a GitLab token: `--gitlab-token YOUR_GITLAB_TOKEN`
- For custom GitLab instances, specify the URL: `--gitlab-url https://gitlab.company.com`
- Use debug mode to see detailed API call information

## Support

For issues and questions:
1. Check the error messages in the output
2. Use `--debug` flag for detailed troubleshooting information
3. Use `--list-orgs` to verify accessible organizations
4. Verify your API tokens have the correct permissions
5. Ensure repository URLs are accessible
6. Check network connectivity and API rate limits

## Changelog

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