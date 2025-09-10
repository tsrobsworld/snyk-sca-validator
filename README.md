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

## Support

For issues and questions:
1. Check the error messages in the output
2. Verify your API tokens have the correct permissions
3. Ensure repository URLs are accessible
4. Check network connectivity and API rate limits

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