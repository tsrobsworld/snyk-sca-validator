#!/bin/bash

# Example usage script for Snyk SCA Validator
# Make sure to set your API tokens before running

# Set your API tokens (replace with your actual tokens)
export SNYK_TOKEN="your_snyk_token_here"
export GITLAB_TOKEN="your_gitlab_token_here"  # Optional

echo "Snyk SCA Validator - Example Usage"
echo "==================================="

# Example 1: Basic validation of all organizations
echo "Example 1: Validate all organizations"
echo "Command: python3 snyk_sca_validator.py --snyk-token \$SNYK_TOKEN"
echo ""

# Example 2: Validate specific organization
echo "Example 2: Validate specific organization"
echo "Command: python3 snyk_sca_validator.py --snyk-token \$SNYK_TOKEN --org-id YOUR_ORG_ID"
echo ""

# Example 3: With GitLab token for private repositories
echo "Example 3: With GitLab token for private repositories"
echo "Command: python3 snyk_sca_validator.py --snyk-token \$SNYK_TOKEN --gitlab-token \$GITLAB_TOKEN"
echo ""

# Example 4: Custom GitLab instance
echo "Example 4: Custom GitLab instance"
echo "Command: python3 snyk_sca_validator.py --snyk-token \$SNYK_TOKEN --gitlab-url https://gitlab.company.com"
echo ""

# Example 5: Custom output report
echo "Example 5: Custom output report"
echo "Command: python3 snyk_sca_validator.py --snyk-token \$SNYK_TOKEN --output-report my_report.txt"
echo ""

# Example 6: Different Snyk region
echo "Example 6: Different Snyk region"
echo "Command: python3 snyk_sca_validator.py --snyk-token \$SNYK_TOKEN --snyk-region SNYK-EU-01"
echo ""

# Example 7: Debug logging
echo "Example 7: Debug logging for troubleshooting"
echo "Command: python3 snyk_sca_validator.py --snyk-token \$SNYK_TOKEN --debug"
echo ""

echo "To run any of these examples:"
echo "1. Set your API tokens in the environment variables above"
echo "2. Uncomment and run the desired command"
echo "3. Check the generated batch_report.txt file for results"
echo ""

# Uncomment one of these to run:
# python3 snyk_sca_validator.py --snyk-token $SNYK_TOKEN
# python3 snyk_sca_validator.py --snyk-token $SNYK_TOKEN --org-id YOUR_ORG_ID
# python3 snyk_sca_validator.py --snyk-token $SNYK_TOKEN --gitlab-token $GITLAB_TOKEN
# python3 snyk_sca_validator.py --snyk-token $SNYK_TOKEN --gitlab-url https://gitlab.company.com
# python3 snyk_sca_validator.py --snyk-token $SNYK_TOKEN --snyk-region SNYK-EU-01
# python3 snyk_sca_validator.py --snyk-token $SNYK_TOKEN --output-report my_report.txt
# python3 snyk_sca_validator.py --snyk-token $SNYK_TOKEN --debug