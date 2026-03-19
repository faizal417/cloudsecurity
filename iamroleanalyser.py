#!/usr/bin/env python3
"""
IAM Role Enumerator & Dangerous Permissions Checker
 
Checks all IAM roles for dangerous permission combinations
that could lead to privilege escalation"""
 
import boto3
import json
import sys
import argparse
from botocore.exceptions import ClientError, NoCredentialsError
 
# ---------------------------------------------------------------
# Dangerous permission combinations — based on real attack paths
# ---------------------------------------------------------------
DANGEROUS_COMBOS = [
    {
        "name": "EC2 Instance Profile Attachment (CloudGoat Scenario 1)",
        "description": "Allows attacker to attach a powerful role to EC2 and escalate privileges",
        "permissions": ["iam:PassRole", "ec2:AssociateIamInstanceProfile"],
    },
    {
        "name": "IAM User Privilege Escalation",
        "description": "Allows attacker to attach admin policy to any user including themselves",
        "permissions": ["iam:AttachUserPolicy"],
    },
    {
        "name": "IAM Role Privilege Escalation",
        "description": "Allows attacker to attach admin policy to any role",
        "permissions": ["iam:AttachRolePolicy"],
    },
    {
        "name": "Create Admin User",
        "description": "Allows attacker to create a new IAM user with admin access",
        "permissions": ["iam:CreateUser", "iam:AttachUserPolicy"],
    },
    {
        "name": "Assume Any Role",
        "description": "Allows attacker to assume any role in the account",
        "permissions": ["sts:AssumeRole"],
    },
    {
        "name": "Lambda Privilege Escalation",
        "description": "Allows attacker to create/update Lambda with a powerful role",
        "permissions": ["lambda:CreateFunction", "iam:PassRole", "lambda:InvokeFunction"],
    },
    {
        "name": "CloudFormation Privilege Escalation",
        "description": "Allows attacker to deploy CFN stack with admin role",
        "permissions": ["cloudformation:CreateStack", "iam:PassRole"],
    },
]
 
# ---------------------------------------------------------------
# Colours for terminal output
# ---------------------------------------------------------------
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
 
 
def get_iam_client(profile=None, region="us-east-1"):
    """Create IAM boto3 client using optional AWS profile."""
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        return session.client("iam")
    except Exception as e:
        print(f"{RED}[ERROR] Could not create session: {e}{RESET}")
        sys.exit(1)
 
 
def list_all_roles(iam_client):
    """Paginate through all IAM roles and return them."""
    roles = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        roles.extend(page["Roles"])
    return roles
 
 
def get_role_permissions(iam_client, role_name):
    """
    Get all permissions for a role by reading:
    1. Attached managed policies
    2. Inline policies
    Returns a flat set of allowed actions.
    """
    allowed_actions = set()
 
    # --- Managed policies ---
    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page["AttachedPolicies"]:
                policy_arn = policy["PolicyArn"]
                try:
                    # Get default version
                    policy_detail = iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = policy_detail["Policy"]["DefaultVersionId"]
                    version = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id
                    )
                    statements = version["PolicyVersion"]["Document"].get("Statement", [])
                    allowed_actions.update(_extract_allowed_actions(statements))
                except ClientError:
                    pass
    except ClientError:
        pass
 
    # --- Inline policies ---
    try:
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page["PolicyNames"]:
                try:
                    inline = iam_client.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )
                    statements = inline["PolicyDocument"].get("Statement", [])
                    allowed_actions.update(_extract_allowed_actions(statements))
                except ClientError:
                    pass
    except ClientError:
        pass
 
    return allowed_actions
 
 
def _extract_allowed_actions(statements):
    """Extract all Allow actions from a policy statement list."""
    actions = set()
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        # Action can be a string or a list
        if isinstance(raw, str):
            raw = [raw]
        for action in raw:
            actions.add(action.lower())
    return actions
 
 
def has_permission(allowed_actions, required_permission):
    """
    Check if a permission is covered — handles wildcards like:
    - '*'  (allow everything)
    - 'iam:*' (allow all IAM)
    - 'ec2:Describe*'
    """
    required = required_permission.lower()
    service, action = required.split(":", 1)
 
    for allowed in allowed_actions:
        if allowed == "*":
            return True
        if ":" not in allowed:
            continue
        a_service, a_action = allowed.split(":", 1)
        if a_service != service and a_service != "*":
            continue
        if a_action == "*":
            return True
        # Wildcard suffix match e.g. 'describe*'
        if a_action.endswith("*") and action.startswith(a_action[:-1]):
            return True
        if a_action == action:
            return True
    return False
 
 
def check_dangerous_combos(allowed_actions, role_name):
    """Check a role's permissions against all dangerous combos."""
    findings = []
    for combo in DANGEROUS_COMBOS:
        matched = all(
            has_permission(allowed_actions, perm)
            for perm in combo["permissions"]
        )
        if matched:
            findings.append(combo)
    return findings
 
 
def is_wildcard_role(allowed_actions):
    """Detect if a role has full Allow * permissions."""
    return "*" in allowed_actions
 
 
def main():
    parser = argparse.ArgumentParser(
        description="IAM Role Enumerator & Dangerous Permissions Checker"
    )
    parser.add_argument("--profile", default=None, help="AWS CLI profile name")
    parser.add_argument("--region",  default="us-east-1", help="AWS region")
    parser.add_argument("--output",  default=None, help="Save results to JSON file")
    args = parser.parse_args()
 
    print(f"\n{BOLD}{CYAN}{'='*60}")
    print("  IAM Role Enumerator — Piyush's Laboratory")
    print(f"{'='*60}{RESET}\n")
 
    # Connect
    iam = get_iam_client(profile=args.profile, region=args.region)
 
    # Get all roles
    print(f"{CYAN}[*] Fetching all IAM roles...{RESET}")
    try:
        roles = list_all_roles(iam)
    except NoCredentialsError:
        print(f"{RED}[ERROR] No AWS credentials found. Use --profile or set env vars.{RESET}")
        sys.exit(1)
 
    print(f"{GREEN}[+] Found {len(roles)} roles{RESET}\n")
 
    results = []
    dangerous_count = 0
 
    for role in roles:
        role_name = role["RoleName"]
        role_arn  = role["Arn"]
 
        print(f"{BOLD}[Role]{RESET} {role_name}")
 
        # Get permissions
        allowed = get_role_permissions(iam, role_name)
 
        # Wildcard check
        if is_wildcard_role(allowed):
            print(f"  {RED}[!!!] WILDCARD — Allow * on everything{RESET}")
 
        # Dangerous combo check
        findings = check_dangerous_combos(allowed, role_name)
 
        if findings:
            dangerous_count += 1
            for f in findings:
                print(f"  {RED}[DANGER]{RESET} {f['name']}")
                print(f"  {YELLOW}          {f['description']}{RESET}")
                print(f"  {YELLOW}          Permissions: {', '.join(f['permissions'])}{RESET}")
            results.append({
                "role_name": role_name,
                "role_arn": role_arn,
                "dangerous_combos": findings,
                "wildcard": is_wildcard_role(allowed),
            })
        else:
            print(f"  {GREEN}[OK] No dangerous combinations found{RESET}")
 
        print()
 
    # Summary
    print(f"{BOLD}{CYAN}{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}{RESET}")
    print(f"  Total roles scanned : {len(roles)}")
    print(f"  Dangerous roles     : {RED}{dangerous_count}{RESET}")
    print()
 
    if dangerous_count > 0:
        print(f"{RED}[!!!] Roles with dangerous permissions:{RESET}")
        for r in results:
            print(f"  - {r['role_name']} ({r['role_arn']})")
            for combo in r["dangerous_combos"]:
                print(f"      -> {combo['name']}")
    else:
        print(f"{GREEN}[+] No dangerous permission combinations found!{RESET}")
 
    # Optional JSON export
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n{GREEN}[+] Results saved to {args.output}{RESET}")
 
    print()
 
 
if __name__ == "__main__":
    main()
