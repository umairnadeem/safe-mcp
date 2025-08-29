# SAFE-T1002: Supply Chain Compromise

## Overview
**Tactic**: Initial Access (ATK-TA0001)  
**Technique ID**: SAFE-T1002  
**Severity**: Critical  
**First Observed**: June 2025 (SQL injection in Anthropic’s SQLite MCP server)  
**Last Updated**: 2025-04-25

## Description
Supply Chain Compromise in the MCP context involves attackers distributing backdoored MCP server packages through unofficial repositories, compromised legitimate sources (as in Anthropic's case), or by hijacking the distribution channels of trusted MCP tools. This technique exploits the trust relationships between developers and package repositories to deliver malicious MCP servers that appear legitimate but contain hidden malicious functionality.

Unlike direct tool poisoning attacks, supply chain compromise targets the distribution infrastructure itself, allowing attackers to compromise multiple users simultaneously through a single malicious package. This technique is particularly dangerous because it can bypass individual security controls and affect entire organizations that rely on the same MCP server packages. The blast radius can be especially severe since third-party packages are often widely distributed across fleets and ecosystems.

## Attack Vectors
- **Primary Vector**: Compromised package repositories distributing backdoored MCP servers
- **Secondary Vectors**: 
  - Typosquatting on popular MCP server names in package registries
  - Compromised developer accounts publishing malicious updates
  - Man-in-the-middle attacks on package download channels
  - Dependency confusion attacks targeting internal package feeds
  - Compromised CI/CD pipelines injecting malicious code during builds

## Technical Details

### Prerequisites
- Access to package repository infrastructure or developer accounts
- Understanding of target MCP server's functionality and dependencies
- Ability to create or modify package distribution channels
- Knowledge of target organization's package management practices

### Attack Flow
1. **Initial Reconnaissance**: Attacker identifies popular MCP servers and their distribution channels
2. **Infrastructure Compromise**: Gain access to package repository, developer account, or CI/CD pipeline
3. **Malicious Package Creation**: Create backdoored version of legitimate MCP server
4. **Distribution**: Publish malicious package through compromised channels
5. **Exploitation**: Wait for users to install the compromised package
6. **Post-Exploitation**: Execute malicious functionality when MCP server is activated

### Example Scenario
```json
// Legitimate package.json for popular MCP server
{
  "name": "mcp-github",
  "version": "1.2.0",
  "description": "GitHub integration for MCP",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0"
  }
}

// Malicious package.json with hidden dependency
{
  "name": "mcp-github",
  "version": "1.2.0",
  "description": "GitHub integration for MCP",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "postinstall": "node .hidden/backdoor.js"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0",
    "legitimate-looking-package": "1.0.0"
  },
  "devDependencies": {
    "hidden-malware": "file:.hidden/malware.tgz"
  }
}
```

### Advanced Attack Techniques (2025 Research)

According to recent security research, sophisticated supply chain attacks in the MCP ecosystem include:

1. **Dependency Confusion**: Attackers publish malicious packages with names matching internal dependencies, exploiting package manager resolution precedence
2. **Build Pipeline Compromise**: Malicious code injected during CI/CD builds that only activates in production environments
3. **Package Registry Hijacking**: Compromised developer accounts used to publish malicious updates to legitimate packages
4. **Multi-Stage Malware**: Initial package appears benign but downloads additional malicious components after installation

## Impact Assessment
- **Confidentiality**: Critical - Direct access to all data accessible through compromised MCP servers
- **Integrity**: High - Ability to modify data and systems through compromised tools
- **Availability**: Medium - Potential for service disruption through malicious server behavior
- **Scope**: Enterprise-wide - Single compromised package can affect entire organizations

### Current Status (2025)
Supply chain attacks targeting MCP servers have been observed in research environments and are considered a high-priority threat. The MCP ecosystem's rapid growth and lack of standardized security practices make it an attractive target for sophisticated attackers.

## Detection Methods

### Indicators of Compromise (IoCs)
- Unexpected network connections from MCP servers
- Unusual file system access patterns
- Suspicious package checksums or signatures
- Unexpected dependencies in package manifests
- Anomalous behavior after package updates

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Attackers continuously develop new supply chain compromise techniques. Organizations should:
- Implement comprehensive package verification procedures
- Use multiple detection methods beyond pattern matching
- Regularly audit package dependencies and sources
- Monitor for unexpected network or file system activity

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: MCP Supply Chain Compromise Detection
id: 9f4e8b93-5c67-4d89-a890-3d6f9g0b4e22
status: experimental
description: Detects potential supply chain compromise in MCP server packages
author: SAFE-MCP Team
date: 2025-08-28
references:
  - https://github.com/fkautz/safe-mcp/tree/main/techniques/SAFE-T1002
logsource:
  product: mcp
  service: package_management
detection:
  selection_suspicious_package:
    package_name|contains:
      - 'mcp-'
      - 'model-context-'
    package_source|not:
      - 'npmjs.org'
      - 'pypi.org'
      - 'github.com'
  selection_suspicious_checksum:
    package_checksum|not:
      - 'verified_checksum_1'
      - 'verified_checksum_2'
  selection_unexpected_dependencies:
    dependency_name|contains:
      - 'hidden'
      - 'backdoor'
      - 'malware'
  condition: selection_suspicious_package or selection_suspicious_checksum or selection_unexpected_dependencies
falsepositives:
  - Legitimate packages from alternative sources
  - Development/testing packages
  - Custom internal packages
level: high
tags:
  - attack.initial_access
  - attack.t1195
  - safe.t1002
```

### Behavioral Indicators
- MCP servers making unexpected network connections
- Unusual file system access patterns
- Unexpected tool behavior after package updates
- Suspicious process creation from MCP server processes

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-6: Tool Registry Verification](../../mitigations/SAFE-M-6/README.md)**: Install MCP servers only from verified sources with cryptographic signatures
2. **[SAFE-M-2: Cryptographic Integrity](../../mitigations/SAFE-M-2/README.md)**: Verify package integrity using digital signatures and checksums
3. **[SAFE-M-9: Sandboxed Testing](../../mitigations/SAFE-M-9/README.md)**: Test new packages in isolated environments before production deployment
4. **Package Source Verification**: Maintain allowlists of trusted package sources and verify package origins
5. **Dependency Auditing**: Regularly audit package dependencies for suspicious additions or changes

### Detective Controls
1. **[SAFE-M-10: Automated Scanning](../../mitigations/SAFE-M-10/README.md)**: Scan all MCP server packages for known malicious patterns
2. **[SAFE-M-11: Behavioral Monitoring](../../mitigations/SAFE-M-11/README.md)**: Monitor MCP server behavior for anomalies
3. **[SAFE-M-12: Audit Logging](../../mitigations/SAFE-M-12/README.md)**: Log all package installations and updates with verification results

### Response Procedures
1. **Immediate Actions**:
   - Remove compromised packages from all systems
   - Revoke any credentials or tokens used by compromised servers
   - Alert affected users and security teams
2. **Investigation Steps**:
   - Analyze compromised packages for malicious functionality
   - Trace distribution channels to identify compromise source
   - Assess scope of compromise across affected systems
3. **Remediation**:
   - Restore packages from verified sources
   - Implement additional verification controls
   - Update security policies for package management

## Related Techniques
- [SAFE-T1001](../SAFE-T1001/README.md): Tool Poisoning Attack - Similar malicious functionality in MCP servers

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST SP 800-204D: Software Supply Chain Security in DevSecOps](https://csrc.nist.gov/pubs/sp/800/204/d/final)
- [In-Toto: Securing Software Supply Chains — A Comprehensive Guide - ThamizhElango Natarajan](https://thamizhelango.medium.com/in-toto-securing-software-supply-chains-a-comprehensive-guide-76945d257004)
- [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies - Alex Birsan](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [Why a Classic MCP Server Vulnerability Can Undermine Your Entire AI Agent](https://www.trendmicro.com/en_fi/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html)

## MITRE ATT&CK Mapping
- [T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
- [T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/) (for data exfiltration through compromised tools)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-20 | Initial documentation based on supply chain security research and MCP ecosystem analysis | Umair Nadeem |
