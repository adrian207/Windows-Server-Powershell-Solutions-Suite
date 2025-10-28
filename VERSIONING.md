# Versioning Policy

**Author:** Adrian Johnson (adrian207@gmail.com)  
**Version:** 1.0.0  
**Last Updated:** December 2024

## 📋 Overview

This document outlines the versioning strategy for the **Windows Server PowerShell Solutions Suite**. The project follows [Semantic Versioning 2.0.0](https://semver.org/) principles.

## 🎯 Semantic Versioning

Version numbers follow the format: **MAJOR.MINOR.PATCH**

### Version Components

| Component | Description | Example | When to Increment |
|-----------|-------------|---------|-------------------|
| **MAJOR** | Breaking changes | 2.0.0 | • API changes incompatible with previous versions<br>• Major architectural changes<br>• Removed features or functionality |
| **MINOR** | New features (backward compatible) | 1.1.0 | • New modules or solutions added<br>• New functionality added<br>• Enhanced features without breaking changes |
| **PATCH** | Bug fixes (backward compatible) | 1.0.1 | • Bug fixes<br>• Performance improvements<br>• Documentation updates |

## 📊 Version Number Examples

| Version | Type | Example Changes |
|---------|------|-----------------|
| **1.0.0** | Initial Release | First stable release with all 18 solutions |
| **1.0.1** | Patch | Fixed bug in AD module error handling |
| **1.0.2** | Patch | Updated documentation and corrected typos |
| **1.1.0** | Minor | Added new Hyper-V snapshot management feature |
| **1.2.0** | Minor | Added new solution (e.g., Windows Server Update Services) |
| **2.0.0** | Major | Rewrote authentication system with breaking changes |

## 🔄 Release Types

### **Stable Release (Production)**
- Format: `MAJOR.MINOR.PATCH`
- Example: `1.0.0`, `1.2.5`, `2.0.0`
- Status: Production-ready, thoroughly tested
- Git Tag: `v1.0.0`

### **Release Candidate (RC)**
- Format: `MAJOR.MINOR.PATCH-rc.REVISION`
- Example: `1.1.0-rc.1`, `1.1.0-rc.2`
- Status: Feature-complete, pending final testing
- Git Tag: `v1.1.0-rc.1`

### **Beta Release**
- Format: `MAJOR.MINOR.PATCH-beta.REVISION`
- Example: `1.2.0-beta.1`, `1.2.0-beta.2`
- Status: Early access for testing new features
- Git Tag: `v1.2.0-beta.1`

### **Alpha Release (Development)**
- Format: `MAJOR.MINOR.PATCH-alpha.REVISION`
- Example: `2.0.0-alpha.1`
- Status: Active development, unstable
- Git Tag: `v2.0.0-alpha.1`

## 📝 Version File

A `version.json` file tracks the current version:

```json
{
  "version": "1.0.0",
  "major": 1,
  "minor": 0,
  "patch": 0,
  "build": "2024.12.24",
  "semver": "1.0.0",
  "status": "stable",
  "date": "2024-12-24",
  "author": "Adrian Johnson (adrian207@gmail.com)",
  "description": "Initial production release with 18 complete solutions"
}
```

## 🏷️ Git Tagging Strategy

### **Tag Format**
- **Stable:** `v1.0.0`, `v1.2.5`
- **RC:** `v1.1.0-rc.1`
- **Beta:** `v1.2.0-beta.1`
- **Alpha:** `v2.0.0-alpha.1`

### **Tag Annotation**
```bash
# Stable release
git tag -a v1.0.0 -m "Release version 1.0.0

Initial production release with 18 complete solutions:
- Active Directory Scripts (40 scenarios)
- AD Certificate Services (35 scenarios)
- Hyper-V Scripts (35 scenarios)
... (full list)

Author: Adrian Johnson <adrian207@gmail.com>
Date: December 24, 2024"

# Push tag to GitHub
git push origin v1.0.0
```

## 📅 Release Schedule

### **Regular Releases**
- **Major Releases:** Every 12-18 months
- **Minor Releases:** Every 2-3 months
- **Patch Releases:** As needed (typically monthly)

### **Hotfix Releases**
- Released immediately for critical security patches
- Follows `MAJOR.MINOR.PATCH` format
- Example: `1.0.1` (hotfix for `1.0.0`)

## 🔖 Branching Strategy

### **Main Branches**
- **`main`** - Production-ready code (tagged releases)
- **`develop`** - Integration branch for features

### **Supporting Branches**
- **`feature/`** - New features for next minor release
- **`hotfix/`** - Critical bug fixes for production
- **`release/`** - Preparation for new production release

### **Version Tags**
All production releases are tagged:
```bash
# List all version tags
git tag -l "v*"

# Show specific version tag
git show v1.0.0
```

## 📊 Version Tracking

### **README.md**
Every solution's README includes:
```markdown
**Version:** 1.0.0
**Date:** December 2024
```

### **Module Files**
Every PowerShell module includes:
```powershell
# Module Version
$script:ModuleVersion = '1.0.0'

# Version History
# 1.0.0 - 2024-12-24 - Initial release
```

### **Documentation Files**
All documentation includes:
```markdown
**Author:** Adrian Johnson (adrian207@gmail.com)
**Version:** 1.0.0
**Date:** December 2024
```

## 🔄 Release Process

### **1. Preparation**
- [ ] Update `version.json` with new version number
- [ ] Update all README files with new version
- [ ] Update module files with new version
- [ ] Update `CHANGELOG.md` with release notes

### **2. Testing**
- [ ] Run all test suites
- [ ] Verify all solutions work as expected
- [ ] Check for linter errors
- [ ] Review documentation accuracy

### **3. Release Creation**
- [ ] Create release branch if needed
- [ ] Merge changes to `main` branch
- [ ] Create annotated Git tag
- [ ] Push tag to GitHub

### **4. GitHub Release**
- [ ] Create GitHub release from tag
- [ ] Add release notes from CHANGELOG
- [ ] Upload any build artifacts if applicable
- [ ] Mark release as latest/pre-release

### **5. Documentation**
- [ ] Update CHANGELOG.md
- [ ] Verify all version references are updated
- [ ] Update this document if versioning policy changes

## 📈 Version Comparison

| Release Type | Stability | Recommended For |
|--------------|-----------|-----------------|
| **Stable** | ✅ Production-ready | All users, production environments |
| **RC** | ⚠️ Feature-complete | Testing before production deployment |
| **Beta** | ⚠️ Testing | Early adopters, test environments |
| **Alpha** | ❌ Development | Developers only |

## 🔗 References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Git Tagging Best Practices](https://git-scm.com/book/en/v2/Git-Basics-Tagging)

## 📞 Questions?

For questions about versioning:
- **Email:** adrian207@gmail.com
- **Issues:** [GitHub Issues](https://github.com/adrian207/Windows-Server-Powershell-Solutions-Suite/issues)

---

**Windows Server PowerShell Solutions Suite** - Professional versioning for enterprise deployments.

Copyright © 2024 Adrian Johnson. All rights reserved.

