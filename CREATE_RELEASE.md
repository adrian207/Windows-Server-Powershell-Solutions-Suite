# Creating GitHub Releases

**Author:** Adrian Johnson (adrian207@gmail.com)  
**Version:** 1.0.0  
**Last Updated:** December 2024

## 🎯 Overview

This guide explains how to create and manage GitHub releases for the Windows Server PowerShell Solutions Suite.

## 🏷️ Creating a Release via GitHub Web UI

### **Step 1: Access Releases Page**
1. Navigate to your repository on GitHub
2. Click on **"Releases"** in the right sidebar
3. Click **"Create a new release"**

### **Step 2: Fill Release Information**
- **Tag version:** Select or create tag (e.g., `v1.0.0`)
- **Release title:** `Release v1.0.0` or descriptive name
- **Description:** Copy content from `CHANGELOG.md` for the version

### **Step 3: Configure Release Settings**
- **Pre-release:** Uncheck for stable releases
- **Set as latest release:** Check for major/minor releases

### **Step 4: Publish Release**
Click **"Publish release"**

## 🤖 Creating a Release via GitHub CLI

### **Install GitHub CLI (if needed)**
```powershell
# Windows
winget install GitHub.cli

# Or download from: https://cli.github.com/
```

### **Authenticate**
```powershell
gh auth login
```

### **Create Release from Tag**
```powershell
# Create release from existing tag
gh release create v1.0.0 --title "Release v1.0.0" --notes "Initial production release"

# Or with file for notes
gh release create v1.0.0 --title "Release v1.0.0" --notes-file CHANGELOG.md
```

### **Create Pre-release**
```powershell
# Release Candidate
gh release create v1.1.0-rc.1 --title "Release Candidate v1.1.0-rc.1" --prerelease

# Beta
gh release create v1.2.0-beta.1 --title "Beta Release v1.2.0-beta.1" --prerelease

# Alpha
gh release create v2.0.0-alpha.1 --title "Alpha Release v2.0.0-alpha.1" --prerelease
```

## 📦 Automated Release via GitHub Actions

### **Manual Trigger**
1. Go to **Actions** tab
2. Select **Release Management** workflow
3. Click **"Run workflow"**
4. Enter version number (e.g., `1.0.0`)
5. Select release type (stable, rc, beta, alpha)
6. Waiting for the workflow to complete

### **Trigger via Git Tag**
```bash
# Create and push tag
git tag -a v1.0.1 -m "Release version 1.0.1"
git push origin v1.0.1

# GitHub Actions will automatically create the release
```

## 📝 Best Practices

### **Release Notes Format**
```markdown
## 🎉 Release Name

### ✨ What's New
- Feature 1
- Feature 2

### 🐛 Bug Fixes
- Fix 1
- Fix 2

### 🔒 Security Updates
- Security update 1

### 📚 Documentation
- Updated documentation

### 🔗 Links
- Full Changelog: [link]
- Documentation: [link]
```

### **Version Numbering**
- **Major:** Breaking changes
- **Minor:** New features (backward compatible)
- **Patch:** Bug fixes (backward compatible)
- **Pre-release:** Add `-rc.1`, `-beta.1`, or `-alpha.1`

### **Timing**
- **Major releases:** Every 12-18 months
- **Minor releases:** Every 2-3 months
- **Patch releases:** As needed (typically monthly)

## 📊 Release Checklist

Before creating a release:

- [ ] Update `CHANGELOG.md` with all changes
- [ ] Update `version.json` with new version
- [ ] Update all README files with new version
- [ ] Test all changes thoroughly
- [ ] Run all test suites
- [ ] Check for linter errors
- [ ] Review documentation accuracy
- [ ] Create Git tag with proper annotation
- [ ] Push tag to GitHub
- [ ] Create GitHub release
- [ ] Verify release notes are complete

## 🔗 Additional Resources

- [CHANGELOG.md](CHANGELOG.md) - Version history
- [VERSIONING.md](VERSIONING.md) - Versioning policy
- [version.json](version.json) - Current version info
- [GitHub Releases Documentation](https://docs.github.com/en/repositories/releasing-projects-on-github)

## 📞 Support

For questions about releases:
- **Email:** adrian207@gmail.com
- **Issues:** [GitHub Issues](https://github.com/adrian207/Windows-Server-Powershell-Solutions-Suite/issues)

---

**Windows Server PowerShell Solutions Suite** - Professional release management.

Copyright © 2024 Adrian Johnson. All rights reserved.

