# iOS Penetration Testing Checklist

## 1. Basic Operations

### IPA Management
- [ ] Install IPA using ideviceinstaller
- [ ] Uninstall IPA using ideviceinstaller
- [ ] Set up local web server for IPA distribution
- [ ] Install IPA using ReProvision Reborn
- [ ] Install IPA using 3uTools (if needed)

### Device Access
- [ ] SSH to iOS device
- [ ] Download files from iOS device
- [ ] Upload files to iOS device
- [ ] Edit files using nano

## 2. IPA Inspection

### Decryption and Analysis
- [ ] Pull decrypted IPA using frida-ios-dump
- [ ] Unpack IPA file
- [ ] Analyze binary for keywords
- [ ] Search for WebView implementations
- [ ] Extract endpoints and sensitive data
- [ ] Use AppInfoScanner for endpoint extraction

### Info.plist Analysis
- [ ] Extract URL schemes
- [ ] Search for endpoints
- [ ] Search for Base64 encoded data
- [ ] Export IPA using AnyTrans

## 3. File System Analysis

### Directory Search
- [ ] Search root directory for keywords
- [ ] Navigate app-specific directories
- [ ] Search current directory for sensitive files
- [ ] Download app directories for analysis

### Storage Analysis
- [ ] Check NSUserDefaults storage
- [ ] Analyze Cache.db
- [ ] Search for sensitive data in property lists
- [ ] Verify cache clearing on logout

## 4. File Inspection

### Single File Analysis
- [ ] Search for hardcoded sensitive data
- [ ] Extract URLs and deeplinks
- [ ] Extract IP addresses
- [ ] Extract and decode Base64 strings

### Multiple File Analysis
- [ ] Search multiple files for sensitive data
- [ ] Extract URLs and deeplinks from all files
- [ ] Extract IP addresses from all files
- [ ] Extract and decode Base64 strings from all files

### Automated Analysis
- [ ] Use File Scraper for automated inspection
- [ ] Use SQLite 3 for database analysis
- [ ] Use Property Lister for database and plist analysis
- [ ] Use Nuclei for sensitive data detection

### Backup Analysis
- [ ] Get device UDID
- [ ] Create full backup
- [ ] Verify no sensitive data in backups
- [ ] Use iExplorer for backup browsing

## 5. Deeplink Testing

- [ ] Test apple-app-site-association
- [ ] Test deeplink authentication bypass
- [ ] Create HTML template for manual testing
- [ ] Set up deeplink fuzzing environment
- [ ] Use Frida for deeplink fuzzing

## 6. Frida Usage

- [ ] Set up Frida environment
- [ ] List running processes
- [ ] Attach to target process
- [ ] Use Frida scripts for analysis
- [ ] Monitor system calls
- [ ] Hook into application functions

## 7. Objection Usage

- [ ] Set up Objection environment
- [ ] Connect to target application
- [ ] Test SSL pinning bypasses
- [ ] Test jailbreak detection bypasses
- [ ] Test root detection bypasses
- [ ] Test debugger detection bypasses

## 8. IPA Repackaging

- [ ] Extract IPA contents
- [ ] Modify application code
- [ ] Repackage IPA
- [ ] Sign modified IPA
- [ ] Install modified IPA

## 9. Miscellaneous

### System Monitoring
- [ ] Monitor system logs
- [ ] Monitor file changes
- [ ] Dump pasteboard contents
- [ ] Get provisioning profile

## 10. Security Best Practices

- [ ] Verify proper data encryption
- [ ] Check for secure storage implementation
- [ ] Verify proper authentication mechanisms
- [ ] Test for proper session management
- [ ] Verify secure communication channels
- [ ] Check for proper input validation
- [ ] Test for proper error handling
- [ ] Verify secure coding practices

## 11. Report Writing

- [ ] Document all findings
- [ ] Include proof of concepts
- [ ] Provide remediation steps
- [ ] Calculate CVSS scores
- [ ] Reference CWE entries
- [ ] Include OWASP references
- [ ] Add MITRE ATT&CK references
