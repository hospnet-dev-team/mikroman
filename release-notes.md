
# Release Notes  
## Version 1.0.6 - Firmware upgrade fix  

### Bugs Fixed  

- **Firmware Download:** 
  - Resolved multiple bugs for frimware repository and download
  - Resolved multiple bugs while applying updates to routers
  - Fix CHR firmware updates
- **Device Edit:** Fix password change in edit form when the user the password is not changed
- **Syslog:** Added new regex for new versions of MikroTik the user trace (usernam/ip/connection) is not provided in logs and actions when setup wizards used in winbox/webfig (This is MikroTik bug and Already reported to MikroTik support ,Fix is comming)
- **Dashboard** Fixed showing wrong update information for MikroWizard
### New Features  
- **Firmware Management:** 
  - **Backup** : Now before any firmware update it will try to get a backup of router
  - **Pakages update** : All packages is getting updated and not only the routeros
  - **Wifi package  Update** :Now it should update wifi/radio enabled routers without problem

---
## Version 1.0.5 - Major Improvements and Bug Fixes  

We’re excited to announce the release of version 1.0.5! This update introduces new features, significant enhancements, and essential bug fixes to improve system functionality and user experience.  

### Bugs Fixed  

- **Firmware Download:** Resolved issues with downloading firmware from the MikroTik website when multiple `.npk` files were available.  
- **System Permissions:** Fixed errors when system permissions were set to "None."  
- **Device Group Permissions:** Corrected user device group permissions to function properly.  
- **IP Scanning:**  
  - Fixed issues with single IP scans and ensured the last IP in a range is scanned correctly.
- **Snippets:**  
  - Fixed manual snippet execution issues when device groups were selected.  
- **Backup Visibility:** Resolved problems with MikroTik backups not displaying for larger backup sizes.  
- **Minor UI and Bug Fixes:** Enhanced overall UI consistency and addressed several minor bugs.  

---

### New Features  

- **Background Task Management:** Added the ability to view and stop tasks running in the background, such as IP scanning.  
- **Manual Update Support:** Introduced support for manual MikroWizard updates via the dashboard or settings page.  
- **Firmware Management:** Enabled the option to delete downloaded firmware directly.  

---

### Enhancements  

- **Permission Feedback:** Improved error messages when users lack necessary permissions for specific actions or pages.  
- **Dashboard Improvements:**  
  - Enhanced charts and graphs for better data visualization.  
  - Added detailed version, update, and license information.  
- **Login Page:** Improved error messaging for failed login attempts.  

---

## Version 1.0.1 - Initial Bug Fix Release  

The 1.0.1 update focused on addressing critical issues and improving system stability:  

### Bugs Fixed  

- **Scanning:** Resolved an issue causing scanning failures with tunnel peers and x86 installations.  
- **Syslogs:** Fixed false positive logs and restored accounting functionality.  
- **Updater:** Enhanced security by switching the updater to use HTTPS instead of HTTP.  
- **Firmware Checking:** Resolved issues with automatic firmware checking for free-tier users.  
- **Snippet Execution:** Fixed problems with snippet execution not functioning correctly.  
- **Other Fixes:** Addressed several minor bugs to improve system reliability.  

---

### Upgrade Recommendation  

We strongly recommend upgrading to the latest version to enjoy these new features, improvements, and fixes.  

---

Thank you for your continued trust and feedback! For questions or support, feel free to contact us:  

- **Email:** info[@]mikrowizard[.]com - please replace [@] with @, and [.] with .