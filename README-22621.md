# Cleanup-Wim-22621.ps1
 
Based on Microsoft official ISO image releases. If you want to use this script directly, obtain the correct ISO image from Microsoft. Otherwise you may want to modify the script.

## List of modifications

- Remove OneDrive Setup
- Remove most APPX packages
  - Remove Widgets (by removing Web Experience Pack, which will be reinstalled in 22621.1344 update)
- Remove Start Menu promotions (by firewalling StartMenuExperienceHost)
- Disable automatic installation of Microsoft Teams
- Disable Chat icon (with Group Policy)
- Disable Widgets (with Group Policy)
- Disable web-enabled Windows Search (with Group Policy); falls back to local search
- Disable promotions from Content Delivery Manager
- Disable automatic updates for Microsoft Store apps (behaves independently from Microsoft Store)
- Disable OOBE promotions

## Notes

- The APPX removal list targets all editions (Core, Professional, N-variants, etc.), and anything missing from the currently processing edition will be ignored.

## Credits

- [RunAsTI](https://forums.mydigitallife.net/threads/lean-and-mean-snippets-for-power-users-runasti-reg_own-toggledefender-edge-removal-redirect.83479/)
