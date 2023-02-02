# Cleanup-Wim-22621.ps1
 
Based on Microsoft official ISO image releases. If you want to use this script directly, obtain the correct ISO image from Microsoft. Otherwise you may want to modify the script.

## List of modifications

- Remove Not-Supported-On-LTSB-Package (does not break Windows Update as of January 2023)
  - Remove OneDrive Setup (and OneDrive will be gone)
  - Remove OEM Default associations (does not break Windows Update as of January 2023)
- Remove most APPX packages
  - Remove Widgets (by removing Web Experience Pack)
- Remove Start Menu promotions (by firewalling StartMenuExperienceHost)
- Disable automatic installation of Microsoft Teams
- Disable Chat icon (with Group Policy)
- Disable web-enabled Windows Search (with Group Policy); falls back to local search
- Disable promotions from Content Delivery Manager
- Disable automatic updates for Microsoft Store apps (behaves independently from Microsoft Store)
- Disable OOBE promotions

## Notes

- The APPX removal list targets all editions (Core, Professional, N-variants, etc.), and anything missing from the currently processing edition will be ignored.

## Credits

- [RunAsTI](https://forums.mydigitallife.net/threads/lean-and-mean-snippets-for-power-users-runasti-reg_own-toggledefender-edge-removal-redirect.83479/)
