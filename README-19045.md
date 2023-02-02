# Cleanup-Wim-22621.ps1
 
Based on Microsoft official ISO image releases. If you want to use this script directly, obtain the correct ISO image from Microsoft. Otherwise you may want to modify the script.

## List of modifications

- Remove OneDrive Setup (and OneDrive will be gone)
- Remove most APPX packages
- Remove Start Menu promotions (by changing Content Delivery Manager entries)
- Disable News and Interests (with Group Policy)
- Disable Meet Now (with Group Policy)
- Disable automatic installation of PC Health Check
- Disable web-enabled Windows Search (with Group Policy); falls back to local search
- Disable promotions from Content Delivery Manager
- Disable automatic updates for Microsoft Store apps (behaves independently from Microsoft Store)
- Disable OOBE promotions
- Set telemetry to lowest level possible for edition (with Group Policy)

## Notes

- The APPX removal list targets all editions (Core, Professional, N-variants, etc.), and anything missing from the currently processing edition will be ignored.
