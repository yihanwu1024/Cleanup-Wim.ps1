# Cleanup-Wim-*.ps1

**Abandoned. Use [this guide](https://www.tebibyte.io/~yihanwu1024/things/policing-windows-11/) instead.**

This repository contains a Windows image modification script for each feature update version we support. For a list of modifications made by the script, refer to each of the READMEs.

## Functionalities

- Remove Component Based Servicing packages
- Remove APPX packages
- Provides a trivial framework for registry modification

## Better Clean Your Windows Before Setup

Cleaning a Windows installation/image before setup has a few advantages:

- The result is a deployable installation image.
  - There is no user. You are forced to change the default user registry rather than the current user registry. In this way, all users will receive the user registry modification, not just the user that you operated.
  - You can create a modified image for every Windows feature update and install from your modified image, rather than having everything come back again.
- No initialization can happen in the components you removed.
