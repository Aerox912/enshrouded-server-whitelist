# Enshrouded Server Whitelist

Allow only listed Steam accounts into your Windows dedicated server. No client mod required.

[Download on Nexus Mods](https://www.nexusmods.com/enshrouded/mods/155) | [GitHub release](https://github.com/Aerox912/enshrouded-server-whitelist/releases/tag/v1.0.0)

Tested on Enshrouded 1.0 dedicated build **25967645**. Other builds and Linux/Proton are not verified. Unsupported binaries refuse startup.

## Install

1. Stop the server and back up its settings and world.
2. Extract the release ZIP into a separate folder beside your server folder.
3. Add allowed players to esm-admission.txt: one 17-digit SteamID64 per line, no comments, blank lines or duplicates. Maximum 512 accounts. The shipped empty list deliberately refuses startup.
4. In PowerShell run: `& .\Start-WhitelistedServer.ps1 -ServerExe 'D:\YourServer\enshrouded_server.exe'`
5. Check esm-admission.log for ready/commit messages and the game log for Host_Online. Test one allowed and one unlisted account.

Always use this script. Starting the game EXE directly bypasses the whitelist. Existing roles, passwords, ports, settings and worlds are unchanged. No service or autostart is installed. Stop the server before editing the list, then restart with the script. No live reload.

## How it works

The launcher starts its own server and installs the check before game startup. It checks successfully authenticated Steam accounts against your list. Listed accounts continue; others are rejected. Rejected sessions are closed so repeated attempts do not leave a phantom player count.

Invalid configuration, changed binaries or failed initialization refuse startup. This is access control, not anti-cheat or a firewall. Owners with filesystem access can bypass it.

## Other mods

- [Minimap and Weather Clock](https://www.nexusmods.com/enshrouded/mods/143)
- [First Person View](https://www.nexusmods.com/enshrouded/mods/153) (release in preparation)

## Build

Windows x64, Visual Studio 2022 C++ Build Tools, CMake 3.20+:

    cmake -S src -B build -A x64
    cmake --build build --config Release
    ctest --test-dir build -C Release --output-on-failure

Default tests cover policy only. For all eight suites, configure ADMISSION_SERVER_FIXTURE with your own exact supported server EXE and ADMISSION_PYTHON with Python containing pefile and unicorn. No game binaries are distributed.

Version 1.0.0 packages the unchanged tested r5 DLL and paired launcher. Eight offline suites passed. Live testing verified allowed entry, two rejected retries and a count returning to zero. Coexistence with other native-hook mods needs separate testing.

Technical filenames retain esm_admission for compatibility. Copyright 2026 Aerox912, MIT. Unofficial mod; Enshrouded belongs to Keen Games.

