# Synology NAS Permissions Manager

A Python script for managing user permissions on a disposable internet-exposed Synology NAS (NAS B) that syncs from a secure original NAS (NAS A). This tool automates the creation of permissions after each sync operation resets them.

## Description

This script addresses the challenge of maintaining user permissions on a Synology NAS exposed to the internet. Since syncing from the original secure NAS (A) to the internet-facing NAS (B) wipes all permissions, this tool reads a JSON configuration file and reapplies the necessary users, groups, and access control entries (ACEs) on NAS B.

The script is designed with a "disposable" model in mind: treat NAS B as ephemeral. If compromised or issues arise, simply re-sync from NAS A and run the script again.

It is also assumed the script will only ever be run on NAS B.  For security reasons, I don't want these users to exist
on NAS A.  Nor do I want any overlap between users on NAS B with NAS A.  With data hijacking and general hacking these days, 
this is why I want to treat NAS B as disposable.  If anyone compromizes NAS B, all I need to do is blow it away, deal with any admin password changes and then re-sync from NAS A.

## Features

- **User and Group Management**:    Creates users and groups on NAS B based on JSON configuration
- **Permission Setting**:           Applies directory and file permissions (ACEs) using Synology's ACL tools
- **Cleanup Functionality**:        Removes all created users, groups, and ACEs for reset scenarios
- **Idempotent Operations**:        Safe to run multiple times without side effects
- **Dry-Run Mode**:                 Preview what would be deleted during cleanup
- **Prevent File Support**:         Respects `prevent_share.txt` files to block directory access
- **Configurable Defaults**:        Customizable settings via JSON file (auto-created if missing)

## Prerequisites

- **Hardware**: Two Synology NAS devices
  - NAS A: Secure original with data
  - NAS B: Internet-exposed, configured for Snapshot Replication from NAS A
- **Software**:
  - Python 3.x
  - Synology DSM with CLI tools (`synouser`, `synogroup`, `synoacltool`, `synoshare`)
  - Snapshot Replication configured between NAS A and NAS B
- **One-Time Setup on NAS A**:
  - Control Panel → Shared Folder → Enable "Hide sub-folders and files from users without permission"
  - This is not necessary but is how I want my data exposed to users.  I.e. users can only see
        the files they have permission to download/edit.
- **Base Directory**: Verify your Synology's shared volume mount point (default: "/volume1/"). 
  Update `base_dir` in `variables.json` if your setup uses a different path.

## Installation

1. Clone or download this repository to NAS B.
2. Ensure Python 3.x is installed on NAS B.
3. Place the required files in the same directory:
   - `user_permissions.py` (main script)
   - `library.py` (custom library, assumed present)
   - `duration.py` (timing utility, assumed present)
4. Make the script executable: `chmod +x user_permissions.py`

## Usage

Run the script with sudo privileges on NAS B:

```bash
sudo ./user_permissions.py -u user_permissions.json
```

### Command Line Options

- `-u, --user-file`:        Path to the JSON configuration file (required)
- `-d, --defaults-file`:    Path to defaults JSON file (default: `variables.json`)
- `-v, --verbose`:          Increase output verbosity (can be used multiple times)
- `-c, --check_ace`:        Check ACEs for a specific user/group
- `-ug, --user_or_group`:   Specify user/group for ACE checking
- `--dry-run`:              Preview cleanup without actually deleting

### Example

```bash
# Apply permissions from config
sudo ./user_permissions.py -u user_permissions.json

# Dry-run cleanup to see what would be deleted
sudo ./user_permissions.py -u user_permissions.json --dry-run

# Verbose output
sudo ./user_permissions.py -u user_permissions.json -vvv
```

## Configuration

### User Permissions JSON (`user_permissions.json`)

Example structure:

```json
{
  "base_dir": "/volume1/",
  "users": {
    "alice": {
      "username": "alice",
      "password": "securepass123",
      "full_name": "Alice Smith",
      "e_mail": "alice@example.com",
      "permissions": {
        "root_dir": "music",
        "sub_dirs": {
          "jazz": "r",
          "classical": "w"
        },
        "specific_dirs": [
          {
            "root_dir": "videos",
            "sub_dirs": {
              "documentaries": "r"
            }
          }
        ]
      }
    }
  }
}
```

- `base_dir`:       Optional override of the shared-volume root on the NAS (e.g. `/volume1/`). This is useful if your system uses a different mount point.
- `root_dir`:       Base directory for user permissions (relative to `base_dir`)
- `sub_dirs`:       Subdirectories with permission levels (r=read, w=write, admin=full)
- `specific_dirs`:  Additional directory trees with their own permissions

### Defaults JSON (`variables.json`)

Auto-created if missing. Contains configurable settings like exclude directories, prevent files, etc.

Key settings:
- `base_dir`: The mount point for shared volumes (default: "/volume1/"). Change this if your Synology uses a different mount point.
- `group_name_prefix`: Prefix for auto-generated group names (default: "auto_group_")
- `exclude_dirs`: Directories to skip during permission setting
- `prevent_sharing_files`: Files that block directory access when present

## Important Notes

- **Disposable Model**: NAS B is treated as disposable. Re-sync from NAS A to reset everything.
- **User Uploads**: If allowing uploads to NAS B, remember they will be lost on re-sync. Move important uploads to NAS A first.
- **Security**: Run with appropriate privileges. The script uses Synology CLI tools.
- **Idempotency**: Safe to run multiple times; will not create duplicates.

## Restrictions / Future optomizations

Currently I have written this very heavy handedly to just add ACEs for every single file and folder 
under the root_dir for each user.  This is because I was running into issues with the ACEs not applying correctly 
to sub-folders and files when I added them at a higher level.  This is likely due to some weirdness with 
how Synology handles ACEs, or my own lack of understanding.  I haven't had time to dig into it yet.  
I have not found great documentation on these CLI commands from Synology and the last major update, I had to make
significant changes to this automation.  In the future, it would be nice to optimize 
this by only adding high level ACEs and then relying on inheritance, but for now this brute force method 
seems to be the most reliable way to ensure the correct permissions are applied.
It's also useful from a QA standpoint to be able to see the ACEs being added for each file and folder, 
so I have left in some print statements for that.  Also, if the user has prevent_shareing files in their repo, 
we won't have to rely on placing blocking ACEs as the sharing ACEs will never be added in the first place for those files. 
While this seems to keep the script much more reliable (in my testing), it takes longer to run.

For my own application, we're still talking 5-10 minute run-times depending on the number of users I have configured.
If anyone has a larger repo than I do and execution time becomes an issue, you might want to look into inheritance.
Synology does support this and we might be able to speed this up considerably using that method.

At one point, I created a "task" in the UI and was looking into a way of easily launching this automation from within
the UI.  I gave up on that when it broke in the last major rev.  I currently SSH into NAS B and execute the script
from there.

I don't use this automation much to provide users with write access.  Generally when I do, I am watchful and very careful.
I have not thought too much about it, but it might be nice to have some sort of check before a re-sync to be alerted of
user-uploads that the host might want to preserve.  Maybe create some sort of cache outside the repo for user-uploaded files?
Again, this feature has not been super important to me, its just something I could envision others wanting.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on a Synology NAS
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This script is provided as-is for managing Synology NAS permissions. Use at your own risk. Always backup important data and test in a safe environment before production use. The authors are not responsible for any data loss or security issues.