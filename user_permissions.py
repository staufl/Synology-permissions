#!/usr/bin/env python3

import argparse
import hashlib
import json
import library as l
import os
import re
import time
from duration import Duration

Duration.default_round_ndigits = 3

"""
This script manages permissions on a disposable internet-exposed Synology NAS (B) synced from a secure original (A).

Problem: Syncing from A to B resets permissions. This script applies user/group permissions based on a JSON config file.

Features:
- Creates users and groups on B
- Sets directory/file permissions (ACEs) 
- Cleanup function to remove added entities
- Idempotent; safe to run multiple times

Use Model: Treat B as disposable. Re-sync from A to reset, then run script.  Never run the script on NAS A. Always run on NAS B.

Configuration: Defaults are read from `variables.json`; you can override values (e.g., `base_dir`) per run 
in `user_permissions.json`.

Warning: Any uploads to B are lost on re-sync; move to A to preserve.

Setup: Requires Snapshot Replication from A to B. 

*** Note ***
If you want to prevent user from seeing files they don't have permission for:
Enable "Hide sub-folders and files from users without permission" on A.

Usage: sudo ./user_permissions.py -u user_permissions.json

"""

class userPermissions:

    def __init__(self):
        self.start_time = time.time()
        self.added_users = 0
        self.removed_users_list = []
        self.removed_groups_list = []
        self.deleted_users = 0
        self.added_groups = 0
        self.deleted_groups = 0
        self.cleaned_aces = 0
        self.cleaned_group_aces = 0
        self.added_aces = 0
        self.user_added_aces = {}
        self.thinking_dir_count = 0
        self.thinking_file_count = 0
        self.total_time = 0
        self.time_synology_acl_processing = 0
        self.group_members = {}
        # Prefix used for groups created by this script. This makes cleanup deterministic.
        self.group_name_prefix = "auto_group_"
        # Each of these default values below will be over-ridden if they are included in the defaults json file
        self.system_group_members = ["administrators", "admin"]
        # If these files are found, the entire directory they are in won't be shared
        self.prevent_sharing_files = ["prevent_share.txt"]
        # If these directories are found anywhere in a path, that directory won't be shared
        self.exclude_dirs = ["pycache", "recycle", "@eaDir", "@tmp", "snapshot"]
        # If these files are found, they won't be shared
        self.exclude_files = [".swp", "SYNOINDEX_MEDIA_INFO"]
        # Default mount point for Synology shared volumes. Can be overridden via variables.json or user_permissions.json.
        self.base_dir = "/volume1/"
        self.cmd_output_file = "output_file.txt"
        # File storing the groups this script created, used for cleanup.
        self.created_groups_file = ".created_groups.json"
        with open(self.cmd_output_file, "w+") as outfile:
            hdr_str = "Debug output file with CLI commands run\n"
            outfile.write(hdr_str)

    def set_defaults(self, defaults_dict):
        """
        Set default values for instance variables based on the provided dict (typically loaded from variables.json).
        This includes values such as `base_dir`, `exclude_dirs`, `prevent_sharing_files`, and others.
        """
        self.system_group_members = l.dict_ref(defaults_dict, ["system_group_members"], default_val=self.system_group_members)
        self.prevent_sharing_files = l.dict_ref(defaults_dict, ["prevent_sharing_files"], default_val=self.prevent_sharing_files)
        self.exclude_dirs = l.dict_ref(defaults_dict, ["exclude_dirs"], default_val=self.exclude_dirs)
        self.exclude_files = l.dict_ref(defaults_dict, ["exclude_files"], default_val=self.exclude_files)
        self.base_dir = l.dict_ref(defaults_dict, ["base_dir"], default_val=self.base_dir)
        self.cmd_output_file = l.dict_ref(defaults_dict, ["cmd_output_file"], default_val=self.cmd_output_file)
        self.created_groups_file = l.dict_ref(defaults_dict, ["created_groups_file"], default_val=self.created_groups_file)
        self.group_name_prefix = l.dict_ref(defaults_dict, ["group_name_prefix"], default_val=self.group_name_prefix)

    def add_users(self):
        """
        We've already figured out the names of the users and the dict is stored in the class.
        Now lets create the users
        """
        successful_user_adds = []
        for user in self.all_users:
            password = l.dict_ref(self.user_dict, ["users", user, "password"])
            full_name = l.dict_ref(self.user_dict, ["users", user, "full_name"])
            e_mail = l.dict_ref(self.user_dict, ["users", user, "e_mail"])
            self.add_user(user, password, full_name, e_mail, 2)
            if self.check_user_exist(user):
                successful_user_adds.append(user)

        self.dprnt(f"Successfully added users: {successful_user_adds}", level=0)
        return True


    def add_user(self, username, password, full_name, e_mail, app_priv):
        """
        Add a user to the local Synology system
        I added in logic to check for illegal characters in the username, 
        as well as illegal first and last characters.  If any of those are found, 
        the user will not be added and a message will be printed about it.

        str username:     the username of the user to be added
        str password:     the password of the user to be added
        str full_name:    the full name of the user to be added
        str e_mail:       the e-mail of the user to be added
        int app_priv:     the application privileges of the user to be added, 0 for none, 2 for all
        """
        with Duration() as d:
            legal_name = True
            illegal_characters = "!\"#$%&'()*+,/:;<=>?@[]\^`{}|˜"
            found_illegal_chars = self.check_chars(username, illegal_characters)
            if found_illegal_chars:
                self.dprnt(f"Illegal character(s) found in {username}", level=0)
                legal_name = False
            # Check if first character is illegal
            char_one = username[0]
            illegal_first_characters = "- "
            found_illegal_chars = self.check_chars(char_one, illegal_first_characters, str_piece=0)
            if found_illegal_chars:
                self.dprnt(f"Illegal first character found in {username}", level=0)
                legal_name = False
            # Check if last character is illegal
            last_char = username[-1]
            illegal_last_characters = " "
            found_illegal_chars = self.check_chars(last_char, illegal_last_characters, str_piece=-1)
            if found_illegal_chars:
                self.dprnt(f"Illegal last character found in {username}", level=0)
                legal_name = False

            if legal_name:
                expired_account = 0
                cmd = f"synouser -add {username} {password} \"{full_name}\" {expired_account} {e_mail} {app_priv}"
                # self.dprnt(f"User cmd: {cmd}", level=2)
                self.run_cmd(cmd, calling_function="add_user")
                self.added_users += 1
                self.user_added_aces[username] = 0

        self.dprnt(f"Added user {username} in {d} seconds", level=1)
        self.total_time += float(d)

    def run_cmd(self, cmd, calling_function=None):
        """
        This function calls the external library to execute a command on the Synology command line
        It also times how long this takes so we know how much processing time the Synology is doing
        throughout the script run

        str cmd:                the command to run on the Synology command line
        str calling_function:   the name of the function that is calling this, used for debugging purposes
        """
        with Duration() as d:
            response, error = l.cmd(cmd, output_file=self.cmd_output_file, calling_function=calling_function)
        self.time_synology_acl_processing += float(d)
        return response, error

    def remove_users(self):
        """
        Remove a user from the local Synology system
        """
        users_count = 0
        users_str = ""
        for user in self.all_users:
            if self.check_user_exist(user):
                users_count += 1
                self.removed_users_list.append(user)
                users_str = f"{users_str} {user}"
        users_str = users_str.strip(" ")
        # self.dprnt(f"users_str: {users_str}", level=2)
        if users_count > 0:
            self.dprnt(f"Deleting users: {users_str}", level=0)
            cmd = f"synouser --del {users_str}"
            # self.dprnt(f"Command to delete users: {cmd}", level=2)
            with Duration() as d:
                self.run_cmd(cmd)
            self.dprnt(f"Took {d} seconds to delete {users_count} users", level=1)
            self.deleted_users += users_count
            self.total_time += float(d)
        else:
            self.dprnt("No users on NAS currently, nothing to delete", level=1)

    def check_user_exist(self, user_name):
        """
        Check if a particular user exists

        str user_name: the name of the user to check for existence
        """
        cmd = f"synouser --get {user_name}"
        response, error = self.run_cmd(cmd, calling_function="check_user_exist")
        if "SYNOUserGet failed" in error:
            return False
        elif "Permission denied" in response:
            self.dprnt("You appear to be running without correct privlidges", level=0)
            return False
        else:
            return True

    def add_groups(self):
        """
        Add all the groups and persist the created group list for future cleanup.
        """
        created_groups = []
        for group in self.all_groups:
            if self.add_group(group):
                created_groups.append(group)

        # Store the list of groups created during this run so cleanup can delete them later.
        self.save_created_groups(created_groups)

        self.dprnt(f"Successfully added groups: {created_groups}", level=0)
        return created_groups

    def add_group(self, group_name):
        """
        Add a group to the local Synology system

        str group_name: the name of the group to be added
        """
        with Duration() as d:
            legal_name = True
            illegal_characters = "!\"#$%&’()*+,/:;<=>?@[]ˆ`\{\}|˜"
            found_illegal_chars = self.check_chars(group_name, illegal_characters)
            if found_illegal_chars:
                self.dprnt(f"Illegal character(s) found in {group_name}", level=0)
                legal_name = False
            # Check if first character is illegal
            char_one = group_name[0]
            illegal_first_characters = "-+"
            found_illegal_chars = self.check_chars(group_name, illegal_first_characters, str_piece=0)
            if found_illegal_chars:
                self.dprnt(f"Illegal first character found in {group_name}", level=0)
                legal_name = False
            # Check if last character is illegal
            last_char = group_name[-1]
            illegal_last_characters = " "
            found_illegal_chars = self.check_chars(group_name, illegal_last_characters, str_piece=-1)
            if found_illegal_chars:
                self.dprnt(f"Illegal last character found in {group_name}", level=0)
                legal_name = False

            if legal_name:
                cmd = f"synogroup -add {group_name}"
                self.run_cmd(cmd, calling_function="add_group")
                self.user_added_aces[group_name] = 0
        if self.check_group_exist(group_name):
            self.dprnt(f"Took {d} seconds to create group {group_name}", level=1)
            self.added_groups += 1
            self.total_time += float(d)
            return True
        else:
            self.dprnt(f"Failed to create group {group_name}", level=0)
            return False

    def remove_groups(self, dry_run=False):
        """
        Remove groups created by this script.

        This method does not attempt to list all groups on the NAS (since the
        Synology CLI does not offer a reliable list command); instead it deletes:
          - groups generated from the current JSON run (self.all_groups)
          - any groups previously created by this script and recorded in the
            persisted created-groups file

        If dry_run is True, we only print what would be deleted and do not execute
        any synogroup delete commands.
        """
        remove_names = set(self.all_groups)

        # Add any previously-recorded emitted groups (from earlier runs)
        remove_names.update(self.load_created_groups())

        if not remove_names:
            self.dprnt("No groups to delete", level=1)
            return

        # Verify existence before attempting deletion
        existing_remove_names = []
        for group_name in sorted(remove_names):
            if self.check_group_exist(group_name):
                existing_remove_names.append(group_name)

        if not existing_remove_names:
            self.dprnt("No matching groups found to delete", level=1)
            return

        groups_str = " ".join(existing_remove_names)
        self.dprnt(f"Deleting groups: {groups_str}", level=0)

        if dry_run:
            self.dprnt("Dry run enabled: not deleting groups", level=0)
            return

        cmd = f"synogroup -del {groups_str}"
        with Duration() as d:
            self.run_cmd(cmd)
        self.dprnt(f"Took {d} seconds to delete {len(existing_remove_names)} groups", level=0)
        self.total_time += float(d)
        self.deleted_groups += len(existing_remove_names)
        self.removed_groups_list.extend(existing_remove_names)

        # Clear persisted list so we don't try to delete them again later
        self.save_created_groups([])

    def check_group_exist(self, group_name):
        """
        If a group name exists, return True, otherwise False

        str group_name: the name of the group to check for existence
        """
        cmd = f"synogroup -get {group_name}"
        response, error = self.run_cmd(cmd, calling_function="check_group_exist")
        if "SYNOGroupGet failed" in response:
            return False
        elif "Permission denied" in response:
            self.dprnt("You appear to be running without correct privlidges", level=0)
            return False
        else:
            return True

    def load_created_groups(self):
        """
        Load the list of groups created by this script from disk.
         Returns a set of group names, or an empty set if the file doesn't exist or is invalid.
         This is used during cleanup to know which groups to delete.
         The file is expected to be a JSON array of group names, e.g. ["auto_group_root", "auto_group_data"]
            If the file is missing or contains invalid data, we return an empty set to avoid deleting any groups.
        """
        try:
            with open(self.created_groups_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return set(data)
        except FileNotFoundError:
            return set()
        except Exception:
            return set()
        return set()

    def save_created_groups(self, groups):
        """
        Persist the list of groups created by this script for future cleanup.
        
        list groups: the list of group names to persist
        """
        try:
            with open(self.created_groups_file, "w", encoding="utf-8") as f:
                json.dump(sorted(groups), f)
        except Exception:
            pass

    def save_defaults(self, filepath):
        """
        Save the current default settings to a JSON file.

        str filepath: the path to the file where defaults should be saved
        """
        defaults = {
            "system_group_members": self.system_group_members,
            "prevent_sharing_files": self.prevent_sharing_files,
            "exclude_dirs": self.exclude_dirs,
            "exclude_files": self.exclude_files,
            "base_dir": self.base_dir,
            "cmd_output_file": self.cmd_output_file,
            "created_groups_file": self.created_groups_file,
            "group_name_prefix": self.group_name_prefix,
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(defaults, f, indent=2)
            self.dprnt(f"Created defaults file: {filepath}", level=0)
        except Exception as e:
            self.dprnt(f"Failed to save defaults file: {e}", level=0)

    def make_group_name(self, root_dir, existing_names=None):
        """
        Create a deterministic group name from a root path.
        
        Synology has a 32-character limit for group names. This function:
        - Sanitizes the root path
        - Truncates if necessary while preserving determinism via hash suffix
        - Handles collisions with numeric suffixes
        """
        existing_names = existing_names or set()
        
        # Maximum length Synology allows for group names
        max_length = 32
        hash_suffix_length = 5  # For collision detection
        
        clean = root_dir.strip("/\\")
        if clean == "":
            clean = "root"
        clean = re.sub(r"[^A-Za-z0-9_-]", "_", clean)
        clean = re.sub(r"_+", "_", clean)
        clean = clean.strip("_-")
        if clean == "":
            clean = "root"

        base = f"{self.group_name_prefix}{clean}"
        
        # If name is too long, truncate and add hash suffix for determinism
        if len(base) > max_length:
            # Calculate how much space we have for the clean part
            available_length = max_length - len(self.group_name_prefix) - hash_suffix_length - 1  # -1 for underscore before hash
            
            # Get hash of original clean name to maintain determinism across runs
            hash_digest = hashlib.md5(clean.encode()).hexdigest()[:hash_suffix_length]
            
            # Truncate clean part
            truncated_clean = clean[:available_length]
            base = f"{self.group_name_prefix}{truncated_clean}_{hash_digest}"
        
        candidate = base
        suffix = 1
        while candidate in existing_names:
            # For collision handling, append numeric suffix (should be rare)
            candidate = f"{base}_{suffix}"
            suffix += 1
        
        return candidate

    def groups_add_members(self):
        """
        Add all the members to the groups
        """
        for group_dir in self.group_dict.keys():
            group_name = l.dict_ref(self.group_dict, [group_dir, "group_name"])
            group_members = l.dict_ref(self.group_dict, [group_dir, "usernames"])
            # self.dprnt(f"group_name: {group_name}, group_members: {group_members}", level=2)
            self.group_add_members(group_name, group_members)

        self.dprnt(f"self.group_members: {self.group_members}", level=0)

    def group_add_members(self, group_name, group_members):
        """
        Add a list of members to a group

        str group_name: the name of the group to add members to
        list group_members: the members to add to the group
        """
        with Duration() as d:
            user_str = ""
            for member in group_members:
                user_str = f"{user_str} {member}"
            user_str = user_str.strip(" ")
            cmd = f"synogroup -member {group_name} {user_str}"
            self.run_cmd(cmd, calling_function="group_add_members")
        self.dprnt(f"Added {group_members} to group {group_name} in {d} seconds", level=1)
        self.group_members[group_name] = group_members
        self.total_time += float(d)

    def groups_add_share(self):
        """
        Add all the shares for the groups.  
        This is done after all the members are added to the groups, 
        so we can add the ACEs for the groups at the same time as the users.
        """
        for group_dir in self.group_dict.keys():
            group_name = l.dict_ref(self.group_dict, [group_dir, "group_name"])
            self.group_add_share(group_dir, group=group_name)

    def group_add_share(self, share_name, user_list=[], group=None, access_type="RO"):
        """
        Add a set of users to access their specific share

        str share_name: the name of the share to add users to
        list user_list: the users to add to the share, default is empty list
        str group: the group to add to the share, default is None
        str access_type: the type of access to grant, default is "ReadOnly" (RO), other option is "RW" for read/write

        """
        with Duration() as d:
            user_str = ""
            if len(user_list) > 0:
                for user in user_list:
                    user_list = f"{user_str} {user}"
            if group is not None:
                user_list = f"{user_str} @{group}"
            user_str = user_str.strip(" ")
            cmd = f"synoshare -setuser {share_name} {access_type} = {user_list}"
            response, error = self.run_cmd(cmd, calling_function="group_add_share")
        self.dprnt(f"Added user(s): {user_str} to share {share_name} in {d} seconds", level=1)
        self.total_time += float(d)

    def check_chars(self, i_str, input_illegal, str_piece=None):
        """
        Certain characters are not allowed for usernames/passwords, this
        checks for illegal characters

        str i_str: the string to check for illegal characters
        str input_illegal: the characters that are illegal to be included in the string
        str str_piece: the piece of the string to check, default is None (Allows to check first or last character specifically)
        """
        found_character = False
        if str_piece is None:
            input_str = i_str
        else:
            input_str = i_str[str_piece]
        for i_char in list(input_illegal):
            if i_char in input_str:
                self.dprnt(f"Illegal character \"{i_char}\" found.", level=0)
                found_character = True

        return found_character

    def find_groups(self, user_dict):
        """
        Parse through the group_dict, figure out which users can group together

        str user_dict: the dict containing all the users and their permissions, 
            this is used to figure out which users can be grouped together based on their root_dir permissions
        """
        self.user_dict = user_dict
        self.all_users = user_dict["users"].keys()
        self.group_dict = {}
        used_group_names = set()
        users = user_dict["users"].keys()
        for user in users:
            specific_dirs = False
            if "specific_dirs" in user_dict["users"][user]["permissions"]:
                specific_dirs = True
            # self.dprnt(f"user: {user}", level=2)
            root_dir = l.dict_ref(user_dict, ["users", user, "permissions", "root_dir"]).strip(" \\/,")
            # self.dprnt(f"root_dir: {root_dir}", level=2)
            if root_dir in self.group_dict:
                self.group_dict[root_dir]["usernames"].append(user)
            else:
                group_name = self.make_group_name(root_dir, existing_names=used_group_names)
                used_group_names.add(group_name)
                self.group_dict[root_dir] = {
                    "usernames": [user],
                    "group_name": group_name,
                    "added_ace": False,
                }

            # Adding in the ability to group together specific_dirs along with regular ones
            if specific_dirs:
                this_user_specific_dirs = l.dict_ref(user_dict, ["users", user, "permissions", "specific_dirs"])
                for specific_dir in this_user_specific_dirs:
                    root_dir = l.dict_ref(specific_dir, ["root_dir"], default_val=None).strip(" \\/,")
                    if root_dir is not None:
                        if root_dir in self.group_dict:
                            self.group_dict[root_dir]["usernames"].append(user)
                        else:
                            group_name = self.make_group_name(root_dir, existing_names=used_group_names)
                            used_group_names.add(group_name)
                            self.group_dict[root_dir] = {
                                "usernames": [user],
                                "group_name": group_name,
                                "added_ace": False,
                            }

        if specific_dirs:
            self.dprnt(f"self.group_dict post find_groups: {self.group_dict}", level=1)

        self.all_groups = []
        for group_dir in self.group_dict:
            if self.group_dict[group_dir]["group_name"] not in self.all_groups:
                self.all_groups.append(self.group_dict[group_dir]["group_name"])

        return self.group_dict, self.all_groups

    def get_group_root_dir(self, group_name):
        """
        Walk through the self.group_dict and figure out the root dir that goes with
        a certain group

        str group_name: the name of the group to find the root dir for
        """
        for potential_root_dir in self.group_dict:
            this_group_name = l.dict_ref(self.group_dict, [potential_root_dir, "group_name"], default_val=None)
            if this_group_name is not None:
                if this_group_name == group_name:
                    return potential_root_dir
        return None

    def check_dir_for_ace(self, root_dir, user_or_group):
        """
        I changed the way I delete permissions so, if I mess something up in the logic
        there may be some ACEs left stale after running the script.
        This is to search for ACEs for a specific user or group

        str root_dir: the root directory to check for ACEs for the user or group
        str user_or_group: the user or group to check for ACEs for
        """
        root_base_dir = f"{self.base_dir}{root_dir}/"
        total_checked_files = 0
        found_file_matches = 0
        with Duration() as d:
            for root, dir, files in os.walk(root_base_dir):
                self.dprnt(f"Checking file {root} for user \"{user_or_group}\"", level=2)
                skip_check = False
                # Don't bother checking if the directory isn't long enough
                if not self.dir_long_enough(root):
                    skip_check = True
                # Don't check directories we are excluding anyway
                for exclude_dir in self.exclude_dirs:
                    if exclude_dir in root:
                        skip_check = True
                cmd_dir = self.format_syno_dir_str(root)
                cmd = f"synoacltool -get \"{cmd_dir}\""
                response, error = self.run_cmd(cmd, calling_function="check_dir_for_ace")

                if skip_check is False:
                    if "Path not found" in response:
                        self.dprnt(f"Looking for file_or_dir: \"{cmd_dir}\" but it is saying it doesn't exist", level=0)
                        return []
                    if "---------------------" not in response:
                        self.dprnt(f"Don't seem to have permissions to get ACE data on {root}", level=0)
                    response_lines = response.split("\n")
                    r_response_lines = response_lines.copy()
                    r_response_lines.reverse()
                    for line in r_response_lines:
                        line = line.strip(" \r\t\n")
                        # self.dprnt(f"line: {line}", level=2)

                        answer = re.match(r"^\[(\d*)\] [^:]*:([^:]*):.*", line)
                        # self.dprnt(f"answer: {answer}", level=2)
                        if answer:
                            total_checked_files += 1
                            self.dprnt(f"Answer groups: -{answer.group(1)}- -{answer.group(2)}-", level=2)
                            ace_num = answer.group(1)
                            this_user_or_group = answer.group(2)
                            if this_user_or_group == user_or_group:
                                found_file_matches += 1
                                self.dprnt(f"Found ACE for user {user_or_group} on file: {root}", level=2)
        self.dprnt(f"Checked {total_checked_files} files and found {found_file_matches} for user \"{user_or_group}\"", level=1)
        minutes = float(d) / 60.0
        self.dprnt(f"Total check took {d:0.2f} seconds or {minutes:0.2f} minutes", level=1)

    def is_dir_protected(self, directory, prevent_dirs):
        """
        Check if directory or any parent is in prevent list.

        str directory:      the directory to check
        set prevent_dirs:   the set of protected directories for O(1) lookup
        """
        # Check if exact match or any parent path is protected
        current = directory
        while current and current.startswith(self.base_dir):
            if current in prevent_dirs:
                return True
            parent = current.rsplit('/', 1)[0]
            if parent == current:  # Reached root
                break
            current = parent
        return False

    def walk_all_files(self, root_dir, interest, user, permission, prevent_dirs):
        """
        Walk through all the directories and files in the root_dir directory
        Look for reasons to share or not share directories and files
        Implement the corresponding ACE entries

        str root_dir:       the root directory to start the walk from
        str interest:       the directory of interest, if this is found anywhere in the path of a file or directory, 
                                it will be shared
        str user:           the user to check for ACEs for
        str permission:     the permission to check for
        set prevent_dirs:   Pre-built set of protected directories for efficient lookup
        """
        root_base_dir = f"{self.base_dir}{root_dir}/"
        initial_aces = self.user_added_aces.get(user, 0)
        with Duration() as d:
            self.add_non_propogating_group_ace(permission)
            # Once the group ACE is added, now we need to add the ACEs for all sub-dirs and files
            # self.dprnt(f"New self.group_dict: {self.group_dict}", level=2)
            last_root = ""
            last_root_permission = True
            for root, dir, files in os.walk(root_base_dir):
                self.thinking_dir_count += 1
                # path = root.split(os.sep)
                skip_dir = False
                
                # Skip excluded directories
                for exclude_dir in self.exclude_dirs:
                    # self.dprnt(f"exclude_dir:{exclude_dir}, root: {root}", level=2)
                    if exclude_dir in root:
                        # self.dprnt("Setting exclude_dir to True", level=2)
                        skip_dir = True
                
                # Skip protected directories
                if self.is_dir_protected(root, prevent_dirs):
                    skip_dir = True
                
                this_dir_files, found_prevent_file, _ = self.individual_dir_file_parse(files, root, prevent_dirs)

                # Continue on with logic now that we've checked all the files in the current dir
                # self.dprnt(f"Thinking about root dir: {root}, skip_dir: {skip_dir}, found_prevent_file: {found_prevent_file}", level=2)
                if len(root) < len(last_root):
                    last_root_permission = True
                # The idea here is that if any user/group did not have permission
                # on the directory above this, should not have to check the permission
                # of the sub directories.  Need to test this out.
                if last_root_permission:
                    num_cleaned_aces = self.clean_aces(root, calling_function="walk_all_files")
                if num_cleaned_aces == 0:
                    last_root_permission = False
                
                for ace_file in this_dir_files:
                    ace_individual_file = ace_file.rsplit('/', 1)[1]
                    # self.dprnt(f"Checking file: {ace_file}")
                    this_ace_dir = self.obtain_full_dir_from_full_file_path(ace_file)
                    # this_ace_dir = ace_file.rsplit('/', 1)[0]
                    if self.is_dir_protected(this_ace_dir, prevent_dirs):
                        # self.dprnt(f"2 - Found that directory {this_ace_dir} is protected")
                        pass
                    else:
                        if not skip_dir:
                            if f"/{interest}/" in root or f"/{interest}/" in ace_file:
                                non_prop_perm = f"{permission}n"
                                # Skip if this directory is under a protected parent
                                if not self.is_dir_protected(root, prevent_dirs):
                                    self.add_ace(root, ace_individual_file, user, non_prop_perm, root_dir=root_base_dir)
        # User run through multiple walk_all_files, may want to split this out
        aces_added = self.user_added_aces[user] - initial_aces
        self.dprnt(f"Took {d} seconds to setup {aces_added} ACEs for {interest}", level=0)
        self.total_time += float(d)

    def check_for_longest_match(self, prevent_file_dict, longest_prevent_matches, root):
        """
        This function allows us to keep track of the longest partial match to a prevent directory
        This function is not used anymore, should remove it entirely, 
        but the logic is good and may want to use it in the future if I change the way I am doing the prevent directories

        The logic is as follows:
        1. If root is a sub-match to anything in {longest_prevent_match}, done
        2. See if {root} is a sub-match to any of the keys in prevent_file_dict
            If so, check if there are any sub-matches to {root} already in {longest_prevent_match}...
                ...remove those sub-matches...
                ...and add {root} to longest_prevent_match

        str prevent_file_dict: a dict of the directories that have prevent files in them
        list longest_prevent_matches: a list of the longest matches to prevent directories so far
        str root: the directory we are currently checking for matches to prevent directories
        """
        # 1. If root is a sub-match to anything in {longest_prevent_match}, done.
        if not self.check_list_for_sub_matches(root, longest_prevent_matches):
            # 2. See if {root} is a sub-match to any of the keys in prevent_file_dict
            if self.check_list_for_sub_matches(root, prevent_file_dict.keys()):
                #    If so, check if there are any sub-matches to {root} already in {longest_prevent_match}...
                #    ...remove those sub-matches...
                for value in longest_prevent_matches:
                    if self.check_list_for_sub_matches(value, [root]):
                        longest_prevent_matches.remove(value)
                #    ...and add {root} to longest_prevent_match
                longest_prevent_matches.append(root)
        # self.dprnt(f"longest_prevent_matches: {longest_prevent_matches}")
        return longest_prevent_matches

    def check_list_for_sub_matches(self, value, possible_matches):
        """
        Check if the provided value is the beginning of any of the values in the match list

        str value:              the value to check for being a sub-match
        list possible_matches:  the list of values to check for sub-matches to the provided value
        """
        return any(possible_match.startswith(value) for possible_match in possible_matches)

    def build_prevent_dirs_map(self, root_dir):
        """
        Single filesystem walk to identify all directories containing prevent files.
        Returns a set of protected directories for O(1) lookup.
        This is called once before processing all users.

        str root_dir: the root directory to start the walk from
        """
        prevent_dirs = set()
        root_base_dir = f"{self.base_dir}{root_dir}/"
        
        with Duration() as d:
            for root, dirs, files in os.walk(root_base_dir):
                # Check if prevent file exists in current directory
                if any(prevent_file in files for prevent_file in self.prevent_sharing_files):
                    prevent_dirs.add(root)
                    # Skip subdirectories of protected dir
                    dirs[:] = []
                    self.dprnt(f"Found protected directory: {root}", level=1)
                else:
                    # Remove excluded directories from traversal to skip them
                    dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
        
        self.dprnt(f"Built prevent directories map with {len(prevent_dirs)} protected dir(s) in {d} seconds", level=0)
        return prevent_dirs

    def is_dir_protected(self, directory, prevent_dirs):
        """
        Check if a directory or any parent directory is in the prevent set.
        This walks up the directory tree; it runs in O(d) time where d is the depth of the directory.

        str directory:      the directory to check
        set prevent_dirs:   the set of protected directories for O(1) lookup
        """
        if not prevent_dirs:
            return False
        # Check if exact match or any parent path is protected
        current = directory
        while current and current.startswith(self.base_dir):
            if current in prevent_dirs:
                return True
            # Move to parent directory
            parent = current.rsplit('/', 1)[0]
            if parent == current:  # Reached root
                break
            current = parent
        return False

    def individual_dir_file_parse(self, files, root, prevent_dirs):
        """
        Parse files in a directory and filter out those in protected directories.
        prevent_dirs is a pre-built set of protected directories.

        list files:         the list of files in the directory
        str root:           the directory being parsed
        set prevent_dirs:   the set of protected directories
        """
        found_prevent_file = False
        this_dir_files = []
        
        # Quick check: if current directory is protected, skip all files
        if self.is_dir_protected(root, prevent_dirs):
            found_prevent_file = True
            return this_dir_files, found_prevent_file, prevent_dirs
        
        for file in files:
            fp = os.path.join(root, file)
            # self.dprnt(f"individual_dir_file_parse fp: {fp}")

            self.thinking_file_count += 1
            skip_file = False
            # self.dprnt(len(path) * "---", file, level=2)
            for exclude_file in self.exclude_files:
                if exclude_file in file:
                    skip_file = True
            
            # Check if the file's directory is protected
            fp_root = self.obtain_full_dir_from_full_file_path(fp)
            if self.is_dir_protected(fp_root, prevent_dirs):
                skip_file = True

            if not skip_file:
                this_dir_files.append(fp)

        return this_dir_files, found_prevent_file, prevent_dirs

    def obtain_full_dir_from_full_file_path(self, fp):
        """
        From a full path of a file, return the full directory without the filename
        I don't believe any of my individual files have "."s in them
        This also handles the case of nothing to split

        str fp: the full path of the file, including the filename
        """
        split = fp.rsplit('/', 1)
        fp_root = split[0]
        if len(split) > 1:
            new_file = split[1]
            if "." in new_file or 'SYNOINDEX_MEDIA_INFO' in new_file:
                return self.obtain_full_dir_from_full_file_path(fp_root)
            return fp
        return fp

    def find_user_group(self, user):
        """
        Find the group associated with a user

        str user: the user to find the group for
        """
        found_groups = []
        for group in self.group_members:
            if user in self.group_members[group]:
                found_groups.append(group)
        # self.dprnt(f"Old found groups for user {user}: {found_groups}", level=2)
        # This new way is supposed to only add relevant groups to this user AND only add the groups once
        # Not once per user, which was redundant
        found_groups = []
        already_added = []
        for group_dir in self.group_dict:
            possible_usernames = l.dict_ref(self.group_dict, [group_dir, "usernames"], default_val=[])
            # self.dprnt(f"Looking for user {user} in group_dir {group_dir}, names: {possible_usernames}", level=2)
            if user in possible_usernames:
                group_name = l.dict_ref(self.group_dict, [group_dir, "group_name"], default_val=None)
                # If the group exists and if the ACEs have not already been added
                if group_name is not None and not l.dict_ref(self.group_dict, [group_dir, "added_ace"], default_val=False):
                    found_groups.append(group_name)
                else:
                    already_added.append(group_name)
        # self.dprnt(f"New found groups for user {user}: {found_groups}", level=2)
        # self.dprnt(f"Previously added group(s): {already_added}", level=2)
        return found_groups

    def add_ace(self, full_dir, filename, user_or_group, permission, root_groups=False, root_dir=None):
        """
        Add an ACE to the system

        str full_dir:       the full directory to add the ACE to
        str filename:       the filename to add the ACE to, if adding to a file instead of a directory
        str user_or_group:  the user or group to add the ACE for
        str permission:     the permission to add for this ACE, options are 
                                "r" for read, "w" for write, "admin" for full control, 
                                "wn" for write non-propagating, and "rn" for read non-propagating
        bool root_groups:   whether this is being called from the root group ACE function, 
                                which changes the logic of how ACEs are added for the root directories of groups, 
                                default is False
        str root_dir:       the root directory for the group, only used if root_groups is True, 
                                default is "/"
        """
        root_dir = root_dir or "/"
        # If we ever support deeper base directories, this logic would need to change
        # Not sure if this could be supported on Synology or not
        if not self.dir_long_enough(full_dir):
            return
        path = full_dir.split(os.sep)
        full_dir_file = f"{full_dir}{filename}"
        # self.dprnt(f"path: {path}, full_dir_file: {full_dir_file}", level=2)
        build_dir = ""
        for dir_piece in path:
            if dir_piece != "":
                build_dir = f"{build_dir}/{dir_piece}"
                # self.dprnt(f"build_dir: {build_dir}, root_dir: {root_dir}", level=2)
                if root_groups or len(build_dir) > len(root_dir):
                    # If there is not already an ace for this group...
                    if not self.check_for_existing_ace(build_dir, desired_user_or_group=user_or_group):
                        self.ace_cmd(build_dir, user_or_group, permission)
        if not root_groups:
            total_dir = f"{build_dir}/{filename}"
            # self.dprnt(f"total_dir: {total_dir}", level=2)
            self.ace_cmd(total_dir, user_or_group, permission)

    def add_non_propogating_group_ace(self, permission):
        """
        Each user will be part of a group.  Hopefully this will reduce the total number of ACEs added
        as there should be some overlap here.

        str permission: the permission to add for this ACE, 
                            options are "r" for read, "w" for write, "admin" for full control,
        """
        # First add in the non-propagating ACE for the group to access this folder
        groups = self.find_user_group(user)
        if len(groups) > 0:
            self.dprnt(f"Found new groups: {groups} for user {user}", level=2)
        for group in groups:
            non_prop_perm = f"{permission}n"
            this_group_root_dir = self.get_group_root_dir(group)
            this_group_root_base_dir = f"{self.base_dir}{this_group_root_dir}"
            self.dprnt(f"Going to add non-proagating ACE for group {group} to {this_group_root_base_dir}", level=1)
            self.add_ace(this_group_root_base_dir, "", group, non_prop_perm, root_groups=True)
            if this_group_root_dir in self.group_dict:
                self.group_dict[this_group_root_dir]["added_ace"] = True
            else:
                self.dprnt(f"Tried updating ACE for group {group} with root_dir {this_group_root_dir} but failed.", level=0)

    def dir_long_enough(self, directory):
        """
        Not going to mess with directories below the shares

        str directory: the directory to check the length of
        """
        dir_pieces = directory.strip("/").split("/")
        if len(dir_pieces) > 1:
            return True
        # self.dprnt(f"Only putting ACEs on directories deeper than {self.base_dir}", level=2)
        return False

    def ace_cmd(self, file, user_or_group, permission, permission_type=None):
        """
        Run the synoacltool command to add an ACE for a user or group on a file or directory

        str file:               the file or directory to add the ACE to
        str user_or_group:      the user or group to add the ACE for
        str permission:         the permission to add for this ACE, 
                                    options are "r" for read, "w" for write, "admin" for full control, 
                                    "wn" for write non-propagating, and "rn" for read non-propagating
        str permission_type:    the type of permission to add, default is "allow"
        """
        permission_type = permission_type or "allow"
        # If we ever support deeper base directories, this logic would need to change
        # Not sure if this could be supported on Synology or not
        if not self.dir_long_enough(file):
            return
        self.clean_aces(file, calling_function="ace_cmd")
        with Duration() as d:
            """
            r: (r)ead data
            w: (w)rite data (create file)
            x: e(x)ecute
            p: a(p)pend data (create dir)
            d: (d)elete
            D: (D)elete child (only for dir)
            a: read (a)ttribute (For SMB read-only/hidden/archive/system)
            A: write (A)ttribute
            R: (R)ead xattr
            W: (W)rite xattr
            c: read a(c)l
            C: write a(c)l
            o: get (o)wner ship
                inherit mode: fdin
            f: (f)ile inherited
            d: (d)irectory inherited
            i: (i)nherit only
            n: (n)o propagate

            """
            perm_str = None
            if permission == "r":
                perm_str = "r-x---a-R-c--:fd--"
            elif permission == "w":
                perm_str = "rw----aARWc--:fd--"
            elif permission == "admin":
                perm_str = "rwxpdDaARWc--:fd--"
            elif permission == "wn":
                perm_str = "rw----aARWc--:---n"
            elif permission == "rn":
                perm_str = "r-x---a-R-c--:---n"
            if perm_str is None:
                self.dprnt("Don't have enough info to create ACE", level=0)
            else:
                if user_or_group in self.group_members.keys() or user_or_group in self.system_group_members:
                    u_type = "group"
                else:
                    u_type = "user"
                cmd_dir = self.format_syno_dir_str(file)
                cmd = f"synoacltool -add \"{cmd_dir}\" {u_type}:{user_or_group}:{permission_type}:{perm_str}"
                # self.dprnt(f"Adding ACL with cmd: {cmd}", level=2)
                self.run_cmd(cmd, calling_function="ace_cmd")
                self.added_aces += 1
                if user_or_group in self.user_added_aces:
                    self.user_added_aces[user_or_group] += 1
                else:
                    self.user_added_aces[user_or_group] = 1
        self.total_time += float(d)

    def format_syno_dir_str(self, dir_str, escape_chars=None):
        """
        The synoacltool command requires certain format of the directory/file string
        Escape spaces and quotes.

        str dir_str:        the directory string to format for synoacltool commands
        list escape_chars:  list of characters to escape, default is ["`", "$"] 
                              (characters that can cause issues in shell commands)
        """
        ret_str = dir_str.replace("\\\\" , "\\")
        ret_str = ret_str.replace("//" , "/")
        escape_chars = escape_chars or ["`", "$"]
        for escape_char in escape_chars:
            ret_str = ret_str.replace(f"{escape_char}" , f"\{escape_char}")
        return f"{ret_str}"

    def clean_aces(self, file, calling_function=None):
        """
        This is my attempt at an algorithm to loop from the end to the beginning.  This
        may prevent a whole bunch of synoacltool -get commands as it won't
        alter the ace numbers when deleting (or at least none of the ones
        to be deleted)
        It appears with this algorithm, the transition between groups and
        users, the directory has its ACEs checked, then added, then deleted
        again.  Appears the walk gives the directory as a file and as a
        directory, maybe that is why?
        snippet from the command output file:
        synoacltool -get "<base_dir>/blah"
        synoacltool -add "<base_dir>/blah" group:auto_group_1:allow:r-x---a-R-c--:---n
        synoacltool -del "<base_dir>/blah" 0

        str file: the file or directory to clean ACEs on
        str calling_function: the function that called clean_aces, used for debugging purposes
        """
        calling_function = calling_function or ""
        this_cleaned_aces = 0
        # self.dprnt(f"Asked to delete ACEs on file {file}", level=2)
        aces_to_delete = self.find_all_deletable_aces(file)
        # self.dprnt(f"ACEs to delete: {aces_to_delete}", level=2)
        for ace_num in aces_to_delete:
            with Duration() as d:
                cmd_file = self.format_syno_dir_str(file)
                cmd = f"synoacltool -del \"{cmd_file}\" {ace_num}"
                # self.dprnt(f"Deleting ACE {ace_num} on file {cmd_file}, called from {calling_function}", level=2)
                # l.wait_for_user(f"Run cmd: {cmd}?")
                response, error = self.run_cmd(cmd, calling_function=calling_function)
                if "Inherited ACL Entry is not valid to change" in response:
                    self.can_not_delete = True
                else:
                    this_cleaned_aces += 1
                    self.cleaned_aces += 1
            self.total_time += float(d)
        return this_cleaned_aces

    def find_all_deletable_aces(self, file):
        """
        For a particular file, check its ACEs and return a list of all deletable
        users/groups.  The returned list will be in reverse order as well.

        str file: the file or directory to check ACEs on
        """
        # Don't bother checking if the directory isn't long enough
        if not self.dir_long_enough(file):
            return []
        # Don't check directories we are excluding anyway
        for exclude_dir in self.exclude_dirs:
            if exclude_dir in file:
                return []
        cmd_dir = self.format_syno_dir_str(file)
        cmd = f"synoacltool -get \"{cmd_dir}\""
        response, error = self.run_cmd(cmd, calling_function="find_all_deletable_aces")
        # self.dprnt(f"synoacltool -get \"{cmd_dir}\" response: {response}", level=2)
        if "Path not found" in response:
            self.dprnt(f"Looking for file_or_dir: \"{cmd_dir}\" but it is saying it doesn't exist", level=0)
            # self.dprnt(f"file: {file}")
            return []
        if "---------------------" not in response:
            self.dprnt(f"Don't seem to have permissions to get ACE data on {file}", level=0)
        response_lines = response.split("\n")
        aces_to_delete = []
        r_response_lines = response_lines.copy()
        r_response_lines.reverse()
        for line in r_response_lines:
            line = line.strip(" \r\t\n")
            # self.dprnt(f"line: {line}", level=2)

            answer = re.match(r"^\[(\d*)\] [^:]*:([^:]*):.*", line)
            # self.dprnt(f"answer: {answer}", level=2)
            if answer:
                # self.dprnt(f"Answer groups: -{answer.group(1)}- -{answer.group(2)}-", level=2)
                ace_num = answer.group(1)
                this_user_or_group = answer.group(2)
                if this_user_or_group in self.system_group_members:
                    # Do not delete ACEs related to system groups (administrators)
                    pass
                # this_user_or_group in self.removed_groups_list or \
                # this_user_or_group in self.removed_users_list or \
                if this_user_or_group == "":
                    # self.dprnt(f"Found ACE with desired uog "{this_user_or_group}" on path {file_or_dir}", level=2)
                    aces_to_delete.append(ace_num)
        return aces_to_delete

    def perform_one_ace_clean(self, file, desired_user_or_group="", skip_to=None):
        """
        Clean up an ACE on a file where there is no group or username associated.
        This happens when an ACE with a user exists and the user is deleted
        Once a synoacltool -del is run, the number associated with the ACEs
        change.  So, can only delete one at a time
        If there is an entry that can not be deleted (Inherited ACL), skip it

        str file:                   the file or directory to clean ACEs on
        str desired_user_or_group:  the user or group to look for when cleaning ACEs,
                                        if this is found, will be cleaned, 
                                        default is "" which means to clean ACEs with no user or group associated
        int skip_to:                the ACE number to skip to when looking for ACEs to clean, 
                                        default is 0 which means to check all ACEs, this is
        """
        skip_to = skip_to or 0
        if desired_user_or_group in self.system_group_members:
            return False
        ace_num = self.check_for_existing_ace(file,
                                              desired_user_or_group=desired_user_or_group,
                                              skip_to=skip_to)

        if ace_num:
            with Duration() as d:
                cmd_file = self.format_syno_dir_str(file)
                cmd = f"synoacltool -del \"{cmd_file}\" {ace_num}"
                self.cleaned_aces += 1
                if desired_user_or_group != "":
                    self.cleaned_group_aces += 1

                l.wait_for_user(f"Run cmd: {cmd}?")
                response, error = self.run_cmd(cmd, calling_function="perform_one_ace_clean")
                if "Inherited ACL Entry is not valid to change" in response:
                    self.can_not_delete = True
            self.total_time += float(d)
            return ace_num
        return False

    def check_for_existing_ace(self, file_or_dir, desired_user_or_group="", skip_to=0):
        """
        Check to see if a specific ACE already exists.
        """
        # Don't bother checking if the directory isn't long enough
        if not self.dir_long_enough(file_or_dir):
            return False
        # Don't check directories we are excluding anyway
        for exclude_dir in self.exclude_dirs:
            if exclude_dir in file_or_dir:
                return False
        # synoacltool needs directories formatted properly
        cmd_dir = self.format_syno_dir_str(file_or_dir)
        cmd = f"synoacltool -get \"{cmd_dir}\""
        response, error = self.run_cmd(cmd, calling_function="check_for_existing_ace")
        if "Path not found" in response:
            self.dprnt(f"Looking for file_or_dir: \"{cmd_dir}\" but it is saying it doesn't exist", level=0)
            return False
        if "---------------------" not in response:
            self.dprnt(f"Don't seem to have permissions to get ACE data on {file_or_dir}", level=0)
        response_lines = response.split("\n")
        for line in response_lines:
            line = line.strip(" \r\t\n")
            # self.dprnt(f"line: {line}", level=2)

            answer = re.match(r"^\[(\d*)\] [^:]*:([^:]*):.*", line)
            # self.dprnt(f"answer: {answer}", level=2)
            if answer:
                # self.dprnt(f"Answer groups: -{answer.group(1)}- -{answer.group(2)}-", level=2)
                ace_num = answer.group(1)
                if int(ace_num) >= skip_to:
                    this_user_or_group = answer.group(2)
                    if this_user_or_group == desired_user_or_group:
                        # self.dprnt(f"Found ACE with desired uog "{desired_user_or_group}" on path {file_or_dir}", level=2)
                        return ace_num
        return False

    def dprnt(self, str, level=None, end=None, flush=False):
        """
        Print a string if the verbosity level is high enough

        str str:            the string to print
        int level:          the verbosity level of this string, default is 0 which means important information
        str end:            the end character to use when printing, default is "\n"
        bool flush:         whether to flush the output buffer, default is False
        int self.verbose:   the current verbosity level, higher means more verbose, 
                                default is 0 which means only print important information
        """
        level = level or 0
        end = end or "\n"
        if self.verbose >= level:
            print(f"{level}: {str}", end=end, flush=flush)

    def set_verbosity(self, level):
        """
        Set the verbosity level to be used

        int level: the verbosity level, higher means more verbose, default is 0 which means only print important information
        """
        if level is None:
            self.verbose = 0
        else:
            self.verbose = level
        self.dprnt(f"Set verbosity level to {level}", level=2)

    def verify_ace_exists(self, file_or_dir, desired_user_or_group=None):
        """
        Verify that a specific ACE already exists, and print the result

        str file_or_dir:            the file or directory to check for the ACE
        str desired_user_or_group:  the user or group to check for in the ACE, 
                                        default is "" which means to check for ACEs with no user or group associated
        """
        desired_user_or_group = desired_user_or_group or ""
        answer = self.check_for_existing_ace(file_or_dir, desired_user_or_group=desired_user_or_group)
        if answer is False:
            self.dprnt(f"ACE for {desired_user_or_group} missing on {file_or_dir}", level=0)
            return
        self.dprnt(f"ACE for {desired_user_or_group} verified on {file_or_dir}", level=0)

    def print_user_info(self, username, print_time=None):
        """
        Want to print out some simple info about a particular user

        str username:       the user to print info about
        float print_time:   the time it took to process this user, optional
        """
        print_str = f" -- Completed user {username}"
        if print_time is not None:
            print_str += f" in {print_time:0.2f} seconds"
        self.dprnt(f"{print_str}", level=0)

    def print_final_info(self):
        """
        Print final information about the permission updates
        """
        total_time = time.time() - self.start_time
        self.dprnt(f"deleted_users: {self.deleted_users}", level=0)
        self.dprnt(f"added_users: {self.added_users}", level=0)
        self.dprnt(f"deleted_groups: {self.deleted_groups}", level=0)
        self.dprnt(f"added_groups: {self.added_groups}", level=0)
        self.dprnt(f"cleaned_aces: {self.cleaned_aces}", level=0)
        self.dprnt(f"cleaned_group_aces: {self.cleaned_group_aces}", level=0)
        self.dprnt(f"added_aces: {self.added_aces}", level=0)
        for user_or_group in self.user_added_aces:
            self.dprnt(f"User or Group: {user_or_group}, Added ACEs: {self.user_added_aces[user_or_group]}", level=0)
        self.dprnt(f"thinking_dir_count {self.thinking_dir_count}", level=0)
        self.dprnt(f"thinking_file_count {self.thinking_file_count}", level=0)
        total_minutes = self.total_time / 60.0
        self.dprnt(f"total_Duration()_time: {total_minutes:0.2f} minutes", level=0)
        total_minutes = total_time / 60.0
        self.dprnt(f"total_time: {total_minutes:0.2f} minutes", level=0)
        synology_processing_time = self.time_synology_acl_processing / 60.0
        self.dprnt(f"total_Synology_ACL_time: {synology_processing_time:0.2f} minutes", level=0)

u = userPermissions()

parser = argparse.ArgumentParser(description="Update NAS permissions.")
parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="count")

run = parser.add_argument_group("run_options")
run.add_argument("-u", "--user-file", dest="user_file", action="store",
                    help="json file describing the users and their desired permissions")

run.add_argument("-d", "--defaults-file", dest="defaults_file", action="store",
                    default="variables.json",
                    help="json file describing the default variables")
# This is mostly here for debug purposes.  While this script can clean up ACEs, the normal use-model
# is to run this after a sync from NAS A.  This leaves NAS B without any of the ACEs this script sets up.  
# So, if you want to run this on NAS B to clean up the ACEs after the sync, you can use the --dry-run option 
# to see what would be deleted without actually deleting it.
run.add_argument("--dry-run", dest="dry_run", action="store_true",
                    help="Print what would be deleted when cleaning groups without actually deleting")

check = parser.add_argument_group("check_options")
check.add_argument("-c", "--check_ace", dest="check_ace", action="store_true",
                    help="Check the NAS for ACEs of a particular user/group")
check.add_argument("-ug", "--user_or_group", dest="user_or_group", action="store",
                    help="The actual user to look for")

args = parser.parse_args()

u.set_verbosity(args.verbose)

u.dprnt(args, level=2)

# Always load defaults and user config
try:
    with open(args.defaults_file) as f:
        defaults_dict = json.load(f)
        u.set_defaults(defaults_dict)
except FileNotFoundError:
    u.dprnt(f"Defaults file not found: {args.defaults_file}", level=0)
    u.dprnt("Using built-in defaults and creating defaults file...", level=0)
    u.save_defaults(args.defaults_file)

with open(args.user_file) as f:
    user_dict = json.load(f)
# u.dprnt(f"Loaded dict: {user_dict}", level=2)

# Allow overriding base_dir via the user permissions JSON (top-level key)
if isinstance(user_dict, dict) and "base_dir" in user_dict:
    base_dir_val = str(user_dict["base_dir"]).strip()
    if base_dir_val:
        # Ensure trailing slash for consistent path joins
        if not base_dir_val.endswith("/"):
            base_dir_val += "/"
        u.base_dir = base_dir_val

# Build groups after any base_dir / config overrides
group_dict, all_groups = u.find_groups(user_dict)
u.dprnt(f"Group dict: {group_dict}", level=2)
all_users = user_dict["users"].keys()

if args.check_ace:
    # Determine root_dir based on user_or_group from JSON config
    if args.user_or_group in all_users:
        root_dir = l.dict_ref(user_dict, ["users", args.user_or_group, "permissions", "root_dir"]).strip(" \\/,")
    elif args.user_or_group in all_groups:
        root_dir = u.get_group_root_dir(args.user_or_group)
        if root_dir is None:
            u.dprnt(f"Could not find root directory for group '{args.user_or_group}'", level=0)
            exit(1)
    else:
        u.dprnt(f"User or group '{args.user_or_group}' not found in configuration file", level=0)
        exit(1)
    
    u.check_dir_for_ace(root_dir, f"{args.user_or_group}")
else:

    # u.dprnt(f"All users: {all_users}", level=2)

    configure_groups = True

    # 1 - Remove all users:
    u.remove_users()

    # Remove all groups
    u.remove_groups(dry_run=args.dry_run)

    # Add groups
    if configure_groups:
        u.add_groups()

    # Add users
    u.add_users()

    # Put users in their groups
    if configure_groups:
        u.groups_add_members()

    # Now add permission to access shares for their users
    if configure_groups:
        # u.groups_add_share()
        pass

    # u.add_ace(u.base_dir, "", "administrators", "admin")

    # Build prevent directories map once before processing all users
    # This avoids redundant filesystem walks for each user
    u.dprnt("Building prevent directories map...", level=0)
    prevent_dirs_by_root = {}
    for user in all_users:
        root_dir = l.dict_ref(user_dict, ["users", user, "permissions", "root_dir"]).strip(" \\/,")
        if root_dir not in prevent_dirs_by_root:
            prevent_dirs_by_root[root_dir] = u.build_prevent_dirs_map(root_dir)
        
        # Also check specific_dirs
        specific_dirs = l.dict_ref(user_dict, ["users", user, "permissions", "specific_dirs"], default_val=[])
        if len(specific_dirs) > 0:
            for specific_dir in specific_dirs:
                specific_root_dir = l.dict_ref(specific_dir, ["root_dir"]).strip(" \\/,")
                if specific_root_dir not in prevent_dirs_by_root:
                    prevent_dirs_by_root[specific_root_dir] = u.build_prevent_dirs_map(specific_root_dir)

    u.dprnt(f"Prevent directories map built for {len(prevent_dirs_by_root)} root(s)", level=0)

    for user in all_users:
        with Duration() as d:
            username = l.dict_ref(user_dict, ["users", user, "username"])
            root_dir = l.dict_ref(user_dict, ["users", user, "permissions", "root_dir"]).strip(" \\/,")
            u.dprnt(f"Setting up user: {username}", level=1)
            prevent_dirs = prevent_dirs_by_root.get(root_dir, set())
            sub_dirs = l.dict_ref(user_dict, ["users", user, "permissions", "sub_dirs"], default_val=[])
            for sub_dir in sub_dirs:
                u.dprnt(f"{sub_dir}: ", level=2, end="", flush=True)
                perm = sub_dirs[sub_dir]
                u.walk_all_files(root_dir, sub_dir, username, perm, prevent_dirs)
            specific_dirs = l.dict_ref(user_dict, ["users", user, "permissions", "specific_dirs"], default_val=[])
            if len(specific_dirs) > 0:
                u.dprnt(f" Non-empty specific_dirs for user {username}", level=2)
                for specific_dir in specific_dirs:
                    specific_root_dir = l.dict_ref(specific_dir, ["root_dir"]).strip(" \\/,")
                    # root_dir = l.dict_ref(specific_dir, ["root_dir"])
                    prevent_dirs = prevent_dirs_by_root.get(specific_root_dir, set())
                    sub_dirs = l.dict_ref(specific_dir, ["sub_dirs"], default_val=[])
                    for sub_dir in sub_dirs:
                        u.dprnt(f"{sub_dir} - ", level=2, end="", flush=True)
                        perm = sub_dirs[sub_dir]
                        u.walk_all_files(specific_root_dir, sub_dir, username, perm, prevent_dirs)
        u.print_user_info(username, print_time=d)
        # u.dprnt(f"Complete user {username}", level=2)

    u.print_final_info()
