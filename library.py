import subprocess

def cmd(cmd_str, output_file=None, calling_function=None):
    """
    Execute the given command on the command line
    """
    cmd_str = cmd_str.strip()
    if output_file is not None:
        with open(output_file, "a") as outfile:
            if calling_function is not None:
                outfile.write(cmd_str + f" called from {calling_function}\n")
            else:
                outfile.write(cmd_str + "\n")
    result = subprocess.run([cmd_str], shell=True, capture_output=True, encoding="UTF-8")

    # print(f"Error: {result.stderr}")
    # print(f"Output: {result.stdout}")
    return result.stdout, result.stderr

def dict_ref(full_dict, id_list, default_val=None):
    """
    A way to reference the value in a dictionary by listing the keys
    If the key set doesn't exist, return the default_val
    """
    cur_dict = full_dict
    for key in id_list:
        # print(f"key: {key} - cur_dict: {cur_dict}")
        if isinstance(key, int):
            # In this case, key is a list index
            if key < len(cur_dict):
                cur_dict = cur_dict[key]
        elif key in cur_dict:
            cur_dict = cur_dict[key]
        else:
            return default_val
    return cur_dict

def wait_for_user(print_str):
    """
    Grab user input and return it
    """
    wait_type = "print"
    wait_type = "nothing"
    # wait_type = "wait"
    if wait_type == "print":
        return print(print_str)
    elif wait_type == "nothing":
        return
    elif wait_type == "wait":
        user_input = input(f"Do you want to continue?: {print_str}")
        return user_input
