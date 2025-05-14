import os
from .models import Entry

def check_name_conflict(user, name, parent_entry):
    """Checks if an entry with the given name exists under the parent for the user."""
    return Entry.objects.filter(
        user=user,
        name__iexact=name, # Case-insensitive check
        parent=parent_entry # parent_entry can be None for root
    ).exists()

def get_unique_name(user, original_name, parent_entry):
    """Finds a unique name in the target folder by appending suffixes."""
    if not check_name_conflict(user, original_name, parent_entry):
        return original_name

    base_name, extension = os.path.splitext(original_name)
    counter = 1
    while True:
        new_name = f"{base_name} ({counter}){extension}"
        if not check_name_conflict(user, new_name, parent_entry):
            return new_name
        counter += 1
        if counter > 100:
             raise Exception("Could not find a unique name after 100 attempts.")

def is_descendant(folder_to_check, potential_parent):
    """Checks if potential_parent is a descendant of folder_to_check (DB objects)."""
    if not potential_parent:
        return False
    current = potential_parent
    while current:
        if current == folder_to_check:
            return True
        current = current.parent
    return False