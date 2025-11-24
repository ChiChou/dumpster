# Source - https://stackoverflow.com/a/1094933
# Posted by Sridhar Ratnakumar, modified by community. See post 'Timeline' for change history
# Retrieved 2025-11-23, License - CC BY-SA 4.0
#
def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"
