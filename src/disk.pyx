from fnctl import ioctl

from . import disk_ioctl


def flush_buffer_cache_with_name(disk):
    """
    Flush buffer cache for `disk`.

    `disk` must be a string and can be `/dev/sda` or just `sda`
    """
    disk = disk.removeprefix('/dev/')
    with open(f'/dev/{disk}', 'wb') as f:
        return flush_buffer_cache_with_file(f)


def flush_buffer_cache_with_file(f):
    """Flush buffer cache for disk.

    `f` must be a python file object.
    """
    return ioctl(f.fileno(), disk_ioctl.BLKFLSBUF)


def reread_disk_partition_tables_with_name(disk):
    """
    Forces a reread of the `disk` partition tables.

    `disk` must be a string and can be `/dev/sda` or just `sda`
    """
    disk = disk.removeprefix('/dev/')
    with open(f'/dev/{disk}', 'wb') as f:
        return reread_disk_partition_tables_with_file(f)


def reread_disk_partition_tables_with_file(f):
    """
    Forces a reread of a disks partition tables.

    `f` must be a python file object.
    """
    return ioctl(f.fileno(), disk_ioctl.BLKRRPART)
