// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors
use crate::error::{Error, Result};
use log::*;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

pub static MOUNTINFO: &str = "/proc/self/mountinfo";

/*
 * Check the mount status of the secure mount directory by parsing /proc/self/mountinfo content.
 *
 * /proc/[pid]/mountinfo have 10+ elements separated with spaces (check proc (5) for a complete
 * description)
 *
 * The elements of interest are the mount point (5th element), and the file system type (1st
 * element after the '-' separator).
 *
 * Input: secure mount directory path
 * Return: Result wrap boolean with error message
 *         - true if directory is mounted
 *         - false if not mounted
 *
 */
pub fn check_mount(secure_dir: &Path) -> Result<bool> {
    let f = fs::File::open(MOUNTINFO)?;
    let f = BufReader::new(f);
    let lines = f.lines();

    for line in lines.map_while(std::result::Result::ok) {
        let mut iter = line.split(' ');
        if let Some(mount_point) = &iter.nth(4) {
            if Path::new(mount_point) == secure_dir {
                // Skip all fields up to the separator
                let mut iter = iter.skip_while(|&x| x != "-");

                if let Some(_separator) = iter.next() {
                    // The file system type is the first element after the separator
                    if let Some(fs_type) = iter.next() {
                        if fs_type == "tmpfs" {
                            debug!("Secure store location {} already mounted on tmpfs", secure_dir.display());
                            return Ok(true);
                        } else {
                            let message = format!("Secure storage location {secure_dir} already mounted on wrong file system type: {fs_type}. Unmount to continue.", secure_dir = secure_dir.display(), fs_type = fs_type);
                            error!("Secure mount error: {message}");
                            return Err(Error::SecureMount(message));
                        }
                    } else {
                        let message = "Mount information parsing error: missing file system type".to_string();
                        error!("Secure mount error: {message}");
                        return Err(Error::SecureMount(message));
                    }
                } else {
                    let message = "Separator field not found. Information line cannot be parsed".to_string();
                    error!("Secure mount error: {message}");
                    return Err(Error::SecureMount(message));
                }
            }
        } else {
            let message =
                "Mount information parsing error: not enough elements"
                    .to_string();
            error!("Secure mount error: {message}");
            return Err(Error::SecureMount(message));
        }
    }
    debug!("Secure store location {} not mounted", secure_dir.display());
    Ok(false)
}

/*
 * Return: Result wrap secure mount directory or error code
 *
 * Mounted the work directory as tmpfs, which is owned by root. Same
 * implementation as the original python version, but the chown/geteuid
 * functions are unsafe function in Rust to use.
 */
pub fn mount(work_dir: &Path, secure_size: &str) -> Result<PathBuf> {
    // Mount the directory to file system
    let secure_dir_path = Path::new(work_dir).join("secure");

    // If the directory is not mount to file system, mount the directory to
    // file system.
    if !check_mount(&secure_dir_path)? {
        // Create directory if the directory is not exist. The
        // directory permission is set to 448.
        if !secure_dir_path.exists() {
            fs::create_dir(&secure_dir_path).map_err(|e| {
                Error::SecureMount(format!(
                    "unable to create secure dir path: {e:?}"
                ))
            })?;

            info!("Directory {secure_dir_path:?} created.");
            let metadata = fs::metadata(&secure_dir_path).map_err(|e| {
                Error::SecureMount(format!(
                    "unable to get metadata for secure dir path: {e:?}"
                ))
            })?;
            metadata.permissions().set_mode(0o750); // decimal 488
        }

        info!(
            "Mounting secure storage location {:?} on tmpfs.",
            &secure_dir_path
        );

        // mount tmpfs with secure directory
        match Command::new("mount")
            .args([
                "-t",
                "tmpfs",
                "-o",
                format!("size={secure_size},mode=0700").as_str(),
                "tmpfs",
                secure_dir_path.to_str().unwrap(), //#[allow_ci]
            ])
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    return Err(Error::SecureMount(format!(
                        "unable to mount tmpfs with secure dir: exit status code {status}",
                        status = output.status
                    )));
                }
            }
            Err(e) => {
                return Err(Error::SecureMount(format!(
                    "unable to mount tmpfs with secure dir: {e}"
                )));
            }
        }
    }

    Ok(secure_dir_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_mount() {
        let temp_workdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let secure_size = "1m";
        let _test_mount = mount(temp_workdir.path(), secure_size);
        assert!(check_mount(temp_workdir.path()).is_ok());
    }
}
