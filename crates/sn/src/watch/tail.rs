//! Incremental log reading with rotation detection.
//!
//! For each file we remember `(dev, inode, pos)`. If the inode/device changed
//! or the file is now shorter than our offset, the file rotated and we read
//! from the start of the new file. On first sight (no stored offset) we start
//! at EOF so a fresh install does not replay the entire historical log and
//! mass-ban on day one; the installer separately seeds the baseline from
//! rotated logs.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::OnceLock;

use crate::state::Offset;

/// Result of reading new bytes from one file.
pub struct TailRead {
    pub lines: Vec<String>,
    pub new_offset: Offset,
    /// Bytes read from the file this time, including a trailing partial line
    /// that is left for the next cycle.
    pub bytes: u64,
}

/// Who may own a log we follow: root, ourselves (root in production), and the
/// users the web server runs as.
fn allowed_owners() -> Vec<u32> {
    static WEB: OnceLock<Vec<u32>> = OnceLock::new();
    let mut owners = vec![0, nix::unistd::geteuid().as_raw()];
    owners.extend(WEB.get_or_init(crate::discover::web_server_uids));
    owners
}

/// Whether a file with this type, owner and mode is one the web server writes
/// and nobody else can: a regular file, owned by an allowed user, writable by no
/// group but root's and by no one else.
fn owner_and_mode_ok(
    is_file: bool,
    uid: u32,
    gid: u32,
    mode: u32,
    owners: &[u32],
) -> Result<(), String> {
    if !is_file {
        return Err("not a regular file".into());
    }
    if !owners.contains(&uid) {
        return Err(format!("owned by uid {uid}, not root or the web server"));
    }
    if mode & 0o002 != 0 || (mode & 0o020 != 0 && gid != 0) {
        return Err(format!("writable by other users (mode {:o})", mode & 0o777));
    }
    Ok(())
}

/// A log refused for what it is, not for an I/O error.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// Why [`open_log`] refused a file, if that is what `e` says.
pub(crate) fn refusal(e: &io::Error) -> Option<&str> {
    e.get_ref()?.downcast_ref::<Refused>().map(|r| r.0.as_str())
}

/// Open a log only if it is what the web server writes. Never through a symlink
/// (`O_NOFOLLOW`), never blocking on a FIFO swapped in after the glob matched
/// (`O_NONBLOCK`, no effect on a regular file), and checked on the open handle,
/// so a file a site's owner creates or swaps next to the real logs is refused.
/// The error of a refusal names the reason (see [`refusal`]).
pub(crate) fn open_log(path: &Path) -> io::Result<File> {
    let refuse = |why: String| io::Error::new(io::ErrorKind::PermissionDenied, Refused(why));
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(nix::libc::ELOOP) => refuse("a symbolic link".into()),
            _ => e,
        })?;
    let m = file.metadata()?;
    owner_and_mode_ok(m.is_file(), m.uid(), m.gid(), m.mode(), &allowed_owners())
        .map_err(refuse)?;
    Ok(file)
}

/// The offset of the end of `path` now, without reading it: for a log that is
/// followed again later, so that it starts from here rather than from where
/// it was left long ago (or from its end, losing what came between).
pub fn offset_at_end(path: &Path) -> io::Result<Offset> {
    let meta = open_log(path)?.metadata()?;
    Ok(Offset {
        dev: meta.dev(),
        inode: meta.ino(),
        pos: meta.len(),
    })
}

/// Read new complete lines from `path` given the previous offset (if any).
/// Caps total bytes read to `max_bytes` to bound a single cycle under a flood;
/// when capped, the offset still advances so the next cycle continues.
///
/// Lines are split on raw bytes and decoded lossily, so a stray non-UTF-8 byte
/// costs one odd character, not the file. The offset advances by exactly the
/// bytes of the complete lines returned; a last line without its newline yet
/// is left for the next cycle.
pub fn read_new(
    path: &Path,
    prev: Option<Offset>,
    first_sight_at_eof: bool,
    max_bytes: u64,
) -> io::Result<TailRead> {
    let mut file = open_log(path)?;
    let meta = file.metadata()?;
    let dev = meta.dev();
    let inode = meta.ino();
    let size = meta.len();

    let start = match prev {
        Some(o) if o.dev == dev && o.inode == inode && o.pos <= size => o.pos,
        Some(_) => 0, // rotated (inode/dev changed) or truncated
        None => {
            if first_sight_at_eof {
                size
            } else {
                0
            }
        }
    };

    if start >= size {
        return Ok(TailRead {
            lines: Vec::new(),
            new_offset: Offset {
                dev,
                inode,
                pos: size,
            },
            bytes: 0,
        });
    }

    file.seek(SeekFrom::Start(start))?;
    let capped = size - start > max_bytes;
    let to_read = (size - start).min(max_bytes);
    let mut reader = BufReader::new((&mut file).take(to_read));

    let mut lines = Vec::new();
    let mut consumed: u64 = 0;
    let mut read: u64 = 0;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)? as u64;
        if n == 0 {
            break;
        }
        read += n;
        if buf.last() != Some(&b'\n') {
            // The window ends inside a line: the server is still writing it,
            // or the cap cut it. Leave it for next time, unless it fills the
            // whole capped window (a line longer than the cap): step over that
            // so the file cannot stall on it.
            if capped && consumed == 0 {
                consumed = n;
            }
            break;
        }
        consumed += n;
        let text = String::from_utf8_lossy(&buf);
        lines.push(text.trim_end_matches(['\n', '\r']).to_string());
    }

    Ok(TailRead {
        lines,
        new_offset: Offset {
            dev,
            inode,
            pos: start + consumed,
        },
        bytes: read,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// Write a log the way a web server leaves it: 0644, whatever the umask.
    fn write(p: &Path, bytes: impl AsRef<[u8]>) {
        std::fs::write(p, bytes).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn append(p: &Path, bytes: &[u8]) {
        let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
        f.write_all(bytes).unwrap();
    }

    #[test]
    fn reads_incrementally() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        write(&p, "line1\nline2\n");

        let r1 = read_new(&p, None, false, 1 << 20).unwrap();
        assert_eq!(r1.lines, vec!["line1", "line2"]);

        // Append and read only the new line.
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "line3").unwrap();
        let r2 = read_new(&p, Some(r1.new_offset), false, 1 << 20).unwrap();
        assert_eq!(r2.lines, vec!["line3"]);
    }

    #[test]
    fn first_sight_at_eof_skips_history() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        write(&p, "old1\nold2\n");
        let r = read_new(&p, None, true, 1 << 20).unwrap();
        assert!(r.lines.is_empty());
    }

    #[test]
    fn detects_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        write(&p, "a\nb\nc\n");
        let r1 = read_new(&p, None, false, 1 << 20).unwrap();
        // Simulate rotation: shorter file at same path (truncated).
        write(&p, "x\n");
        let r2 = read_new(&p, Some(r1.new_offset), false, 1 << 20).unwrap();
        assert_eq!(r2.lines, vec!["x"]);
    }

    #[test]
    fn a_bad_byte_costs_one_character_not_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        write(&p, b"ok1\n\xff\xfebad\r\nok2 \xc3\xa9\n");
        let r = read_new(&p, None, false, 1 << 20).unwrap();
        assert_eq!(r.lines, vec!["ok1", "\u{fffd}\u{fffd}bad", "ok2 \u{e9}"]);
        // Exactly past every byte, so the next cycle starts after them.
        assert_eq!(r.new_offset.pos, std::fs::metadata(&p).unwrap().len());
        append(&p, b"ok3\n");
        let r = read_new(&p, Some(r.new_offset), false, 1 << 20).unwrap();
        assert_eq!(r.lines, vec!["ok3"]);
    }

    #[test]
    fn a_line_still_being_written_waits_for_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        write(&p, "a\nhal");
        let r = read_new(&p, None, false, 1 << 20).unwrap();
        assert_eq!(r.lines, vec!["a"]);
        assert_eq!(r.new_offset.pos, 2);
        append(&p, b"f\n");
        let r = read_new(&p, Some(r.new_offset), false, 1 << 20).unwrap();
        assert_eq!(r.lines, vec!["half"]);
        // Only a partial line: nothing consumed, nothing lost.
        append(&p, b"\xc3");
        let r2 = read_new(&p, Some(r.new_offset), false, 1 << 20).unwrap();
        assert!(r2.lines.is_empty());
        assert_eq!(r2.new_offset.pos, r.new_offset.pos);
    }

    #[test]
    fn the_cap_never_splits_or_skips_a_line() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        // The cap of 6 ends inside "def" and inside the two-byte 'é'.
        write(&p, "abc\ndef\n\u{e9}\u{e9}\n");
        let mut off = None;
        let mut got = Vec::new();
        for _ in 0..10 {
            let r = read_new(&p, off, false, 6).unwrap();
            got.extend(r.lines);
            off = Some(r.new_offset);
        }
        assert_eq!(got, vec!["abc", "def", "\u{e9}\u{e9}"]);
    }

    #[test]
    fn a_line_longer_than_the_cap_cannot_stall_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        write(&p, format!("{}\nnext\n", "x".repeat(20)));
        let mut off = None;
        let mut got = Vec::new();
        for _ in 0..10 {
            let r = read_new(&p, off, false, 8).unwrap();
            if let Some(o) = off {
                assert!(r.new_offset.pos > o.pos || r.bytes == 0);
            }
            got.extend(r.lines);
            off = Some(r.new_offset);
        }
        assert_eq!(got.last().map(String::as_str), Some("next"));
    }

    #[test]
    fn symlinks_fifos_and_shared_writable_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.log");
        write(&real, "a\n");

        // Each refusal says why, and is told apart from an I/O error.
        let link = dir.path().join("link_access.log");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = read_new(&link, None, false, 1 << 20).err().unwrap();
        assert_eq!(refusal(&err), Some("a symbolic link"), "{err}");

        // Opening a FIFO for reading would block until a writer comes.
        let fifo = dir.path().join("fifo_access.log");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let err = read_new(&fifo, None, false, 1 << 20).err().unwrap();
        assert!(
            refusal(&err).is_some_and(|w| w.contains("regular")),
            "{err}"
        );

        let open = dir.path().join("open_access.log");
        write(&open, "a\n");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o646)).unwrap();
        let err = read_new(&open, None, false, 1 << 20).err().unwrap();
        assert!(
            refusal(&err).is_some_and(|w| w.contains("writable")),
            "{err}"
        );
        assert!(err.to_string().contains("writable"), "{err}");

        let gone = dir.path().join("gone_access.log");
        let err = read_new(&gone, None, false, 1 << 20).err().unwrap();
        assert_eq!(refusal(&err), None, "{err}");
        assert!(read_new(&real, None, false, 1 << 20).is_ok());
    }

    #[test]
    fn only_root_or_the_web_server_may_own_a_log() {
        let owners = [0, 33];
        let ok = |uid, gid, mode| owner_and_mode_ok(true, uid, gid, mode, &owners);
        assert!(ok(0, 0, 0o100644).is_ok());
        assert!(ok(0, 4, 0o100640).is_ok());
        assert!(ok(33, 4, 0o100640).is_ok());
        // Group root may write; root is root.
        assert!(ok(0, 0, 0o100664).is_ok());
        // A site owner's own file.
        assert!(ok(1001, 1001, 0o100644).is_err());
        // Writable by a group that is not root's, or by anyone.
        assert!(ok(0, 4, 0o100664).is_err());
        assert!(ok(33, 0, 0o100646).is_err());
        assert!(owner_and_mode_ok(false, 0, 0, 0o010644, &owners).is_err());
    }
}
