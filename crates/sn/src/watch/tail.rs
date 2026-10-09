//! Incremental log reading with rotation detection.
//!
//! For each file we remember `(dev, inode, pos)`. If the inode/device changed
//! or the file is now shorter than our offset, the file rotated and we read
//! from the start of the new file. On first sight (no stored offset) we start
//! at EOF so a fresh install does not replay the entire historical log and
//! mass-ban on day one; the installer separately seeds the baseline from
//! rotated logs.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::state::Offset;

/// Result of reading new bytes from one file.
pub struct TailRead {
    pub lines: Vec<String>,
    pub new_offset: Offset,
    pub bytes: u64,
}

/// Read new complete lines from `path` given the previous offset (if any).
/// Caps total bytes read to `max_bytes` to bound a single cycle under a flood;
/// when capped, the offset still advances so the next cycle continues.
pub fn read_new(
    path: &Path,
    prev: Option<Offset>,
    first_sight_at_eof: bool,
    max_bytes: u64,
) -> std::io::Result<TailRead> {
    let mut file = File::open(path)?;
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
    let to_read = (size - start).min(max_bytes);
    let mut limited = (&mut file).take(to_read);
    let reader = BufReader::new(&mut limited);

    let mut lines = Vec::new();
    let mut consumed: u64 = 0;
    for line in reader.lines() {
        let line = line?;
        consumed += line.len() as u64 + 1; // approx (+newline)
        lines.push(line);
    }

    let new_pos = (start + consumed).min(size);
    Ok(TailRead {
        lines,
        new_offset: Offset {
            dev,
            inode,
            pos: new_pos,
        },
        bytes: consumed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_incrementally() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        std::fs::write(&p, "line1\nline2\n").unwrap();

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
        std::fs::write(&p, "old1\nold2\n").unwrap();
        let r = read_new(&p, None, true, 1 << 20).unwrap();
        assert!(r.lines.is_empty());
    }

    #[test]
    fn detects_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        std::fs::write(&p, "a\nb\nc\n").unwrap();
        let r1 = read_new(&p, None, false, 1 << 20).unwrap();
        // Simulate rotation: shorter file at same path (truncated).
        std::fs::write(&p, "x\n").unwrap();
        let r2 = read_new(&p, Some(r1.new_offset), false, 1 << 20).unwrap();
        assert_eq!(r2.lines, vec!["x"]);
    }
}
