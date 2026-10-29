//! Limit on the tar header data read for one archive member.
//!
//! Before the tar crate returns a member it reads the data of any PAX
//! extended header (`x`), GNU long name (`L`) or GNU long link (`K`) header
//! that precedes it fully into memory, sized only by what that header
//! declares. A small compressed archive can therefore declare gigabytes of
//! header data.
//!
//! [`limited_archive`] puts a counting reader between the decompressed stream
//! and the tar crate and refuses to deliver more than
//! [`MAX_TAR_HEADER_BYTES`] between the end of one member's data and the start
//! of the next member's data. That span holds only header material: padding,
//! the `x`/`L`/`K` headers and their data, GNU sparse extension blocks and
//! the member's own header. Member data is not limited here; the per-verb
//! byte limits govern it.
//!
//! The reader relies on two properties of tar 0.4: it reads its input
//! strictly in order and never past what it needs, so when it returns a
//! member it has read exactly up to that member's data; and it places the
//! next header at that point plus the member's stored size rounded up to
//! 512 bytes. The stored size is `Entry::size()` except for GNU sparse
//! members, whose `size()` is the expanded size (see [`stored_size`]).

use std::cell::Cell;
use std::io::{self, Read};
use std::rc::Rc;

use tar::{Archive, Entries, Entry, PaxExtensions};

/// Header data allowed for one member, in bytes of the decompressed tar
/// stream. Ordinary metadata is far smaller: a path is at most a few KiB and
/// a Linux extended attribute value at most 64 KiB.
pub(crate) const MAX_TAR_HEADER_BYTES: u64 = 1024 * 1024;

const BLOCK_SIZE: u64 = 512;

struct Budget {
    /// Bytes delivered to the tar crate so far.
    delivered: Cell<u64>,
    /// Position the tar crate may not read beyond.
    limit: Cell<u64>,
    max_header_bytes: u64,
}

impl Budget {
    fn exceeded(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "tar header data for one archive member exceeds {} bytes",
                self.max_header_bytes
            ),
        )
    }

    /// Move the limit past the data of `entry`, which the tar crate has just
    /// returned, allowing `max_header_bytes` of header data for the next one.
    fn member_returned<R: Read>(&self, entry: &mut Entry<'_, R>) -> io::Result<()> {
        let data_start = self.delivered.get();
        let overflow = || io::Error::new(io::ErrorKind::InvalidData, "tar member size overflow");
        let padded = stored_size(entry)?
            .checked_add(BLOCK_SIZE - 1)
            .ok_or_else(overflow)?
            & !(BLOCK_SIZE - 1);
        let limit = data_start
            .checked_add(padded)
            .and_then(|end| end.checked_add(self.max_header_bytes))
            .ok_or_else(overflow)?;
        self.limit.set(limit);
        Ok(())
    }
}

/// Size of the member's data in the archive, as the tar crate uses it to
/// find the next header.
fn stored_size<R: Read>(entry: &mut Entry<'_, R>) -> io::Result<u64> {
    if !entry.header().entry_type().is_gnu_sparse() {
        return Ok(entry.size());
    }
    // A sparse member's size() is its expanded size. The crate frames it by
    // the PAX `size` record if one parses, else by the header's size field.
    // The extensions were read before the member was returned, so this does
    // not read from the archive.
    if let Some(size) = entry.pax_extensions()?.and_then(pax_size) {
        return Ok(size);
    }
    entry.header().entry_size()
}

/// The PAX `size` record, read as tar 0.4's `pax_extensions_value` reads it:
/// the first record with key `size`, and none if a record before it is
/// malformed or its value is not a decimal u64.
fn pax_size(extensions: PaxExtensions<'_>) -> Option<u64> {
    for extension in extensions {
        let extension = extension.ok()?;
        if extension.key() != Ok("size") {
            continue;
        }
        return extension.value().ok()?.parse().ok();
    }
    None
}

/// Reader that counts what it delivers and refuses to go past the budget's
/// limit.
pub(crate) struct HeaderLimitedReader<R> {
    inner: R,
    budget: Rc<Budget>,
}

impl<R: Read> Read for HeaderLimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let delivered = self.budget.delivered.get();
        let room = self.budget.limit.get().saturating_sub(delivered);
        if room == 0 {
            return Err(self.budget.exceeded());
        }
        let want = usize::try_from(room).map_or(buf.len(), |room| room.min(buf.len()));
        let n = self.inner.read(&mut buf[..want])?;
        // n <= room, so this stays at or below the limit.
        self.budget.delivered.set(delivered + n as u64);
        Ok(n)
    }
}

/// A tar archive whose members may each be preceded by at most
/// `max_header_bytes` of header data.
pub(crate) struct LimitedArchive<R: Read> {
    archive: Archive<HeaderLimitedReader<R>>,
    budget: Rc<Budget>,
}

/// Read a tar archive from `reader` (the decompressed stream), limiting the
/// header data of each member to [`MAX_TAR_HEADER_BYTES`].
pub(crate) fn limited_archive<R: Read>(reader: R) -> LimitedArchive<R> {
    limited_archive_with(reader, MAX_TAR_HEADER_BYTES)
}

fn limited_archive_with<R: Read>(reader: R, max_header_bytes: u64) -> LimitedArchive<R> {
    let budget = Rc::new(Budget {
        delivered: Cell::new(0),
        limit: Cell::new(max_header_bytes),
        max_header_bytes,
    });
    LimitedArchive {
        archive: Archive::new(HeaderLimitedReader {
            inner: reader,
            budget: Rc::clone(&budget),
        }),
        budget,
    }
}

impl<R: Read> LimitedArchive<R> {
    /// The archive's members, as `tar::Archive::entries` returns them.
    pub(crate) fn entries(&mut self) -> io::Result<LimitedEntries<'_, R>> {
        Ok(LimitedEntries {
            entries: self.archive.entries()?,
            budget: Rc::clone(&self.budget),
            done: false,
        })
    }
}

pub(crate) struct LimitedEntries<'a, R: 'a + Read> {
    entries: Entries<'a, HeaderLimitedReader<R>>,
    budget: Rc<Budget>,
    done: bool,
}

impl<'a, R: Read> Iterator for LimitedEntries<'a, R> {
    type Item = io::Result<Entry<'a, HeaderLimitedReader<R>>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let result = self.entries.next()?.and_then(|mut entry| {
            self.budget.member_returned(&mut entry)?;
            Ok(entry)
        });
        // Like tar's own iterator, stop after the first error.
        self.done = result.is_err();
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tar::{EntryType, GnuExtSparseHeader, Header};

    const LIMIT_MESSAGE: &str = "tar header data for one archive member exceeds";

    /// Builds a tar stream block by block, so headers can declare sizes and
    /// types that `tar::Builder` would not write.
    #[derive(Default)]
    struct Raw(Vec<u8>);

    impl Raw {
        fn header(&mut self, mut h: Header) -> &mut Self {
            h.set_cksum();
            self.0.extend_from_slice(h.as_bytes());
            self
        }

        fn data(&mut self, data: &[u8]) -> &mut Self {
            self.0.extend_from_slice(data);
            let pad = (BLOCK_SIZE as usize - data.len() % 512) % 512;
            self.0.resize(self.0.len() + pad, 0);
            self
        }

        /// A header of `kind` named `name` with `data` as its contents.
        fn member(&mut self, kind: EntryType, name: &str, data: &[u8]) -> &mut Self {
            let mut h = Header::new_ustar();
            h.set_path(name).unwrap();
            h.set_entry_type(kind);
            h.set_mode(0o644);
            h.set_size(data.len() as u64);
            self.header(h).data(data)
        }

        fn file(&mut self, name: &str, data: &[u8]) -> &mut Self {
            self.member(EntryType::Regular, name, data)
        }

        fn pax(&mut self, records: &[(&str, &[u8])]) -> &mut Self {
            let data = pax_records(records);
            self.member(EntryType::XHeader, "PaxHeader", &data)
        }

        fn end(&mut self) -> Vec<u8> {
            self.0.resize(self.0.len() + 1024, 0);
            std::mem::take(&mut self.0)
        }
    }

    fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
        // "<len> <key>=<value>\n", where <len> counts its own digits.
        let rest = key.len() + value.len() + 3;
        let mut len = rest + 1;
        while len != rest + len.to_string().len() {
            len = rest + len.to_string().len();
        }
        let mut out = format!("{len} {key}=").into_bytes();
        out.extend_from_slice(value);
        out.push(b'\n');
        out
    }

    fn pax_records(records: &[(&str, &[u8])]) -> Vec<u8> {
        records.iter().flat_map(|(k, v)| pax_record(k, v)).collect()
    }

    /// PAX data of exactly `len` bytes (len >= 32): one comment record.
    fn pax_data_of_len(len: usize) -> Vec<u8> {
        let mut value_len = len - 12;
        loop {
            let rec = pax_record("comment", &vec![b'a'; value_len]);
            match rec.len().cmp(&len) {
                std::cmp::Ordering::Equal => return rec,
                std::cmp::Ordering::Greater => value_len -= 1,
                std::cmp::Ordering::Less => value_len += 1,
            }
        }
    }

    /// (path, contents) of every member, or the first error.
    fn read_all(tar: &[u8], max: u64) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut archive = limited_archive_with(tar, max);
        let mut out = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_string_lossy().into_owned();
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            out.push((path, data));
        }
        Ok(out)
    }

    /// Paths of every member, without reading their contents (the tar crate
    /// skips them).
    fn read_paths(tar: &[u8], max: u64) -> io::Result<Vec<String>> {
        let mut archive = limited_archive_with(tar, max);
        let mut out = Vec::new();
        for entry in archive.entries()? {
            out.push(entry?.path()?.to_string_lossy().into_owned());
        }
        Ok(out)
    }

    fn assert_refused<T>(result: io::Result<T>) {
        let Err(err) = result else {
            panic!("archive should be refused");
        };
        assert!(err.to_string().contains(LIMIT_MESSAGE), "{err}");
    }

    /// The smallest limit that reads `tar`: `exact` must work and one byte
    /// less must be refused. A wrong data size for one member moves the
    /// limit of the next by at least one block, so this checks the framing
    /// exactly when that next member needs the most header data.
    fn assert_needs_exactly(tar: &[u8], exact: u64) {
        read_all(tar, exact).unwrap();
        read_paths(tar, exact).unwrap();
        assert_refused(read_all(tar, exact - 1));
        assert_refused(read_paths(tar, exact - 1));
    }

    #[test]
    fn plain_members_need_one_header_block_each() {
        let big = vec![7u8; 300_000];
        let tar = Raw::default()
            .file("a", b"hello")
            .file("empty", b"")
            .file("big", &big)
            .file("b", b"x")
            .end();
        // Each member and the end-of-archive block need 512 bytes.
        assert_needs_exactly(&tar, 512);
        let all = read_all(&tar, MAX_TAR_HEADER_BYTES).unwrap();
        assert_eq!(all[2], ("big".to_string(), big));
        assert_eq!(all[3], ("b".to_string(), b"x".to_vec()));
    }

    #[test]
    fn file_data_does_not_count_as_header_data() {
        // 3 MiB of contents with a 1 KiB limit, read and skipped.
        let big = vec![0u8; 3 * 1024 * 1024];
        let tar = Raw::default().file("big", &big).file("after", b"ok").end();
        assert_eq!(read_all(&tar, 1024).unwrap()[1].1, b"ok");
        assert_eq!(read_paths(&tar, 1024).unwrap(), ["big", "after"]);
    }

    #[test]
    fn pax_gnu_and_stacked_headers_count_together() {
        let pax = pax_data_of_len(1500); // 3 blocks
        let long_name = vec![b'n'; 600]; // 2 blocks
        let long_link = vec![b'l'; 100]; // 1 block
        let tar = Raw::default()
            .file("first", b"1")
            .member(EntryType::XHeader, "PaxHeader", &pax)
            .member(EntryType::GNULongName, "././@LongLink", &long_name)
            .member(EntryType::GNULongLink, "././@LongLink", &long_link)
            .member(EntryType::Symlink, "short", b"")
            .file("last", b"2")
            .end();
        // x (1+3) + L (1+2) + K (1+1) + member header (1) = 10 blocks.
        assert_needs_exactly(&tar, 10 * 512);
        let paths = read_paths(&tar, MAX_TAR_HEADER_BYTES).unwrap();
        assert_eq!(paths[1], String::from_utf8(long_name).unwrap());
    }

    #[test]
    fn a_member_at_the_limit_is_read_and_one_byte_more_is_refused() {
        let max = MAX_TAR_HEADER_BYTES as usize;
        // x header + data + member header == the limit.
        let at = pax_data_of_len(max - 1024);
        let tar = Raw::default()
            .member(EntryType::XHeader, "PaxHeader", &at)
            .file("a", b"ok")
            .end();
        assert_eq!(read_all(&tar, MAX_TAR_HEADER_BYTES).unwrap()[0].1, b"ok");

        let over = pax_data_of_len(max - 1023);
        let tar = Raw::default()
            .member(EntryType::XHeader, "PaxHeader", &over)
            .file("a", b"ok")
            .end();
        assert_refused(read_all(&tar, MAX_TAR_HEADER_BYTES));
    }

    #[test]
    fn oversized_pax_and_gnu_headers_are_refused_without_reading_them() {
        for kind in [
            EntryType::XHeader,
            EntryType::GNULongName,
            EntryType::GNULongLink,
        ] {
            // Declares 8 GiB; only 2 MiB follows. Nothing past the limit may
            // be delivered to the tar crate.
            let mut h = Header::new_ustar();
            h.set_path("meta").unwrap();
            h.set_entry_type(kind);
            h.set_size(8 << 30);
            let mut raw = Raw::default();
            raw.file("before", b"x").header(h);
            raw.0.resize(raw.0.len() + 2 * 1024 * 1024, b'a');
            let tar = raw.0.clone();

            let mut archive = limited_archive(&tar[..]);
            let mut entries = archive.entries().unwrap();
            assert!(entries.next().unwrap().is_ok());
            assert_refused(entries.next().unwrap());
            assert!(entries.next().is_none(), "{kind:?}");
            drop(entries);
            assert_eq!(
                archive.budget.delivered.get(),
                1024 + MAX_TAR_HEADER_BYTES,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_first_member_is_limited_too() {
        let pax = pax_data_of_len(MAX_TAR_HEADER_BYTES as usize + 1);
        let tar = Raw::default()
            .member(EntryType::XHeader, "PaxHeader", &pax)
            .file("a", b"x")
            .end();
        assert_refused(read_paths(&tar, MAX_TAR_HEADER_BYTES));
    }

    #[test]
    fn each_member_gets_its_own_limit() {
        // Every member is preceded by 2 KiB of PAX data; with a 3 KiB limit
        // each is accepted however many there are.
        let pax = pax_data_of_len(2048);
        let mut raw = Raw::default();
        for i in 0..50 {
            raw.member(EntryType::XHeader, "PaxHeader", &pax)
                .file(&format!("f{i}"), &[0u8; 700]);
        }
        let tar = raw.end();
        assert_eq!(read_paths(&tar, 3 * 1024).unwrap().len(), 50);
        // x (1+4) + member header (1) = 6 blocks.
        assert_needs_exactly(&tar, 6 * 512);
    }

    #[test]
    fn global_pax_headers_are_members_and_their_data_is_skipped() {
        let global = pax_records(&[("comment", &vec![b'g'; 4000])]);
        let tar = Raw::default()
            .member(EntryType::XGlobalHeader, "pax_global_header", &global)
            .file("a", b"x")
            .member(EntryType::XGlobalHeader, "pax_global_header", &global)
            .file("b", b"y")
            .end();
        assert_eq!(
            read_paths(&tar, 512).unwrap(),
            ["pax_global_header", "a", "pax_global_header", "b"]
        );
        assert_needs_exactly(&tar, 512);
    }

    #[test]
    fn pax_size_overrides_the_header_size_field() {
        // As GNU tar writes members over 8 GiB, scaled down: the ustar size
        // field is 0 and the real size is only in the PAX record.
        let data = vec![9u8; 5000];
        let mut h = Header::new_ustar();
        h.set_path("big").unwrap();
        h.set_size(0);
        let tar = {
            let mut raw = Raw::default();
            raw.pax(&[("size", b"5000")]).header(h).data(&data);
            raw.file("after", b"ok").end()
        };
        let all = read_all(&tar, MAX_TAR_HEADER_BYTES).unwrap();
        assert_eq!(all[0].1, data);
        assert_eq!(all[1], ("after".to_string(), b"ok".to_vec()));
        // x (1+1) + member header (1).
        assert_needs_exactly(&tar, 3 * 512);

        // A header size larger than the PAX size must not widen the limit:
        // the crate frames by the PAX size, and the 4 KiB of PAX data before
        // "after" counts against the 3 KiB limit.
        let mut h = Header::new_ustar();
        h.set_path("small").unwrap();
        h.set_size(1 << 30);
        let pax = pax_data_of_len(4096);
        let tar = {
            let mut raw = Raw::default();
            raw.pax(&[("size", b"1")]).header(h).data(b"z");
            raw.member(EntryType::XHeader, "PaxHeader", &pax)
                .file("after", b"ok")
                .end()
        };
        assert_refused(read_paths(&tar, 3 * 1024));
        assert_eq!(read_paths(&tar, 5 * 1024).unwrap(), ["small", "after"]);
    }

    fn sparse_header(name: &str, real_size: u64, stored: u64, extended: bool) -> Header {
        let mut h = Header::new_gnu();
        h.set_path(name).unwrap();
        h.set_entry_type(EntryType::GNUSparse);
        h.set_mode(0o644);
        h.set_size(stored);
        let gnu = h.as_gnu_mut().unwrap();
        gnu.realsize = octal12(real_size);
        gnu.isextended[0] = u8::from(extended);
        h
    }

    fn octal12(v: u64) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..11].copy_from_slice(format!("{v:011o}").as_bytes());
        out
    }

    fn set_region(region: &mut tar::GnuSparseHeader, offset: u64, len: u64) {
        region.offset = octal12(offset);
        region.numbytes = octal12(len);
    }

    #[test]
    fn sparse_members_are_framed_by_their_stored_size() {
        // Three 512-byte data regions in a 1 MiB file: one in the header and
        // two in extension blocks. size() is 1 MiB; the stored data is 1536.
        let mut h = sparse_header("sparse", 1 << 20, 1536, true);
        set_region(&mut h.as_gnu_mut().unwrap().sparse[0], 0, 512);
        let mut ext1 = GnuExtSparseHeader::new();
        set_region(&mut ext1.sparse[0], 4096, 512);
        ext1.isextended[0] = 1;
        let mut ext2 = GnuExtSparseHeader::new();
        set_region(&mut ext2.sparse[0], (1 << 20) - 512, 512);

        let mut raw = Raw::default();
        raw.file("before", b"1").header(h);
        raw.0.extend_from_slice(ext1.as_bytes());
        raw.0.extend_from_slice(ext2.as_bytes());
        raw.data(&[b'a'; 512]).data(&[b'b'; 512]).data(&[b'c'; 512]);
        let tar = raw
            .member(EntryType::XHeader, "PaxHeader", &pax_data_of_len(2048))
            .file("after", b"2")
            .end();

        let all = read_all(&tar, MAX_TAR_HEADER_BYTES).unwrap();
        assert_eq!(all[1].1.len(), 1 << 20);
        assert_eq!(&all[1].1[4096..4097], b"b");
        assert_eq!(all[2], ("after".to_string(), b"2".to_vec()));
        // The sparse member needs its header and two extension blocks (3);
        // "after" needs x (1+4) + its header (1), counted from the end of the
        // sparse member's 1536 stored bytes.
        assert_needs_exactly(&tar, 6 * 512);
    }

    #[test]
    fn sparse_member_with_pax_size_uses_it() {
        // 1 KiB of data at offset 1024 and a trailing hole to 8 KiB. The
        // header size field is 0; only the PAX record has the stored size.
        let mut h = sparse_header("sparse", 8192, 0, false);
        set_region(&mut h.as_gnu_mut().unwrap().sparse[0], 1024, 1024);
        set_region(&mut h.as_gnu_mut().unwrap().sparse[1], 8192, 0);
        let mut raw = Raw::default();
        raw.pax(&[("size", b"1024")]).header(h).data(&[b's'; 1024]);
        let tar = raw
            .member(EntryType::XHeader, "PaxHeader", &pax_data_of_len(2048))
            .file("after", b"2")
            .end();
        let all = read_all(&tar, MAX_TAR_HEADER_BYTES).unwrap();
        assert_eq!(all[0].1.len(), 8192);
        assert_eq!(all[1].1, b"2");
        // "after": x (1+4) + its header (1), from the end of the 1024 stored
        // bytes (not the 8192 expanded or the 0 in the header).
        assert_needs_exactly(&tar, 6 * 512);
    }

    #[test]
    fn pax_size_is_read_like_the_tar_crate_reads_it() {
        let parse = |records: &[(&str, &[u8])]| pax_size(PaxExtensions::new(&pax_records(records)));
        assert_eq!(parse(&[("path", b"a"), ("size", b"12")]), Some(12));
        assert_eq!(parse(&[("size", b"12"), ("size", b"99")]), Some(12));
        assert_eq!(parse(&[("size", b"-1")]), None);
        assert_eq!(parse(&[("size", b"1e3")]), None);
        assert_eq!(parse(&[("size", b"18446744073709551616")]), None);
        assert_eq!(parse(&[("SIZE", b"12")]), None);
        assert_eq!(parse(&[]), None);
        // A malformed record before `size` hides it.
        let mut bad = b"9 x\n".to_vec();
        bad.extend(pax_record("size", b"12"));
        assert_eq!(pax_size(PaxExtensions::new(&bad)), None);
    }

    #[test]
    fn malformed_and_truncated_archives_fail_without_exceeding_the_limit() {
        // Header declaring more data than the archive holds.
        let mut h = Header::new_ustar();
        h.set_path("meta").unwrap();
        h.set_entry_type(EntryType::XHeader);
        h.set_size(4096);
        let mut raw = Raw::default();
        raw.header(h);
        raw.0.extend_from_slice(&[b'a'; 100]);
        assert!(read_paths(&raw.0, MAX_TAR_HEADER_BYTES).is_err());

        // A truncated header block.
        let tar = Raw::default().file("a", b"x").end();
        assert!(read_paths(&tar[..700], MAX_TAR_HEADER_BYTES).is_err());

        // Bad checksum.
        let mut tar = Raw::default().file("a", b"x").end();
        tar[0] ^= 1;
        assert!(read_paths(&tar, MAX_TAR_HEADER_BYTES).is_err());

        // A PAX header with no member after it.
        let tar = Raw::default().pax(&[("path", b"x")]).end();
        assert!(read_paths(&tar, MAX_TAR_HEADER_BYTES).is_err());

        // Empty input is an empty archive.
        assert!(read_paths(b"", MAX_TAR_HEADER_BYTES).unwrap().is_empty());
    }

    #[test]
    fn a_member_size_near_u64_max_is_refused() {
        let mut h = Header::new_gnu();
        h.set_path("huge").unwrap();
        // base-256 size field, block aligned: the tar crate can place the
        // next header, but that position plus the header limit overflows.
        h.as_gnu_mut().unwrap().size = {
            let mut f = [0u8; 12];
            f[0] = 0x80;
            f[4..].copy_from_slice(&(u64::MAX - 4095).to_be_bytes());
            f
        };
        let mut raw = Raw::default();
        raw.header(h);
        let err = read_paths(&raw.end(), MAX_TAR_HEADER_BYTES).unwrap_err();
        assert!(
            err.to_string().contains("tar member size overflow"),
            "{err}"
        );
    }

    #[test]
    fn compressed_streams_are_limited_after_decompression() {
        use flate2::{Compression, read::GzDecoder, write::GzEncoder};
        let pax = pax_data_of_len(2 * 1024 * 1024);
        let tar = Raw::default()
            .member(EntryType::XHeader, "PaxHeader", &pax)
            .file("a", b"x")
            .end();
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar).unwrap();
        let gz = enc.finish().unwrap();
        assert!(gz.len() < 64 * 1024);

        let mut archive = limited_archive(GzDecoder::new(&gz[..]));
        assert_refused(archive.entries().unwrap().next().unwrap());

        // A truncated compressed stream fails as before.
        let ok = Raw::default().file("a", &[1u8; 10_000]).end();
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&ok).unwrap();
        let gz = enc.finish().unwrap();
        let mut archive = limited_archive(GzDecoder::new(&gz[..gz.len() / 2]));
        let failed = archive
            .entries()
            .unwrap()
            .any(|e| e.and_then(|mut e| e.read_to_end(&mut Vec::new())).is_err());
        assert!(failed);
    }

    #[test]
    fn builder_archives_are_unchanged() {
        // Archives as tar::Builder writes them, including long GNU names.
        let mut b = tar::Builder::new(Vec::new());
        let long = format!("{}/file.txt", "d".repeat(300));
        let mut h = Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o644);
        b.append_data(&mut h, &long, &b"abc"[..]).unwrap();
        let mut h = Header::new_gnu();
        h.set_size(0);
        h.set_mode(0o644);
        b.append_data(&mut h, "empty", &b""[..]).unwrap();
        let tar = b.into_inner().unwrap();
        let all = read_all(&tar, MAX_TAR_HEADER_BYTES).unwrap();
        assert_eq!(all[0], (long, b"abc".to_vec()));
        assert_eq!(all[1], ("empty".to_string(), vec![]));
    }
}
