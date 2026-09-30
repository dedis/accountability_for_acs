//! Minimal RFC 4180 CSV reading and writing, matching the JS helpers.

use std::borrow::Cow;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};

/// Quotes a field only when it needs quoting, as the JS `csvEscape` did.
fn escape(value: &str) -> Cow<'_, str> {
    if value.contains([',', '"', '\n']) {
        Cow::Owned(format!("\"{}\"", value.replace('"', "\"\"")))
    } else {
        Cow::Borrowed(value)
    }
}

fn write_row<W: Write, S: AsRef<str>>(out: &mut W, fields: &[S]) -> Result<()> {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.write_all(b",")?;
        }
        out.write_all(escape(field.as_ref()).as_bytes())?;
    }
    out.write_all(b"\n")?;
    Ok(())
}

/// Writes `headers` followed by `rows`, creating parent directories.
///
/// Every row must hold one field per header, in header order.
pub fn write(path: &Path, headers: &[&str], rows: &[Vec<String>]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut out = BufWriter::new(file);

    write_row(&mut out, headers)?;
    for row in rows {
        debug_assert_eq!(row.len(), headers.len(), "row width must match headers");
        write_row(&mut out, row)?;
    }
    out.flush()?;
    Ok(())
}

/// Appends one row, writing the header first if the file does not exist yet.
pub fn append(path: &Path, headers: &[&str], row: &[String]) -> Result<()> {
    debug_assert_eq!(row.len(), headers.len(), "row width must match headers");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let exists = path.exists();
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let mut out = BufWriter::new(file);

    if !exists {
        write_row(&mut out, headers)?;
    }
    write_row(&mut out, row)?;
    out.flush()?;
    Ok(())
}

/// A parsed CSV: header names plus one field vector per data row.
///
/// Splits on commas without honouring quoting, exactly like the JS
/// `parseCsv`: the files these tools produce hold only numbers, plain
/// identifiers and the benchmark name.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn read(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut lines = text.trim().lines();
        let headers: Vec<String> = lines
            .next()
            .unwrap_or_default()
            .split(',')
            .map(str::to_string)
            .collect();
        let rows = lines
            .map(|line| line.split(',').map(str::to_string).collect())
            .collect();
        Ok(Self { headers, rows })
    }

    pub fn headers(&self) -> &[String] {
        &self.headers
    }

    /// Index of the column named `name`.
    pub fn column(&self, name: &str) -> Result<usize> {
        self.headers
            .iter()
            .position(|h| h == name)
            .ok_or_else(|| anyhow!("missing column {name:?}"))
    }

    /// The data rows; each holds one field per header.
    pub fn rows(&self) -> impl Iterator<Item = Record<'_>> {
        self.rows.iter().map(|fields| Record { fields })
    }
}

/// One data row of a [`Table`].
#[derive(Clone, Copy)]
pub struct Record<'a> {
    fields: &'a [String],
}

impl Record<'_> {
    /// The raw text of column `index`, empty when the row is short.
    pub fn text(&self, index: usize) -> &str {
        self.fields.get(index).map_or("", String::as_str)
    }

    /// Parses column `index`; an empty field is an error.
    pub fn parse<T: FromStr>(&self, index: usize, name: &str) -> Result<T> {
        let raw = self.text(index);
        raw.parse()
            .map_err(|_| anyhow!("column {name:?}: cannot parse {raw:?}"))
    }

    /// Parses column `index`, treating an empty field as `None`.
    pub fn parse_opt<T: FromStr>(&self, index: usize, name: &str) -> Result<Option<T>> {
        if self.text(index).is_empty() {
            return Ok(None);
        }
        self.parse(index, name).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_only_when_needed() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a,b"), "\"a,b\"");
        assert_eq!(escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn roundtrips_through_a_file() {
        let dir = std::env::temp_dir().join("revocation-csv-test");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rows.csv");

        write(
            &path,
            &["benchmark", "set_size", "recurring_pct"],
            &[vec!["direct-decrypt".into(), "10".into(), String::new()]],
        )
        .unwrap();

        let table = Table::read(&path).unwrap();
        assert_eq!(table.headers(), ["benchmark", "set_size", "recurring_pct"]);
        let row = table.rows().next().unwrap();
        assert_eq!(
            row.text(table.column("benchmark").unwrap()),
            "direct-decrypt"
        );
        assert_eq!(row.parse::<u64>(1, "set_size").unwrap(), 10);
        assert_eq!(row.parse_opt::<f64>(2, "recurring_pct").unwrap(), None);
        assert!(row.parse::<u64>(0, "benchmark").is_err());
        assert!(table.column("nope").is_err());

        fs::remove_file(&path).unwrap();
    }
}
