//! Compiling and running MP-SPDZ programs, and parsing what they print. Pure
//! orchestration: no protocol logic.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use regex::Regex;
use zeroize::Zeroize;

/// Compiles `<name>.mpc` with the given arguments, reusing a cached schedule
/// compiled from the same source.
///
/// Returns the compiled program name, `<name>-<arg>-<arg>`.
pub fn compile(spdz_path: &Path, mpc_src: &Path, name: &str, args: &[String]) -> Result<String> {
    let src_dir = spdz_path.join("Programs").join("Source");
    fs::create_dir_all(&src_dir).with_context(|| format!("create {}", src_dir.display()))?;
    let source = fs::read(mpc_src).with_context(|| format!("read {}", mpc_src.display()))?;
    fs::write(src_dir.join(format!("{name}.mpc")), &source)
        .with_context(|| format!("copy {} into {}", mpc_src.display(), src_dir.display()))?;

    let full_name = std::iter::once(name.to_string())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join("-");

    // A schedule is reused only with the source it was compiled from, kept
    // next to it.
    let schedules = spdz_path.join("Programs").join("Schedules");
    let schedule = schedules.join(format!("{full_name}.sch"));
    let compiled_from = schedules.join(format!("{full_name}.source.mpc"));
    if schedule.exists() && fs::read(&compiled_from).is_ok_and(|s| s == source) {
        println!("[mpc] cached compile for {full_name}");
        return Ok(full_name);
    }

    println!("[mpc] compiling {name} {} ...", args.join(" "));
    let started = Instant::now();
    let output = Command::new("./compile.py")
        .args(std::iter::once(name).chain(args.iter().map(String::as_str)))
        .current_dir(spdz_path)
        .output()
        .with_context(|| format!("run ./compile.py in {}", spdz_path.display()))?;
    if !output.status.success() {
        bail!(
            "./compile.py {name} {} failed ({})\nstderr:\n{}\nstdout:\n{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
    }
    fs::write(&compiled_from, &source)
        .with_context(|| format!("write {}", compiled_from.display()))?;
    println!(
        "[mpc] compile done ({} ms) -> {full_name}.sch",
        started.elapsed().as_millis()
    );
    Ok(full_name)
}

/// What each party wrote to its pipes.
pub struct PartyOutput {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
}

/// The MP-SPDZ protocol: Shamir secret sharing among the three authorities.
const PROTOCOL: &str = "shamir-party.x";

/// Launches one copy of [`PROTOCOL`] per entry of `inputs` and waits for all
/// of them, at most `MP_SPDZ_TIMEOUT_S` seconds (default 3600); parties still
/// running then are killed. Party `p` reads its private inputs, whitespace-separated
/// integers, from `inputs[p]` on its standard input (`-I`), so no input
/// reaches the disk; `inputs` is set to zero afterwards. Every party prints
/// its output (`-OF .`). `MP_SPDZ_PORT`, when set, is the parties' base port
/// (`-pn`; MP-SPDZ's default is 5000, which the macOS AirPlay receiver
/// holds).
///
/// Each pipe is written or drained on its own thread: MP-SPDZ is verbose
/// under `-v` and a party blocks once a pipe buffer fills.
pub fn run(spdz_path: &Path, full_name: &str, mut inputs: Vec<String>) -> Result<PartyOutput> {
    let output = run_parties(spdz_path, full_name, &inputs);
    inputs.zeroize();
    output
}

fn run_parties(spdz_path: &Path, full_name: &str, inputs: &[String]) -> Result<PartyOutput> {
    let parties = inputs.len();
    println!("[mpc] launching {parties} parties: {PROTOCOL} {full_name}");
    let started = Instant::now();
    let port = crate::env::var("MP_SPDZ_PORT");
    let limit = Duration::from_secs(crate::env::usize_or("MP_SPDZ_TIMEOUT_S", 3600)? as u64);

    let mut children = Vec::with_capacity(parties);
    for party in 0..parties {
        let mut command = Command::new(format!("./{PROTOCOL}"));
        if let Some(port) = &port {
            command.args(["-pn", port]);
        }
        // No memory dump: MP-SPDZ would write every party's shares of its
        // secret memory to Player-Data after the run.
        let child = command
            .args([
                "-v",
                "-I",
                "-OF",
                ".",
                "-o",
                "no_memory_output",
                "-N",
                &parties.to_string(),
                "-p",
                &party.to_string(),
                full_name,
            ])
            .current_dir(spdz_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        match child {
            Ok(child) => children.push(child),
            Err(e) => {
                stop(&mut children);
                return Err(e).with_context(|| format!("spawn {PROTOCOL} -p {party}"));
            }
        }
    }

    let mut codes: Vec<Option<i32>> = vec![None; parties];
    let mut written: Vec<std::io::Result<()>> = Vec::new();
    let mut read: Vec<Result<String>> = Vec::new();
    std::thread::scope(|scope| {
        let mut readers = Vec::with_capacity(parties * 2);
        let mut writers = Vec::with_capacity(parties);
        for (child, input) in children.iter_mut().zip(inputs) {
            let mut stdin = child.stdin.take().expect("piped stdin");
            let out = child.stdout.take().expect("piped stdout");
            let err = child.stderr.take().expect("piped stderr");
            // Dropping stdin at the end closes it.
            writers.push(scope.spawn(move || stdin.write_all(input.as_bytes())));
            readers.push(scope.spawn(move || drain(out)));
            readers.push(scope.spawn(move || drain(err)));
        }

        // Every party exits, or is stopped at the time limit, before any pipe
        // thread is joined: a stuck party cannot block the runner.
        let polls = limit.as_millis() / POLL.as_millis() + 1;
        for _ in 0..polls {
            for (child, code) in children.iter_mut().zip(codes.iter_mut()) {
                if code.is_none() {
                    *code = match child.try_wait() {
                        Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
                        Ok(None) => None,
                        Err(_) => {
                            stop(std::slice::from_mut(child));
                            Some(-1)
                        }
                    };
                }
            }
            if codes.iter().all(Option::is_some) || started.elapsed() >= limit {
                break;
            }
            std::thread::sleep(POLL);
        }
        if codes.iter().any(Option::is_none) {
            stop(&mut children);
        }

        written = writers
            .into_iter()
            .map(|w| w.join().expect("pipe writer thread"))
            .collect();
        read = readers
            .into_iter()
            .map(|r| r.join().expect("pipe reader thread"))
            .collect();
    });

    println!(
        "[mpc] done in {} ms (codes: [{}])",
        started.elapsed().as_millis(),
        codes
            .iter()
            .map(|c| c.map_or_else(|| "stopped".to_string(), |c| c.to_string()))
            .collect::<Vec<_>>()
            .join(",")
    );

    let mut stdout = Vec::with_capacity(parties);
    let mut stderr = Vec::with_capacity(parties);
    for (i, text) in read.into_iter().enumerate() {
        let text = text.with_context(|| format!("read the pipes of party {}", i / 2))?;
        if i % 2 == 0 {
            stdout.push(text);
        } else {
            stderr.push(text);
        }
    }
    // Only stderr: stdout holds the revealed output, which the caller has not
    // checked yet.
    if codes.iter().any(Option::is_none) {
        bail!(
            "MP-SPDZ did not finish within {} s (MP_SPDZ_TIMEOUT_S); stderr (p0):\n{}",
            limit.as_secs(),
            stderr.first().map_or("", String::as_str)
        );
    }
    if codes.iter().any(|c| *c != Some(0)) {
        bail!(
            "MP-SPDZ failed.\nstderr (p0):\n{}",
            stderr.first().map_or("", String::as_str)
        );
    }
    for (party, result) in written.into_iter().enumerate() {
        result.with_context(|| format!("write the inputs of party {party}"))?;
    }

    Ok(PartyOutput { stdout, stderr })
}

/// How often [`run_parties`] checks whether the parties have exited.
const POLL: Duration = Duration::from_millis(10);

/// Kills and waits for every child. Errors are ignored: a child that has
/// already exited cannot be killed, and the caller reports the failure that
/// led here.
fn stop(children: &mut [Child]) {
    for child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn drain<R: Read>(mut pipe: R) -> Result<String> {
    let mut buf = Vec::new();
    pipe.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Reads the `row_<i>=<0|1>` predicate lines a party prints.
pub fn parse_predicates(stdout: &str, n: usize) -> Result<Vec<bool>> {
    static ROW: OnceLock<Regex> = OnceLock::new();
    let row = ROW.get_or_init(|| Regex::new(r"^row_(\d+)=(\d)").expect("valid regex"));

    let mut out = vec![None; n];
    for line in stdout.lines() {
        if let Some(caps) = row.captures(line) {
            let index: usize = caps[1].parse().context("predicate row index")?;
            if index < n {
                out[index] = Some(&caps[2] == "1");
            }
        }
    }

    out.into_iter()
        .collect::<Option<Vec<bool>>>()
        .with_context(|| format!("failed to parse all {n} predicate rows from MP-SPDZ stdout"))
}

/// Timing and bandwidth counters MP-SPDZ reports under `-v`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SpdzStats {
    pub total_ms: Option<f64>,
    pub online_ms: Option<f64>,
    pub offline_ms: Option<f64>,
    pub online_bytes: Option<u64>,
    pub online_rounds: Option<u64>,
    pub offline_bytes: Option<u64>,
    pub offline_rounds: Option<u64>,
    pub data_sent_bytes: Option<u64>,
    pub data_sent_rounds: Option<u64>,
    pub global_data_sent_bytes: Option<u64>,
}

impl SpdzStats {
    /// Adds the counters of another run; a counter missing in one run keeps
    /// the other's value.
    pub fn add(&mut self, other: &SpdzStats) {
        fn sum<T: std::ops::Add<Output = T> + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
            match (a, b) {
                (Some(a), Some(b)) => Some(a + b),
                (a, b) => a.or(b),
            }
        }
        self.total_ms = sum(self.total_ms, other.total_ms);
        self.online_ms = sum(self.online_ms, other.online_ms);
        self.offline_ms = sum(self.offline_ms, other.offline_ms);
        self.online_bytes = sum(self.online_bytes, other.online_bytes);
        self.online_rounds = sum(self.online_rounds, other.online_rounds);
        self.offline_bytes = sum(self.offline_bytes, other.offline_bytes);
        self.offline_rounds = sum(self.offline_rounds, other.offline_rounds);
        self.data_sent_bytes = sum(self.data_sent_bytes, other.data_sent_bytes);
        self.data_sent_rounds = sum(self.data_sent_rounds, other.data_sent_rounds);
        self.global_data_sent_bytes =
            sum(self.global_data_sent_bytes, other.global_data_sent_bytes);
    }
}

fn seconds_to_ms(raw: &str) -> Option<f64> {
    raw.parse::<f64>().ok().map(|s| s * 1000.0)
}

fn to_bytes(value: &str, unit: &str) -> Option<u64> {
    let v: f64 = value.parse().ok()?;
    let scale = match unit.chars().next().map(|c| c.to_ascii_lowercase()) {
        Some('g') => 1024f64.powi(3),
        Some('m') => 1024f64.powi(2),
        Some('k') => 1024.0,
        _ => 1.0,
    };
    Some((v * scale).round() as u64)
}

/// Parses party 0's combined stdout+stderr.
pub fn parse_spdz_stats(combined: &str) -> SpdzStats {
    static PATTERNS: OnceLock<[Regex; 5]> = OnceLock::new();
    let [total, online, phases, data_sent, global] = PATTERNS.get_or_init(|| {
        [
            Regex::new(r"\bTime\s*=\s*([\d.]+)(?:\s*seconds?)?\b").expect("valid regex"),
            Regex::new(r"\bTime1\s*=\s*([\d.]+)(?:\s*seconds?)?\b").expect("valid regex"),
            Regex::new(
                r"(?i)Spent\s+([\d.]+)\s*seconds?\s*\(([\d.]+)\s*([kKmMgG]?B),\s*(\d+)\s*rounds?\)\s*on\s*the\s*online\s*phase\s*and\s*([\d.]+)\s*seconds?\s*\(([\d.]+)\s*([kKmMgG]?B),\s*(\d+)\s*rounds?\)\s*on\s*the\s*preprocessing(?:/offline)?\s*phase",
            )
            .expect("valid regex"),
            Regex::new(r"Data sent\s*=\s*([\d.]+)\s*([kKmMgG]?B)\s*in\s*~?(\d+)\s*rounds?")
                .expect("valid regex"),
            Regex::new(r"Global data sent\s*=\s*([\d.]+)\s*([kKmMgG]?B)").expect("valid regex"),
        ]
    });

    let mut stats = SpdzStats::default();

    if let Some(caps) = total.captures(combined) {
        stats.total_ms = seconds_to_ms(&caps[1]);
    }
    if let Some(caps) = online.captures(combined) {
        stats.online_ms = seconds_to_ms(&caps[1]);
    }
    if let Some(caps) = phases.captures(combined) {
        stats.online_ms = seconds_to_ms(&caps[1]);
        stats.online_bytes = to_bytes(&caps[2], &caps[3]);
        stats.online_rounds = caps[4].parse().ok();
        stats.offline_ms = seconds_to_ms(&caps[5]);
        stats.offline_bytes = to_bytes(&caps[6], &caps[7]);
        stats.offline_rounds = caps[8].parse().ok();
    }
    if let Some(caps) = data_sent.captures(combined) {
        stats.data_sent_bytes = to_bytes(&caps[1], &caps[2]);
        stats.data_sent_rounds = caps[3].parse().ok();
    }
    if let Some(caps) = global.captures(combined) {
        stats.global_data_sent_bytes = to_bytes(&caps[1], &caps[2]);
    }

    stats
}

/// Reads the `<label>_<i>=<v>,<v>,...` lines a party prints, for `i` in
/// `0..n`, each with `width` values.
pub fn parse_rows(stdout: &str, label: &str, n: usize, width: usize) -> Result<Vec<Vec<u64>>> {
    let prefix = format!("{label}_");
    let mut out: Vec<Option<Vec<u64>>> = vec![None; n];
    for line in stdout.lines() {
        let Some((index, values)) = line
            .strip_prefix(&prefix)
            .and_then(|rest| rest.split_once('='))
        else {
            continue;
        };
        let index: usize = index
            .parse()
            .with_context(|| format!("{label} row index"))?;
        let values = values
            .split(',')
            .map(|v| v.trim().parse::<u64>())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("{label} row {index}"))?;
        if index < n && values.len() == width {
            out[index] = Some(values);
        }
    }
    out.into_iter()
        .collect::<Option<Vec<_>>>()
        .with_context(|| format!("failed to parse all {n} {label} rows from MP-SPDZ stdout"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_predicate_rows() {
        let stdout = "noise\nrow_0=1\nrow_2=0\nrow_1=1\nmore noise\n";
        assert_eq!(parse_predicates(stdout, 3).unwrap(), [true, true, false]);
        assert!(parse_predicates(stdout, 4).is_err());
    }

    #[test]
    fn reads_value_rows() {
        let stdout = "noise\ncft_1=4,5\ncft_0=1,2\ncft_2=7\n";
        assert_eq!(
            parse_rows(stdout, "cft", 2, 2).unwrap(),
            [vec![1, 2], vec![4, 5]]
        );
        // Row 2 has the wrong width.
        assert!(parse_rows(stdout, "cft", 3, 2).is_err());
    }

    #[test]
    fn reads_phase_timings_and_bandwidth() {
        let combined = concat!(
            "Time = 1.5 seconds\n",
            "Time1 = 0.25 seconds\n",
            "Spent 0.4 seconds (12.5 MB, 30 rounds) on the online phase ",
            "and 1.1 seconds (2 GB, 7 rounds) on the preprocessing phase\n",
            "Data sent = 512 kB in ~40 rounds\n",
            "Global data sent = 1.5 MB\n",
        );
        let stats = parse_spdz_stats(combined);
        assert_eq!(stats.total_ms, Some(1500.0));
        assert_eq!(stats.online_ms, Some(400.0));
        assert_eq!(stats.offline_ms, Some(1100.0));
        assert_eq!(stats.online_bytes, Some((12.5 * 1024.0 * 1024.0) as u64));
        assert_eq!(stats.online_rounds, Some(30));
        assert_eq!(stats.offline_bytes, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(stats.offline_rounds, Some(7));
        assert_eq!(stats.data_sent_bytes, Some(512 * 1024));
        assert_eq!(stats.data_sent_rounds, Some(40));
        assert_eq!(stats.global_data_sent_bytes, Some(1024 * 1024 + 512 * 1024));
    }

    #[test]
    fn missing_counters_stay_unset() {
        let stats = parse_spdz_stats("nothing useful here");
        assert!(stats.total_ms.is_none());
        assert!(stats.online_bytes.is_none());
    }
}
