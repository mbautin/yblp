#[macro_use]
extern crate clap;

use yblp::RegexHolder;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::fs::metadata;

use clap::{App, Arg, ArgMatches};
use flate2;
use regex::Regex;
use uuid::Uuid;
use chrono::{NaiveDateTime, NaiveDate};
use walkdir::WalkDir;
use std::fs;
use std::ffi::OsString;
use threadpool::ThreadPool;
use chrono::Datelike;

use std::str::FromStr;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::cell::RefCell;

extern crate yblp;

use self::yblp::parse_capture;
use self::yblp::parse_filter_timestamp;

struct YBLogReaderContext {
    regexes: RegexHolder,
    arg_info: ArgInfo,
}

#[derive(Debug, PartialOrd, PartialEq, Clone)]
struct TimestampWithoutYear {
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    microsecond: u32,
}

impl TimestampWithoutYear {
    fn with_year(&self, year: i32) -> NaiveDateTime {
        NaiveDate::from_ymd(year, u32::from(self.month), u32::from(self.day)).and_hms_micro(
            u32::from(self.hour), u32::from(self.minute), u32::from(self.second),
            u32::from(self.microsecond))
    }
}

#[derive(Debug, Clone)]
struct YBLogLine {
    log_level: char,
    timestamp_without_year: TimestampWithoutYear,
    thread_id: i64,
    file_name: String,
    line_number: i32,
    tablet_id: Option<Uuid>,
}

struct LogChunk {
    sorting_timestamp: TimestampWithoutYear,
}

#[derive(Default)]
struct YBLogFilePreamble {
    created_at: Option<NaiveDateTime>,
    running_on_machine: Option<String>,
    application_fingerprint: Option<String>,
    version: Option<String>,
    build_number: Option<u64>,
    revision: Option<String>,
    build_type: Option<String>,
    built_at: Option<String>
}

impl YBLogLine {
    fn parse_tablet_id(line: &str, context: &YBLogReaderContext) -> Option<Uuid> {
        match context.regexes.tablet_id_re.captures(line) {
            Some(captures) => match Uuid::from_str(captures.get(1).unwrap().as_str()) {
                Ok(parsed_uuid) => Some(parsed_uuid),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn parse(line: &str, context: Arc<YBLogReaderContext>) -> Option<YBLogLine> {
        match context.regexes.yb_log_line_re.captures(line) {
            Some(captures) =>
                {
                    Some(YBLogLine {
                        log_level: parse_capture(
                            captures.get(RegexHolder::CAPTURE_INDEX_LOG_LEVEL),
                        ),
                        timestamp_without_year: TimestampWithoutYear {
                            month: parse_capture(
                                captures.get(RegexHolder::CAPTURE_INDEX_MONTH),
                            ),
                            day: parse_capture(
                                captures.get(RegexHolder::CAPTURE_INDEX_DAY),
                            ),
                            hour: parse_capture(
                                captures.get(RegexHolder::CAPTURE_INDEX_HOUR),
                            ),
                            minute: parse_capture(
                                captures.get(RegexHolder::CAPTURE_INDEX_MINUTE),
                            ),
                            second: parse_capture(
                                captures.get(RegexHolder::CAPTURE_INDEX_SECOND),
                            ),
                            microsecond: parse_capture(
                                captures.get(RegexHolder::CAPTURE_INDEX_MICROSECOND),
                            ),
                        },
                        thread_id: parse_capture(
                            captures.get(RegexHolder::CAPTURE_INDEX_THREAD_ID),
                        ),
                        file_name: String::from(
                            captures
                                .get(RegexHolder::CAPTURE_INDEX_FILE_NAME)
                                .unwrap()
                                .as_str(),
                        ),
                        line_number: parse_capture(
                            captures.get(RegexHolder::CAPTURE_INDEX_LINE_NUMBER),
                        ),
                        tablet_id: YBLogLine::parse_tablet_id(line, context.as_ref()),
                    })
                }
            _ => None,
        }
    }
}

enum FlexibleReader {
    RawReader(BufReader<File>),
    GzipReader(BufReader<flate2::read::GzDecoder<File>>),
}

impl std::iter::Iterator for FlexibleReader {
    type Item = std::io::Result<String>;

    fn next(&mut self) -> Option<std::io::Result<String>> {
        let mut buf = String::new();
        match {
            match self {
                FlexibleReader::RawReader(buf_reader) => buf_reader.read_line(&mut buf),
                FlexibleReader::GzipReader(buf_reader) => buf_reader.read_line(&mut buf),
            }
        } {
            Ok(0) => None,
            Ok(_n) => {
                if buf.ends_with('\n') {
                    buf.pop();
                    if buf.ends_with('\r') {
                        buf.pop();
                    }
                }
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

struct YBLogReader {
    file_name: String,
    reader: FlexibleReader,
    context: Arc<YBLogReaderContext>,
    preamble: YBLogFilePreamble
}

impl YBLogReader {
    fn new(
        file_name: &str,
        context: Arc<YBLogReaderContext>,
    ) -> Result<YBLogReader, std::io::Error> {
        let opened_file = File::open(file_name)?;
        Ok(YBLogReader {
            file_name: String::from(file_name),
            reader: if file_name.ends_with(".gz") {
                FlexibleReader::GzipReader(BufReader::new(flate2::read::GzDecoder::new(opened_file)))
            } else {
                FlexibleReader::RawReader(BufReader::new(opened_file))
            },
            context,
            preamble: Default::default()
        })
    }

    pub fn load(&mut self) {
        let mut line_index: usize = 1;
        const PREAMBLE_NUM_LINES: usize = 10;
        let mut successfully_parsed_lines: u64 = 0;
        let mut unsuccessfully_parsed_lines: u64 = 0;

        let mut year_from_preamble_opt: Option<i32> = None;
        for maybe_line in &mut self.reader {
            let line = maybe_line.unwrap();

            if line_index <= PREAMBLE_NUM_LINES {
                if let Some(captures) = self.context.regexes.log_file_created_at_re.captures(
                        line.as_str()) {
                    let created_at = NaiveDate::from_ymd(
                        parse_capture(captures.get(1)),
                        parse_capture(captures.get(2)),
                        parse_capture(captures.get(3))
                    ).and_hms(
                        parse_capture(captures.get(4)),
                        parse_capture(captures.get(5)),
                        parse_capture(captures.get(6))
                    );
                    self.preamble.created_at = Some(created_at);

                    if let Some(ts_upper_limit) = self.context.arg_info.highest_timestamp {
                        if created_at > ts_upper_limit {
                            println!(
                                "Skipping {} because it was created at {} but the user specified \
                                 {} as the highest timestamp of interest",
                                self.file_name, created_at, ts_upper_limit
                            );
                            break;
                        }
                    }
                }
                if let Some(captures) = self.context.regexes.running_on_machine_re.captures(
                        line.as_str()) {
                    self.preamble.running_on_machine = Some(
                        String::from(captures.get(1).unwrap().as_str()));
                }
            }

            let maybe_parsed_line = YBLogLine::parse(line.as_str(), self.context.clone());
            if let Some(parsed_line) = maybe_parsed_line {
                let year = self.preamble.created_at.map(|d| d.year()).or(
                    self.context.arg_info.default_year).unwrap();
                let ts_with_year = parsed_line.timestamp_without_year.with_year(year);
                successfully_parsed_lines += 1;
                // Parsing success
            } else {
                // Parsing failure
                unsuccessfully_parsed_lines += 1;
            }

            line_index += 1;
        }
        println!(
            "In file {}: successfully parsed lines: {}, unsuccessfully parsed lines: {}",
            self.file_name,
            successfully_parsed_lines,
            unsuccessfully_parsed_lines);
    }
}

fn timestamp_validator(v: String) -> Result<(), String> {
    match parse_filter_timestamp(v.as_str()) {
        Ok(_) => Ok(()),
        Err(s) => Err(s)
    }
}

fn get_timestamp_arg<'a>(values_opt: Option<clap::Values<'a>>) -> Option<NaiveDateTime> {
    match values_opt {
        Some(mut values) => match values.next() {
            Some(value_str) => {
                Some(parse_filter_timestamp(value_str).unwrap())
            },
            None => None
        },
        None => None
    }
}

fn capitalize_string(input: &str) -> String {
    // From https://stackoverflow.com/questions/38406793/why-is-capitalizing-the-first-letter-of-a-string-so-convoluted-in-rust
    let mut s = input.to_string();
    return s.remove(0).to_uppercase().to_string() + &s;
}

struct TimestampArgHelper {
    arg_name: String,
    long_option_name: String,
    help_text: String
}

impl TimestampArgHelper {
    fn new(lowest_or_highest: &str) -> TimestampArgHelper {
        TimestampArgHelper {
            arg_name: String::from(lowest_or_highest.to_uppercase()) + "_TIMESTAMP",
            long_option_name: String::from(lowest_or_highest.to_lowercase()) + "-timestamp",
            help_text: std::format!(
                    "{} timestamp (inclusive) of the log range to look at (YYYY-MM-DD HH:MM:SS)",
                    capitalize_string(lowest_or_highest))
        }
    }

    fn create_arg<'a>(&'a self) -> Arg<'a, 'a> {
        Arg::with_name(self.arg_name.as_str())
            .long(self.long_option_name.as_str())
            .takes_value(true)
            .help(self.help_text.as_str())
            .validator(timestamp_validator)
    }
}

// ------------------------------------------------------------------------------------------------
// ArgInfo
// ------------------------------------------------------------------------------------------------

struct ArgInfo {
    pub lowest_timestamp: Option<NaiveDateTime>,
    highest_timestamp: Option<NaiveDateTime>,
    default_year: Option<i32>,
    input_files: Vec<String>,
}

// ------------------------------------------------------------------------------------------------
// ArgParsingHelper
// ------------------------------------------------------------------------------------------------

struct ArgParsingHelper {
    lowest_helper: TimestampArgHelper,
    highest_helper: TimestampArgHelper,
}

impl ArgParsingHelper {
    fn new() -> ArgParsingHelper {
        ArgParsingHelper {
            lowest_helper: TimestampArgHelper::new("lowest"),
            highest_helper: TimestampArgHelper::new("highest")
        }
    }

    pub fn parse_args<'a>(&'a self) -> ArgInfo {
        let matches = App::new("Yugabyte log processor")
            .about("A tool for manipulating YugabyteDB logs")
            .version("1.0.0")
            .arg(
                Arg::with_name("INPUT_FILES")
                    .help("Sets the input file to use")
                    .required(true)
                    .multiple(true),
            )
            .arg(self.lowest_helper.create_arg())
            .arg(self.highest_helper.create_arg())
            .arg(Arg::with_name("DEFAULT_YEAR")
                    .long("--default-year")
                    .help("Use this year when year is unknown in a glog timestamp")
                    .required(true)
                    .takes_value(true))
            .get_matches();

        let lowest_timestamp = get_timestamp_arg(matches.values_of("LOWEST_TIMESTAMP"));
        let highest_timestamp = get_timestamp_arg(matches.values_of("HIGHEST_TIMESTAMP"));

        // See https://github.com/clap-rs/clap/pull/74/files
        let default_year: Option<i32> = match value_t!(matches.value_of("DEFAULT_YEAR"), i32) {
            Ok(year) => Some(year),
            Err(err) => { panic!("Error parsing DEFAULT_YEAR: {:?}", err) }
        };
        let input_files: Vec<String> = match matches.values_of("INPUT_FILES") {
            Some(values) => {
                values.map(|s| String::from(s)).collect()
            },
            _ => panic!("No input files specified"),
        };
        ArgInfo {
            lowest_timestamp,
            highest_timestamp,
            default_year,
            input_files,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Main program
// ------------------------------------------------------------------------------------------------
fn main() {
    let parsing_helper = ArgParsingHelper::new();
    let arg_info = parsing_helper.parse_args();

    let mut input_files: BTreeSet<OsString> = BTreeSet::new();

    for input_file_str in arg_info.input_files.iter() {
        let input_file = input_file_str.as_str();
        let file_metadata = metadata(input_file).unwrap();
        if file_metadata.is_file() {
            println!("input file: {}", input_file);
            if !Path::new(input_file).exists() {
                panic!("File {} does not exist", input_file);
            }
            input_files.insert(fs::canonicalize(input_file).unwrap().into_os_string());
        } else if file_metadata.is_dir() {
            for entry in WalkDir::new(input_file) {
                let path_unwrapped = entry.unwrap();
                let path_os_str = path_unwrapped.path();
                if metadata(path_os_str).unwrap().is_file() {
                    input_files.insert(fs::canonicalize(path_os_str).unwrap().into_os_string());
                }
            }
        } else {
            panic!("Not a file or directory: {}", input_file);
        }
    }

    let mut readers = Vec::<YBLogReader>::new();
    let mut reader_context = Arc::new(YBLogReaderContext {
        regexes: RegexHolder::new(),
        arg_info,
    });

    let cpus = num_cpus::get();
    let pool = ThreadPool::new(cpus);

    println!("Processing {} files", input_files.len());
    for input_file in input_files {
        let input_file_str = input_file.to_str().unwrap();
        readers.push(YBLogReader::new(input_file_str, reader_context.clone()).unwrap());
    }

    for mut reader in readers {
        pool.execute(move || {
            reader.load();
        })
    }
    pool.join();
}
