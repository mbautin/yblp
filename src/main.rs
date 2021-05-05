use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

use clap::{App, Arg};
use flate2;
use regex::Regex;
use uuid::Uuid;
use chrono::{NaiveDateTime, NaiveDate};

struct YBLogReaderContext {
    yb_log_line_re: Regex,
    tablet_id_re: Regex,
    log_file_created_at_re: Regex,
    running_on_machine_re: Regex,
    application_fingerprint_re: Regex,
    application_fingerprint_details_re: Regex,
}

fn parse_regex(s: &str) -> Regex {
    Regex::new(s).unwrap()
}

impl YBLogReaderContext {
    const CAPTURE_INDEX_LOG_LEVEL: usize = 1;
    const CAPTURE_INDEX_MONTH: usize = 2;
    const CAPTURE_INDEX_DAY: usize = 3;
    const CAPTURE_INDEX_HOUR: usize = 4;
    const CAPTURE_INDEX_MINUTE: usize = 5;
    const CAPTURE_INDEX_SECOND: usize = 6;
    const CAPTURE_INDEX_MICROSECOND: usize = 7;
    const CAPTURE_INDEX_THREAD_ID: usize = 8;
    const CAPTURE_INDEX_FILE_NAME: usize = 9;
    const CAPTURE_INDEX_LINE_NUMBER: usize = 10;
    const CAPTURE_INDEX_MESSAGE: usize = 11;

    fn new() -> YBLogReaderContext {
        YBLogReaderContext {
            yb_log_line_re: parse_regex(
                // Example: I0408 10:34:43.355123
                concat!(
                r"^",
                r"([IWEF])", // Capture group 1: log level
                r"(\d{2})",  // Capture group 2: month
                r"(\d{2})",  // Capture group 3: day
                r"\s+",
                r"(\d{2})", // Capture group 4: hour
                r":",
                r"(\d{2})", // Capture group 5: minute
                r":",
                r"(\d{2})", // Capture group 6: second
                r"[.]",
                r"([0-9]{6})", // Capture group 7: microsecond
                r"\s+",
                r"([0-9]+)", // Capture group 8: thread id
                r"\s+",
                r"([0-9a-zA-Z_-]+[.][0-9a-zA-Z_-]+)", // // Capture group 9: file name
                r":",
                r"(\d+)", // Capture group 10: line number
                r"\] ",
                r"(.*)",  // Capture group 11: message
                ),
            ),
            tablet_id_re: parse_regex(r"T ([0-9a-f]{32})\b"),

            // Log file "preamble" lines.
            // ~~~~~~~~~~~~~~~~~~~~~~~~~
            //
            // Example:
            //
            // Log file created at: 2021/04/08 14:44:23
            // Running on machine: yb-encust-stage-centralus-az1-vmLinux-1
            // Application fingerprint: version 2.4.1.1 build 4 revision 1b7bb2fc3b910912ef758ffca83b076124051c10 build_type RELEASE built at 30 Mar 2021 16:14:23 UTC
            // Running duration (h:mm:ss): 186:27:03
            // Log line format: [IWEF]mmdd hh:mm:ss.uuuuuu threadid file:line] msg
            //
            log_file_created_at_re: parse_regex(
                r"^Log file created at: (\d+{4})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$"
            ),
            running_on_machine_re: parse_regex(r"^Running on machine: (.*)$"),
            application_fingerprint_re: parse_regex(r"^Application fingerprint: (.*)$"),
            application_fingerprint_details_re: parse_regex(
                concat!(
                    r"^",
                    r"version ([0-9.]+) ",
                    r"build (\d+) ",
                    r"revision ([a-f0-9]+) ",
                    r"build_type ([a-zA-Z]+) ",
                    r"built at (.*)"
                )
            )
            // version 2.4.0.0 build 60 revision 4a56a6497b3bbc559f995d30f20f3859debce629 build_type
            // RELEASE built at 21 Jan 2021 02:12:34 UTC
        }
    }
}

#[derive(Debug, PartialOrd, PartialEq, Clone)]
struct TimestampWithoutYear {
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    microsecond: i32,
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

fn parse_capture<T: FromStr>(capture: Option<regex::Match>) -> T {
    if let Ok(result) = capture.unwrap().as_str().parse::<T>() {
        result
    } else {
        panic!("Could not parse field {:?}", capture);
    }
}

impl YBLogLine {
    fn parse_tablet_id(line: &str, context: &YBLogReaderContext) -> Option<Uuid> {
        match context.tablet_id_re.captures(line) {
            Some(captures) => match Uuid::from_str(captures.get(1).unwrap().as_str()) {
                Ok(parsed_uuid) => Some(parsed_uuid),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn parse(line: &str, context: &YBLogReaderContext) -> Option<YBLogLine> {
        match context.yb_log_line_re.captures(line) {
            Some(captures) =>
                {
                    Some(YBLogLine {
                        log_level: parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_LOG_LEVEL),
                        ),
                        timestamp_without_year: TimestampWithoutYear {
                            month: parse_capture(
                                captures.get(YBLogReaderContext::CAPTURE_INDEX_MONTH),
                            ),
                            day: parse_capture(
                                captures.get(YBLogReaderContext::CAPTURE_INDEX_DAY),
                            ),
                            hour: parse_capture(
                                captures.get(YBLogReaderContext::CAPTURE_INDEX_HOUR),
                            ),
                            minute: parse_capture(
                                captures.get(YBLogReaderContext::CAPTURE_INDEX_MINUTE),
                            ),
                            second: parse_capture(
                                captures.get(YBLogReaderContext::CAPTURE_INDEX_SECOND),
                            ),
                            microsecond: parse_capture(
                                captures.get(YBLogReaderContext::CAPTURE_INDEX_MICROSECOND),
                            ),
                        },
                        thread_id: parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_THREAD_ID),
                        ),
                        file_name: String::from(
                            captures
                                .get(YBLogReaderContext::CAPTURE_INDEX_FILE_NAME)
                                .unwrap()
                                .as_str(),
                        ),
                        line_number: parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_LINE_NUMBER),
                        ),
                        tablet_id: YBLogLine::parse_tablet_id(line, context),
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

struct YBLogReader<'a> {
    reader: FlexibleReader,
    context: &'a YBLogReaderContext,
    preamble: YBLogFilePreamble
}

impl<'a> YBLogReader<'a> {
    fn new(
        file_name: &str,
        context: &'a YBLogReaderContext,
    ) -> Result<YBLogReader<'a>, std::io::Error> {
        let opened_file = File::open(file_name)?;
        Ok(YBLogReader {
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
        for maybe_line in &mut self.reader {
            let line = maybe_line.unwrap();
            let maybe_parsed_line = YBLogLine::parse(line.as_str(), self.context);
            if let Some(_parsed_line) = maybe_parsed_line {
                // Parsing success
            } else {
                // Parsing failure
            }

            if line_index <= PREAMBLE_NUM_LINES {
                match self.context.log_file_created_at_re.captures(line.as_str()) {
                    Some(captures) =>
                        self.preamble.created_at = Some(
                            NaiveDate::from_ymd(
                                parse_capture(captures.get(1)),
                                parse_capture(captures.get(2)),
                                parse_capture(captures.get(3))
                            ).and_hms(
                                parse_capture(captures.get(4)),
                                parse_capture(captures.get(5)),
                                parse_capture(captures.get(6))
                            )
                        ),
                    _ => ()
                }
            }
            line_index += 1;
        }
    }
}

fn main() {
    let matches = App::new("Yugabyte log processor")
        .about("A tool for manipulating YugabyteDB logs")
        .version("1.0.0")
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required(true)
                .multiple(true),
        )
        .get_matches();

    let mut input_files: Vec<String> = Vec::new();
    match matches.values_of("INPUT") {
        Some(values) => {
            for input_file in values {
                println!("input file: {}", input_file);
                if !Path::new(input_file).exists() {
                    panic!("File {} does not exist", input_file);
                }
                input_files.push(String::from(input_file));
            }
        }
        _ => panic!("No input files specified"),
    }

    let mut readers = Vec::<YBLogReader>::new();
    let reader_context = YBLogReaderContext::new();
    for input_file in input_files {
        readers.push(YBLogReader::new(input_file.as_str(), &reader_context).unwrap());
    }

    for mut reader in readers {
        reader.load();
    }
}
