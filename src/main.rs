use chrono::NaiveDate;
use clap::{App, Arg, SubCommand};
use regex::Captures;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Lines};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;
use flate2::write::GzEncoder;
use flate2::Compression;

use cursive::traits::*;
use cursive::views::{
    Button, Dialog, DummyView, EditView, LinearLayout, SelectView, TextArea, TextContent, TextView,
};
use cursive::Cursive;
use std::thread;
use std::time::Duration;
use chrono::format::Numeric::Timestamp;
use std::cmp::{Ordering, min};
use flate2;
use std::sync::Mutex;

struct YBLogReaderContext {
    yb_log_line_re: Regex,
    tablet_id_re: Regex,
    peer_id_re: Regex,
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

    fn new() -> YBLogReaderContext {
        YBLogReaderContext {
            yb_log_line_re: Regex::new(
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
                    r".*",
                ),
            )
            .unwrap(),
            tablet_id_re: Regex::new(r"T ([0-9a-f]{32})\b").unwrap(),
            peer_id_re: Regex::new(r"P ([0-9a-f]{32})\b").unwrap(),
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
    microsecond: i32
}

#[derive(Debug, Clone)]
struct YBLogLine {
    log_level: char,
    timestamp_without_year: TimestampWithoutYear,
    thread_id: i64,
    file_name: String,
    line_number: i32,
    tablet_id: Option<Uuid>,
    // peer_id: Option<Uuid>
}

#[derive(Debug, Clone)]
struct LineInFile {
    index: u64,
    line: String,
    parsed: Option<YBLogLine>
}

struct LogFileData {
    lines: Vec<LineInFile>
}

struct LogFile {
    mutex: Mutex<LogFileData>
}

impl LogFile {
    fn new() -> LogFile {
        LogFile {
            mutex: Mutex::<LogFileData>::new(LogFileData{ lines: Vec::new() } )
        }
    }

    fn add_line(&mut self, line: LineInFile) {
        let mut data  = self.mutex.lock().unwrap();
        data.lines.push(line)
    }

    fn get_lines(&self, start_line: usize, num_lines: usize) -> Vec<LineInFile> {
        let data  = self.mutex.lock().unwrap();
        let n = data.lines.len();
        let last_index = min(n, start_line + num_lines);
        let mut result = Vec::<LineInFile>::new();
        result.reserve(last_index - start_line);
        for i in start_line..last_index - 1 {
            result.push(data.lines[i].clone());
        }
        result
    }
}

impl YBLogLine {
    fn parse_capture<T: FromStr>(capture: Option<regex::Match>) -> T {
        if let Ok(result) = capture.unwrap().as_str().parse::<T>() {
            result
        } else {
            panic!("Could not parse field {:?}", capture);
        }
    }

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
            // println!("matched line: {}", line);
            {
                Some(YBLogLine {
                    log_level: YBLogLine::parse_capture(
                        captures.get(YBLogReaderContext::CAPTURE_INDEX_LOG_LEVEL),
                    ),
                    timestamp_without_year: TimestampWithoutYear {
                        month: YBLogLine::parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_MONTH),
                        ),
                        day: YBLogLine::parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_DAY),
                        ),
                        hour: YBLogLine::parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_HOUR),
                        ),
                        minute: YBLogLine::parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_MINUTE),
                        ),
                        second: YBLogLine::parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_SECOND),
                        ),
                        microsecond: YBLogLine::parse_capture(
                            captures.get(YBLogReaderContext::CAPTURE_INDEX_MICROSECOND),
                        )
                    },
                    thread_id: YBLogLine::parse_capture(
                        captures.get(YBLogReaderContext::CAPTURE_INDEX_THREAD_ID),
                    ),
                    file_name: String::from(
                        captures
                            .get(YBLogReaderContext::CAPTURE_INDEX_FILE_NAME)
                            .unwrap()
                            .as_str(),
                    ),
                    line_number: YBLogLine::parse_capture(
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
    GzipReader(BufReader<flate2::read::GzDecoder<File>>)
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
    file_name: String,
    reader: FlexibleReader,
    context: &'a YBLogReaderContext,
}

#[derive(Debug)]
struct LogReadProgress {
    num_bytes: u64,
    num_lines: u64
}

impl<'a> YBLogReader<'a> {
    fn new(
        file_name: &str,
        context: &'a YBLogReaderContext,
    ) -> Result<YBLogReader<'a>, std::io::Error> {
        let opened_file = File::open(file_name)?;
        Ok(YBLogReader {
            file_name: String::from(file_name),
            reader: if file_name.ends_with(".gz") {
                FlexibleReader::GzipReader(BufReader::new(flate2::read::GzDecoder::new(opened_file)))
            } else {
                FlexibleReader::RawReader(BufReader::new(opened_file))
            },
            context
        })
    }

    pub fn load<CB>(&mut self, log_file: &mut LogFile, progress_callback: CB) where CB: Fn(LogReadProgress) {
        let mut num_bytes: u64 = 0;
        let mut num_lines: u64 = 0;
        let mut last_progress_report_bytes: u64 = 0;
        const REPORT_PROGRESS_EVERY_BYTES: u64 = 1024 * 1024;
        let mut prev_ts: Option<TimestampWithoutYear> = None;
        for maybe_line in &mut self.reader {
            let line = maybe_line.unwrap();
            num_bytes += line.bytes().len() as u64;
            num_lines += 1;
            if num_bytes >= last_progress_report_bytes + REPORT_PROGRESS_EVERY_BYTES {
                progress_callback(LogReadProgress{num_bytes, num_lines});
                last_progress_report_bytes += REPORT_PROGRESS_EVERY_BYTES;
            }
            let maybe_parsed_line = YBLogLine::parse(line.as_str(), self.context);
            if let Some(parsed_line) = maybe_parsed_line {
                // println!("Parsed line: {:?}", parsed_line);
                if let Some(prev_ts_value) = prev_ts.clone() {
                    if (prev_ts_value >= parsed_line.timestamp_without_year) {
                        panic!("Timestamps not ordered: was {:?}, now {:?}", prev_ts_value, parsed_line.timestamp_without_year);
                    }
                }
                log_file.add_line(LineInFile{
                    index: num_lines,
                    line: line,
                    parsed: Some(parsed_line)
                });
            } else {
                // println!("Could not parse line: {}", line);
                log_file.add_line(LineInFile{
                    index: num_lines,
                    line: line,
                    parsed: None
                });
            }
        }
        progress_callback(LogReadProgress{num_bytes, num_lines});
    }
}


//
// fn cursive_main() {
//     let mut siv = cursive::default();
//     siv.add_global_callback('q', |s| s.quit());
//     // let mut content = TextContent::new("content");
//     let view = TextView::new("asdf").fixed_size((200, 200)).with_name("my_text_view");
//
//     let cb_sink = siv.cb_sink().clone();
//
//     let handle = thread::spawn(move || {
//         for i in 1..10 {
//             cb_sink.send(Box::new(move |s| {
//                 // content.set_content(format!("hi number {} from the spawned thread!", i));
//                 s.call_on_name("my_text_view", |view: &mut TextView| {
//                     view.set_content(format!("Hello world! i={}", i));
//                 });
//             })).unwrap();
//             thread::sleep(Duration::from_millis(500));
//         }
//         // content.set_content("Loop finished");
//     });
//
//     siv.add_layer(view);
//
//     siv.run();
//     handle.join().unwrap();
// }

fn main() {
    let matches = App::new("Yugabyte log processor")
        .about("A tool for manipulating YugabyteDB logs")
        .version("1.0.0")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .takes_value(true),
        )
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

    let reader_context = YBLogReaderContext::new();


    let mut siv = cursive::default();
    // siv.add_layer(Dialog::around(
    //     TextView::new("Starting...").with_name("text"),
    // ));
    siv.add_global_callback('q', |s| s.quit());
    siv.add_layer(Dialog::around(
        TextView::new("Starting...").with_name("text").fixed_size((200, 200))
    ));

    let cb_sink = siv.cb_sink().clone();

    let duration = std::time::Duration::from_millis(1000);
    let mut log_files = Vec::<LogFile>::new();

    std::thread::spawn(move || {

        let mut readers: Vec<YBLogReader> = Vec::new();
        for input_file in input_files {
            readers.push(YBLogReader::new(input_file.as_str(), &reader_context).unwrap());
        }

        for mut reader in readers {
            log_files.push(LogFile::new());

            reader.load(
                &mut log_files.
                |progress| {
                    cb_sink
                            .send(Box::new(move |s| {
                                s.call_on_name("text", |v: &mut TextView| {
                                    v.set_content(format!("{:?}", progress));
                                });
                            }))
                            .unwrap();
                });
        }


        // for num in 0..25 {
        //     std::thread::sleep(duration);
        //     cb_sink
        //         .send(Box::new(move |s| {
        //             s.call_on_name("text", |v: &mut TextView| {
        //                 v.set_content(num.to_string())
        //             });
        //         }))
        //         .unwrap();
        // }
        // cb_sink.send(Box::new(|s| s.quit())).unwrap();
    });

    siv.run();
    // for mut reader in readers {
    //     reader.load();
    // }

    //
    // // Vary the output based on how many times the user used the "verbose" flag
    // // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'
    // match matches.occurrences_of("v") {
    //     0 => println!("No verbose info"),
    //     1 => println!("Some verbose info"),
    //     2 => println!("Tons of verbose info"),
    //     3 | _ => println!("Don't be crazy"),
    // }
    //
    // // You can handle information about subcommands by requesting their matches by name
    // // (as below), requesting just the name used, or both at the same time
    // if let Some(matches) = matches.subcommand_matches("test") {
    //     if matches.is_present("debug") {
    //         println!("Printing debug info...");
    //     } else {
    //         println!("Printing normally...");
    //     }
    // }
    // println!("Hello, world!");
}
