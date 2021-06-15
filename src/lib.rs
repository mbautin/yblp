use regex::Regex;

fn parse_regex(s: &str) -> Regex {
    Regex::new(s).unwrap()
}

pub struct YBLogReaderContext {
    pub yb_log_line_re: Regex,
    pub tablet_id_re: Regex,
    pub log_file_created_at_re: Regex,
    pub running_on_machine_re: Regex,
    pub application_fingerprint_re: Regex,
    pub application_fingerprint_details_re: Regex,
}

impl YBLogReaderContext {
    pub const CAPTURE_INDEX_LOG_LEVEL: usize = 1;
    pub const CAPTURE_INDEX_MONTH: usize = 2;
    pub const CAPTURE_INDEX_DAY: usize = 3;
    pub const CAPTURE_INDEX_HOUR: usize = 4;
    pub const CAPTURE_INDEX_MINUTE: usize = 5;
    pub const CAPTURE_INDEX_SECOND: usize = 6;
    pub const CAPTURE_INDEX_MICROSECOND: usize = 7;
    pub const CAPTURE_INDEX_THREAD_ID: usize = 8;
    pub const CAPTURE_INDEX_FILE_NAME: usize = 9;
    pub const CAPTURE_INDEX_LINE_NUMBER: usize = 10;
    pub const CAPTURE_INDEX_MESSAGE: usize = 11;

    pub fn new() -> YBLogReaderContext {
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
