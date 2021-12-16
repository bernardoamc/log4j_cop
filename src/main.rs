#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref RULES: String = std::fs::read_to_string("data/rules.txt").unwrap();
}

extern crate clap;
use clap::{App, Arg};

use std::fs::File;
use std::io::{BufRead, BufReader};
use urlencoding::decode;

mod ruleset;
use ruleset::Ruleset;

mod extractor;
use extractor::Extractor;

fn main() {
    let matches = App::new("log4j_cop")
        .version("0.2")
        .about("Search logs for log4j payloads and optionally extract URLs.")
        .author("Bernardo de Araujo")
        .arg(
            Arg::with_name("LOG_FILE")
                .required(true)
                .index(1)
                .help("Specifies the log file to be used"),
        )
        .arg(
            Arg::with_name("urls_output_path")
                .short("u")
                .long("urls_output_path")
                .takes_value(true)
                .required(false)
                .help("When specified URLs will be extracted and persisted in CSV format"),
        )
        .get_matches();

    let filename = matches.value_of("LOG_FILE").unwrap();
    let file = File::open(&filename).expect("Unable to open log file.");
    let reader = BufReader::new(file);
    let ruleset = Ruleset::new(&mut RULES.trim().lines());
    let urls_output_path = matches.value_of("urls_output_path");
    let mut extractor = Extractor::new(urls_output_path.is_some());

    for line in reader.lines() {
        if line.is_err() {
            continue;
        }

        let line = line.unwrap();
        let line = decode(&line).map_or(line.to_owned(), |decoded| decoded.to_string());

        if ruleset.match_rules(&line) {
            extractor.extract_urls(&line);
            println!("{}", line);
        }
    }

    if let Err(err) = extractor.extract_to_csv(urls_output_path) {
        println!("There was an issue when writing to the URL log.");
        println!("{}", err);
    }
}
