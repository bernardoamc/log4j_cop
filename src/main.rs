#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref RULES: String = std::fs::read_to_string("data/rules.txt").unwrap();
}

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::abort;

mod ruleset;
use ruleset::Ruleset;

fn main() {
    let filename = env::args().nth(1);

    if filename.is_none() {
        println!("Filename not found.");
        println!("Usage: log4j_cop <LOG_FILE>");
        println!("Example: log4j_cop log.txt");
        abort();
    }

    let file = File::open(&filename.unwrap()).expect("Unable to open file.");
    let reader = BufReader::new(file);
    let ruleset = Ruleset::new(&mut RULES.trim().lines());

    for line in reader.lines() {
        if line.is_err() {
            continue;
        }

        let line = line.unwrap();

        if ruleset.match_rules(&line) {
            println!("{}", line);
        }
    }
}
