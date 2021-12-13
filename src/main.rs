use std::collections::VecDeque;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref FILE_CONTENTS: String = std::fs::read_to_string("data/log.txt").unwrap();
}

fn is_log4j_payload(line: &str) -> bool {
    let mut matcher: VecDeque<char> = "${jndi:ldap://".chars().collect();

    for c in line.chars() {
        if matcher.is_empty() {
            return true;
        }

        if c == matcher[0] {
            matcher.pop_front();
        }
    }

    false
}

fn main() {
    let payloads: Vec<&str> = FILE_CONTENTS
        .trim()
        .lines()
        .filter(|line| is_log4j_payload(line.trim()))
        .collect();

    payloads.iter().for_each(|payload| println!("{}", payload));
}
