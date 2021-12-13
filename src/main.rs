#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref LOG: String = std::fs::read_to_string("data/log.txt").unwrap();
    static ref RULES: String = std::fs::read_to_string("data/rules.txt").unwrap();
}

struct Matcher<'m> {
    rule: &'m Vec<char>,
    rule_len: usize,
    state: usize,
}

impl<'m> Matcher<'m> {
    fn new(rule: &'m Vec<char>) -> Self {
        Self {
            rule: rule,
            rule_len: rule.len(),
            state: 0,
        }
    }

    fn advance(&mut self, character: char) {
        if self.current_character() == character {
            self.state += 1;
        }
    }

    fn current_character(&self) -> char {
        self.rule[self.state]
    }

    fn is_match(&self) -> bool {
        self.rule_len == self.state
    }
}

fn is_log4j_payload(line: &str, rules: &Vec<Vec<char>>) -> bool {
    let mut matchers: Vec<Matcher> = rules.iter().map(|rule| Matcher::new(rule)).collect();

    for c in line.chars() {
        let is_match = matchers.iter_mut().any(|matcher| {
            matcher.advance(c);
            matcher.is_match()
        });

        if is_match {
            return true;
        }
    }

    false
}

fn main() {
    let rules: Vec<Vec<char>> = RULES
        .trim()
        .lines()
        .map(|matcher| matcher.trim().chars().collect())
        .collect();

    let payloads: Vec<&str> = LOG
        .trim()
        .lines()
        .filter(|line| is_log4j_payload(line.trim(), &rules))
        .collect();

    payloads.iter().for_each(|payload| println!("{}", payload));
}
