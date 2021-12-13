pub struct Matcher<'m> {
    rule: &'m [char],
    rule_len: usize,
    state: usize,
}

impl<'m> Matcher<'m> {
    pub fn new(rule: &'m [char]) -> Self {
        Self {
            rule,
            rule_len: rule.len(),
            state: 0,
        }
    }

    pub fn advance(&mut self, character: char) -> bool {
        if self.current_character() == character {
            self.state += 1;
            return true;
        }

        false
    }

    pub fn is_match(&self) -> bool {
        self.rule_len == self.state
    }

    fn current_character(&self) -> char {
        self.rule[self.state]
    }
}

#[cfg(test)]
mod tests {
    use super::Matcher;

    #[test]
    fn advance_only_advances_state_after_match() {
        let rule: Vec<char> = "a".chars().collect();
        let mut matcher = Matcher::new(&rule);

        assert_eq!(false, matcher.advance('b'));
        assert_eq!(true, matcher.advance('a'));
    }

    #[test]
    fn is_match_returns_true_when_rule_is_consumed() {
        let rule: Vec<char> = "abc".chars().collect();
        let mut matcher = Matcher::new(&rule);

        matcher.advance('a');
        matcher.advance('b');
        matcher.advance('c');
        assert_eq!(true, matcher.is_match());
    }

    #[test]
    fn is_match_returns_false_while_rule_is_not_fully_consumed() {
        let rule: Vec<char> = "abc".chars().collect();
        let mut matcher = Matcher::new(&rule);

        assert_eq!(false, matcher.is_match());
        matcher.advance('a');
        assert_eq!(false, matcher.is_match());
        matcher.advance('b');
        assert_eq!(false, matcher.is_match());
    }
}
