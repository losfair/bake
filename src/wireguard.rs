#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgSection {
    pub name: String,
    pub items: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedWireguardConf {
    pub sections: Vec<WgSection>,
}

pub fn parse_wireguard_conf(conf: &str) -> ParsedWireguardConf {
    fn strip_comment(mut s: &str) -> &str {
        let bytes = s.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'#' || b == b';' {
                s = &s[..i];
                break;
            }
        }
        s.trim()
    }
    fn split_values(v: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut buf = String::new();
        let mut in_squote = false;
        let mut in_dquote = false;
        let flush = |buf: &mut String, out: &mut Vec<String>| {
            let mut tok = buf.trim().to_string();
            if tok.len() >= 2 {
                let b = tok.as_bytes();
                let first = b[0];
                let last = *b.last().unwrap();
                if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
                    tok = tok[1..tok.len() - 1].to_string();
                }
            }
            if !tok.is_empty() {
                out.push(tok);
            }
            buf.clear();
        };
        for ch in v.chars() {
            match ch {
                '\'' if !in_dquote => {
                    in_squote = !in_squote;
                    buf.push(ch);
                }
                '"' if !in_squote => {
                    in_dquote = !in_dquote;
                    buf.push(ch);
                }
                ',' | ' ' | '\t' | '\n' | '\r' if !in_squote && !in_dquote => {
                    if !buf.trim().is_empty() {
                        flush(&mut buf, &mut out);
                    }
                }
                _ => buf.push(ch),
            }
        }
        if !buf.trim().is_empty() {
            flush(&mut buf, &mut out);
        }
        out
    }

    let mut sections: Vec<WgSection> = Vec::new();
    let mut current: Option<WgSection> = None;

    for raw in conf.lines() {
        let line = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(sec) = current.take() {
                sections.push(sec);
            }
            let mut name = &line[1..line.len() - 1];
            name = name.trim();
            current = Some(WgSection {
                name: name.to_string(),
                items: Vec::new(),
            });
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        let vals = split_values(v.trim());
        if current.is_none() {
            // Ignore items outside any section
            continue;
        }
        current.as_mut().unwrap().items.push((key, vals));
    }

    if let Some(sec) = current.take() {
        sections.push(sec);
    }

    ParsedWireguardConf { sections }
}

pub fn serialize_without_keys(conf: &ParsedWireguardConf, drop_keys_ci: &[&str]) -> String {
    let mut out = String::new();
    for sec in &conf.sections {
        out.push('[');
        out.push_str(&sec.name);
        out.push_str("]\n");
        for (k, vals) in &sec.items {
            if drop_keys_ci.iter().any(|d| k.eq_ignore_ascii_case(d)) {
                continue;
            }
            out.push_str(k);
            out.push_str(" = ");
            out.push_str(&vals.join(", "));
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_interface_and_peer() {
        let conf = r#"
            [Interface]
            Address = 10.0.0.2/24, 10.0.1.2/24 # inline comment
            ListenPort = 51820

            [Peer]
            AllowedIPs = 10.0.0.0/24,10.0.2.0/24 ; another comment
            PublicKey = abc
        "#;
        let p = parse_wireguard_conf(conf);
        assert_eq!(p.sections.len(), 2);
        assert_eq!(p.sections[0].name.to_ascii_lowercase(), "interface");
        let iface_addr = p.sections[0]
            .items
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("address"))
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(iface_addr, vec!["10.0.0.2/24", "10.0.1.2/24"]);
        assert_eq!(p.sections[1].name.to_ascii_lowercase(), "peer");
        let peer_allowed = p.sections[1]
            .items
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("allowedips"))
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(peer_allowed, vec!["10.0.0.0/24", "10.0.2.0/24"]);
    }

    #[test]
    fn splits_and_preserves_tokens() {
        let conf = r#"
            [Interface]
            Address=10.0.0.2/24  10.0.0.2/24,10.0.1.2/24
            [Peer]
            AllowedIPs = 10.0.0.0/24 10.0.0.0/24 , 10.0.2.0/24
        "#;
        let p = parse_wireguard_conf(conf);
        let iface = p
            .sections
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("interface"))
            .unwrap();
        let addr = iface
            .items
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("address"))
            .unwrap()
            .1
            .clone();
        assert_eq!(addr, vec!["10.0.0.2/24", "10.0.0.2/24", "10.0.1.2/24"]);
        let peer = p
            .sections
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("peer"))
            .unwrap();
        let allowed = peer
            .items
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("allowedips"))
            .unwrap()
            .1
            .clone();
        assert_eq!(allowed, vec!["10.0.0.0/24", "10.0.0.0/24", "10.0.2.0/24"]);
    }

    #[test]
    fn quotes_and_ipv6() {
        let conf = r#"
            [Interface]
            Address = "2001:db8::1/64", '10.2.3.4/32'
            [Peer]
            AllowedIPs = "fd00::/8", 0.0.0.0/0
        "#;
        let p = parse_wireguard_conf(conf);
        let iface = p
            .sections
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("interface"))
            .unwrap();
        let addr = iface
            .items
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("address"))
            .unwrap()
            .1
            .clone();
        assert_eq!(addr, vec!["2001:db8::1/64", "10.2.3.4/32"]);
        let peer = p
            .sections
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("peer"))
            .unwrap();
        let allowed = peer
            .items
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("allowedips"))
            .unwrap()
            .1
            .clone();
        assert_eq!(allowed, vec!["fd00::/8", "0.0.0.0/0"]);
    }

    #[test]
    fn multiple_peers_collect_all_allowedips() {
        let conf = r#"
            [Peer]
            AllowedIPs = 10.0.0.0/24
            [Peer]
            AllowedIPs = 10.0.1.0/24,10.0.2.0/24
        "#;
        let p = parse_wireguard_conf(conf);
        let peers: Vec<_> = p
            .sections
            .iter()
            .filter(|s| s.name.eq_ignore_ascii_case("peer"))
            .collect();
        assert_eq!(peers.len(), 2);
        let vals: Vec<String> = peers
            .iter()
            .flat_map(|sec| sec.items.iter())
            .filter(|(k, _)| k.eq_ignore_ascii_case("allowedips"))
            .flat_map(|(_, v)| v.clone())
            .collect();
        assert_eq!(vals, vec!["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]);
    }

    #[test]
    fn serializer_drops_address_and_dns() {
        let conf = r#"
            [Interface]
            Address = 10.0.0.2/24, 10.0.1.2/24
            DNS = 1.1.1.1
            PrivateKey = abc

            [Peer]
            PublicKey = def
            AllowedIPs = 10.0.0.0/24
        "#;
        let p = parse_wireguard_conf(conf);
        let s = serialize_without_keys(&p, &["address", "dns"]);
        let expected = "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 10.0.0.0/24\n\n";
        assert_eq!(s, expected);
    }
}
