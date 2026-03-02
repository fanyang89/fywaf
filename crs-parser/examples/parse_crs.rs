use std::path::Path;

fn main() {
    for conf in &[
        "vendor/coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "vendor/coreruleset/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    ] {
        let path = Path::new(conf);
        match crs_parser::parse_conf(path) {
            Ok(rules) => {
                let blocking = rules.iter().filter(|r| r.action == crs_parser::Action::Block).count();
                let pl1 = rules.iter().filter(|r| r.paranoia_level == 1).count();
                let chained = rules.iter().filter(|r| !r.chained.is_empty()).count();
                println!("{}", conf.split('/').last().unwrap());
                println!("  total rules : {}", rules.len());
                println!("  blocking    : {}", blocking);
                println!("  PL1         : {}", pl1);
                println!("  chained     : {}", chained);
            }
            Err(e) => eprintln!("Error parsing {conf}: {e}"),
        }
    }
}
