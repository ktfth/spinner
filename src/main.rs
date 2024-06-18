use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::thread;
use reqwest;
use serde_json::Value;
use chrono::{DateTime, Utc};
use tokio::runtime::Runtime;

#[derive(Clone, Debug)]
struct Wurl {
    date: String,
    url: String,
}

async fn get_wayback_urls(domain: &str, no_subs: bool) -> Result<Vec<Wurl>, reqwest::Error> {
    let subs_wildcard = if no_subs { "" } else { "*." };
    let url = format!(
        "http://web.archive.org/cdx/search/cdx?url={}{}/*&output=json&collapse=urlkey",
        subs_wildcard, domain
    );

    let response = reqwest::get(&url).await?;
    let response_text = response.text().await?;
    let wrapper: Vec<Vec<String>> = serde_json::from_str(&response_text).unwrap_or_default();

    let mut out = Vec::new();
    for (i, urls) in wrapper.iter().enumerate() {
        if i == 0 {
            continue; // Skip the first item
        }
        out.push(Wurl {
            date: urls[1].clone(),
            url: urls[2].clone(),
        });
    }
    Ok(out)
}

async fn get_common_crawl_urls(domain: &str, no_subs: bool) -> Result<Vec<Wurl>, reqwest::Error> {
    let subs_wildcard = if no_subs { "" } else { "*." };
    let url = format!(
        "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url={}{}/*&output=json",
        subs_wildcard, domain
    );

    let response = reqwest::get(&url).await?;
    let response_text = response.text().await?;
    let lines: Vec<&str> = response_text.lines().collect();

    let mut out = Vec::new();
    for line in lines {
        if let Ok(wrapper) = serde_json::from_str::<Value>(line) {
            if let (Some(date), Some(url)) = (wrapper["timestamp"].as_str(), wrapper["url"].as_str()) {
                out.push(Wurl {
                    date: date.to_string(),
                    url: url.to_string(),
                });
            }
        }
    }
    Ok(out)
}

async fn get_virus_total_urls(domain: &str) -> Result<Vec<Wurl>, reqwest::Error> {
    let api_key = env::var("VT_API_KEY").unwrap_or_else(|_| String::new());
    if api_key.is_empty() {
        return Ok(Vec::new());
    }

    let url = format!(
        "https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}",
        api_key, domain
    );

    let response = reqwest::get(&url).await?;
    let response_text = response.text().await?;
    let wrapper: Value = serde_json::from_str(&response_text).unwrap_or_default();

    let mut out = Vec::new();
    if let Some(urls) = wrapper["detected_urls"].as_array() {
        for url_obj in urls {
            if let Some(url) = url_obj["url"].as_str() {
                out.push(Wurl {
                    date: "".to_string(), // TODO: Parse date from VirusTotal format
                    url: url.to_string(),
                });
            }
        }
    }
    Ok(out)
}

fn get_versions(_domain: &str) -> Vec<String> {
    // Implement get_versions logic similar to the Go code
    // Placeholder implementation
    Vec::new()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let dates = args.contains(&"--dates".to_string());
    let no_subs = args.contains(&"--no-subs".to_string());
    let get_versions_flag = args.contains(&"--get-versions".to_string());

    let domains: Vec<String> = if args.len() > 1 {
        args[1..].to_vec()
    } else {
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());
        reader.lines().map(|line| line.unwrap()).collect()
    };

    if get_versions_flag {
        for domain in &domains {
            let versions = get_versions(domain);
            for version in versions {
                println!("{}", version);
            }
        }
        return;
    }

    let fetch_fns: Vec<Arc<dyn Fn(&str, bool) -> Result<Vec<Wurl>, reqwest::Error> + Send + Sync>> = vec![
        Arc::new(|domain, no_subs| {
            let rt = Runtime::new().unwrap();
            rt.block_on(get_wayback_urls(domain, no_subs))
        }),
        Arc::new(|domain, no_subs| {
            let rt = Runtime::new().unwrap();
            rt.block_on(get_common_crawl_urls(domain, no_subs))
        }),
        Arc::new(|domain, _| {
            let rt = Runtime::new().unwrap();
            rt.block_on(get_virus_total_urls(domain))
        }),
    ];

    for domain in domains {
        let results = Arc::new(Mutex::new(HashMap::new()));
        let mut handles = Vec::new();

        for fetch_fn in fetch_fns.clone() {
            let domain = domain.clone();
            let results = Arc::clone(&results);
            let handle = thread::spawn(move || {
                if let Ok(res) = fetch_fn(&domain, no_subs) {
                    let mut results = results.lock().unwrap();
                    for w in res {
                        results.insert(w.url.clone(), w.date.clone());
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
        for (url, date) in results {
            if dates {
                if let Ok(parsed_date) = DateTime::parse_from_str(&date, "%Y%m%d%H%M%S") {
                    println!("{} {}", parsed_date.with_timezone(&Utc).to_rfc3339(), url);
                } else {
                    eprintln!("failed to parse date [{}] for URL [{}]", date, url);
                }
            } else {
                println!("{}", url);
            }
        }
    }
}

