use reqwest::*;

header! { (ReverseItApikey, "api-key") => [String] }

/// client for reverse.it
pub struct ReverseItClient {
    apikey: String,
    root: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileCertificate {
    pub owner: String,
    pub issuer: String,
    pub serial_number: String,
    pub md5: String,
    pub sha1: String,
    pub valid_from: String,
    pub valid_until: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExtractedFile {
    pub name: String,
    pub file_path: String,
    pub file_size: i64,
    pub sha256: String,
    pub type_tags: Option<Vec<String>>,
    pub threat_level: i64,
    pub threat_level_readable: String,
    pub av_lavel: Option<String>,
    pub av_matched: i64,
    pub av_total: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Process {
    pub uid: String,
    pub parent_uid: Option<String>,
    pub name: String,
    pub normalized_path: String,
    pub command_line: String,
    pub sha256: String,
    pub av_lavel: Option<String>,
    pub av_matched: i64,
    pub av_total: i64,
    pub pid: Option<String>,
    pub icon: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SearchResult {
    pub job_id: String,
    pub environment_id: String,
    pub environment_description: String,
    pub size: i64,
    #[serde(rename = "type")] // cannot use keyword "type" in Rust
    pub filetype: String,
    pub type_short: Vec<String>,
    pub target_url: Option<String>,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub ssdeep: String,
    pub imphash: Option<String>,
    pub av_detect: i64,
    pub vx_family: Option<String>,
    pub url_analysis: Option<bool>,
    pub analysis_start_time: String,
    pub threat_score: i64,
    pub interesting: bool,
    pub threat_level: i64,
    pub verdict: String,
    pub certificates: Option<Vec<FileCertificate>>,
    pub domains: Vec<String>,
    pub classification_tags: Vec<String>,
    pub compromised_hosts: Option<Vec<String>>,
    pub hosts: Vec<String>,
    pub total_network_connections: i64,
    pub total_processes: i64,
    pub total_signatures: i64,
    pub extracted_files: Option<Vec<ExtractedFile>>,
    pub processes: Option<Vec<Process>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScreenShot {
    pub name: String,
    pub image: String,
    pub date: String,
}

impl ReverseItClient {
    pub fn new<S: AsRef<str>>(apikey: S) -> ReverseItClient {
        ReverseItClient {
            apikey: String::from(apikey.as_ref()),
            root: String::from("https://www.reverse.it/api/v2"),
        }
    }

    pub fn search<S: AsRef<str>>(&self, hash: S) -> Result<Vec<SearchResult>> {
        let params = [("hash", hash.as_ref())];
        let client = Client::new();
        let result: Vec<SearchResult> = client
            .post(format!("{}/search/hash", self.root).as_str())
            .header(header::UserAgent::new("Falcon Sandbox"))
            .header(ReverseItApikey(self.apikey.clone()))
            .form(&params)
            .send()?
            .json()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn works() {
        let key = match env::var("REVERSEIT_APIKEY") {
            Ok(val) => val,
            Err(_) => panic!("please set env value REVERSEIT_APIKEY"),
        };

        let client = ReverseItClient::new(key.as_str());
        let _ = client
            .search("7e7af056f88c60c3b55adebe54b73370703a5533c5d0982a8752ef94327c6acd")
            .unwrap();
    }
}
