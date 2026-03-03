use ctap_types::ctap2::credential_management::{Request, Response};
use passkeyd_share::config::Config;

pub fn mgt(config: &Config, req: Request) -> anyhow::Result<Response> {
    println!("{:#?}", req);
    todo!()
}
