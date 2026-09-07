use zbus::{Result, proxy};

#[proxy(
    default_service = "net.reactivated.Fprint",
    interface = "net.reactivated.Fprint.Manager",
    default_path = "/net/reactivated/Fprint/Manager"
)]

pub trait FprintManager {
    fn get_default_device(&self) -> Result<String>;
}

#[proxy(
    default_service = "net.reactivated.Fprint",
    interface = "net.reactivated.Fprint.Device"
)]

pub trait FprintDevice {
    fn list_enrolled_fingers(&self, username: &str) -> Result<Vec<String>>;

    fn claim(&self, username: &str) -> Result<()>;
    fn release(&self) -> Result<()>;

    fn verify_start(&self, finger_name: &str) -> Result<()>;
    fn verify_stop(&self) -> Result<()>;

    #[zbus(signal)]
    fn verify_status(&self, result: String, done: bool) -> Result<()>;
}
