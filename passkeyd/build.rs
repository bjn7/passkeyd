fn main() {
    cc::Build::new()
        .file("hidapi/hid.c")
        .include("hidapi")
        .compile("hidapi");

    println!("cargo:rustc-link-lib=udev");
}
