use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    unsafe {
        CxxQtBuilder::new_qml_module(
            QmlModule::new("passkeyd.ui.select").qml_file("src/qml/Main.qml"),
        )
        .file("src/main.rs")
        .cc_builder(|cc| {
            cc.flag("-Wno-sfinae-incomplete");
        })
        .build();
    }
}
