fn main() {
    let path="../ProxyLane/ProxyLane.rc";
    println!("cargo:rerun-if-changed={path}");
    let source=std::fs::read_to_string(path).expect("read ProxyLane product version");
    let line=source.lines().find(|s|s.contains("VALUE \"ProductVersion\"")).expect("ProductVersion resource");
    let version=line.split('"').nth(3).expect("ProductVersion value");
    println!("cargo:rustc-env=PROXYLANE_PRODUCT_VERSION={version}");
}
