fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/ui.proto");
    tonic_prost_build::configure()
        .build_client(true)
        .compile_protos(&["proto/ui.proto"], &["proto"])?;
    Ok(())
}
