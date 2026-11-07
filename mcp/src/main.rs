fn main() {
    let args = std::env::args().skip(1).collect();
    std::process::exit(scrapelens_mcp::entry::run(args));
}
