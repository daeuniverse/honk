use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths: Vec<_> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        println!(
            "{}",
            serde_json::to_string(&honk_config::conformance::project(&input))?
        );
    } else {
        for path in paths {
            let input = std::fs::read_to_string(path)?;
            println!(
                "{}",
                serde_json::to_string(&honk_config::conformance::project(&input))?
            );
        }
    }
    Ok(())
}
