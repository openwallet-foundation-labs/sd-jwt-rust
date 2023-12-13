use clap::Parser;
use serde::Serialize;

#[derive(Parser)]
pub struct Cli {
    /// The type to generate
    #[arg(short, value_enum, default_value_t = GenerateType::Example)]
    pub type_: GenerateType,
    /// The paths to the directories where specification.yaml file is located
    #[arg(short, value_delimiter = ' ', num_args = 0.., require_equals = false)]
    pub paths: Vec<std::path::PathBuf>,
}


#[derive(clap::ValueEnum, Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GenerateType {
    Example,
    TestCase,
}