use libafl_cc::{ClangWrapper, CompilerWrapper};
use std::env;

pub fn main() {
    let args: Vec<String> = env::args().collect();

    let mut dir = env::current_exe().unwrap();
    let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

    // let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
    //     "cc" | "c" => false,
    //     "++" | "pp" | "xx" => true,
    //     _ => panic!("Could not figure out if c or c++ warpper was called. Expected {:?} to end with c or cxx", dir),
    // };

    let mut cc = ClangWrapper::new();

    dir.pop();

    if let Some(code) = cc
        // .cpp(is_cpp)
        // silence the compiler wrapper output, needed for some configure scripts.
        .silence(false)
        .parse_args(&args)
        .expect("Failed to parse the command line")
        .link_staticlib(&dir, "stdfuzzer")
        .add_arg("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        // .add_arg("-static")
        // .add_arg("-fsanitize=undefined,address")
        .add_arg("-v")
        // .add_pass(LLVMPasses::CmpLogRtn)
        .run()
        .expect("Failed to run the wrapped compiler")
    {
        std::process::exit(code);
    }
}
