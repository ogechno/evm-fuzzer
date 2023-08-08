use std::{
    env, 
    path::PathBuf,
    io::Read,
    fs::File
};

use clap::{self, StructOpt};

use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{
        Corpus, InMemoryCorpus, OnDiskCorpus,
    },
    schedulers::{IndexesLenTimeMinimizerScheduler, powersched::PowerSchedule,PowerQueueScheduler},
    events::SimpleEventManager,
    feedback_or,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        scheduled::{havoc_mutations, StdScheduledMutator},
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    stages::{ power::StdPowerMutationalStage, calibrate::CalibrationStage },
    state::{HasCorpus, StdState},
};

use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, EDGES_MAP, MAX_EDGES_NUM};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, StructOpt)]
#[clap(
    name = "evm-fuzzer",
    about = "",
    author = "",
    version = "0.1"
)]
struct Opt {
    #[clap(
        short = 'r',
        long,
        help = "Repeat a testcase.",
        name = "REPEAT",
        parse(try_from_str)
    )]
    repeat: Vec<PathBuf>,
}

#[no_mangle]
pub static mut DEBUG_MODE: i32 = 0;

#[no_mangle]
pub extern "C" fn get_debug_mode() -> *mut i32 {
    unsafe {
        &mut DEBUG_MODE
    }
}

#[no_mangle]
pub fn libafl_main() {
    let opt = Opt::parse();
    let repeat_testcase = opt.repeat;
    let corpus_dirs = vec![PathBuf::from("./corpus"), PathBuf::from("./crashes")];
    
    if !repeat_testcase.is_empty() {
        unsafe {
            DEBUG_MODE = 1;
        };
        let ref dir = &repeat_testcase[0];
        let mut file = File::open(dir).expect("Can not open File.");
        let mut bytes: Vec<u8> = vec![];
        file.read_to_end(&mut bytes).expect("Can not read File.");
        
        // let target = input.target_bytes();
        let buf: &[u8] = bytes.as_slice();
            
        if libfuzzer_test_one_input(buf) != 0 {
            println!("CRASHED")
        } else {
            println!("NOT CRASHED")
        }
    } else { 
        let monitor = SimpleMonitor::new(|s| println!("Monitor: {}", s));
        let mut mgr = SimpleEventManager::new(monitor);

        let edges = unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] };
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new_tracking(&edges_observer, true, false);
        let calibration = CalibrationStage::new(&map_feedback);

        let mut feedback = feedback_or!(TimeFeedback::new_with_observer(&time_observer), map_feedback);
        let mut objective = CrashFeedback::new(); /*, TimeoutFeedback::new()*/

        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryCorpus::new(),
            OnDiskCorpus::new(corpus_dirs[1].clone()).unwrap(),
            &mut feedback,
            &mut objective,
        ).unwrap();

        let args: Vec<String> = env::args().collect();
        if libfuzzer_initialize(&args) == -1 {
            panic!("Warning: LLVMFuzzerInitialize failed with -1")
        }

        let mutator = StdScheduledMutator::new(havoc_mutations());
        let power = StdPowerMutationalStage::new(mutator, &edges_observer);
        let mut stages = tuple_list!(calibration, power);

        let scheduler = IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(PowerSchedule::FAST));
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf: &[u8] = target.as_slice();
            
            if libfuzzer_test_one_input(buf) != 0 {
                ExitKind::Crash
            } else {
                ExitKind::Ok
            }
        };

        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        ).unwrap();

        let args: Vec<String> = env::args().collect();
        if libfuzzer_initialize(&args) == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }

        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &corpus_dirs));
        }

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
}
