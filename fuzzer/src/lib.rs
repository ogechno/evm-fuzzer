use std::{
    env, 
    path::PathBuf,
};

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
    schedulers::{QueueScheduler, IndexesLenTimeMinimizerScheduler},
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
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};

use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, EDGES_MAP, MAX_EDGES_NUM};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[no_mangle]
pub fn libafl_main() {
    let corpus_dirs = vec![PathBuf::from("./corpus"), PathBuf::from("./crashes")];
    
    let monitor = SimpleMonitor::new(|s| println!("Monitor: {}", s));
    let mut mgr = SimpleEventManager::new(monitor);

    let edges = unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] };
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));
    let time_observer = TimeObserver::new("time");

    let mut feedback = feedback_or!(MaxMapFeedback::new_tracking(&edges_observer, true, false), TimeFeedback::new_with_observer(&time_observer));
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
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
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
