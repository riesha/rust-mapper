use core::time;
use std::{fs, num, str::from_utf8, thread};

use rust_mapper::{
    pe::PEFile,
    process::{pause, Process},
};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER};
fn main()
{
    let mut proc = Process::init("testproc.exe").unwrap();
    proc.fetch_modules();
    println!("{:#x?}", proc);
    let mut pe = PEFile::new("test.dll");
    // println!("PEFile: name -> {} sections -> {:#?}", pe.name, pe.sections);

    let map = proc.manual_map(pe);

    thread::sleep(time::Duration::from_secs(5));
}
