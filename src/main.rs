use core::time;
use std::{fs, num, str::from_utf8, thread};

use rust_mapper::{pe::PEFile, process::Process};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER};
fn main()
{
    let proc = Process::init("Calculator.exe").unwrap();
    println!("{:?}", proc);
    let pe = PEFile::new("test.dll");
    println!("PEFile: name -> {} sections -> {:#?}", pe.name, pe.sections);

    thread::sleep(time::Duration::from_secs(5));
}
