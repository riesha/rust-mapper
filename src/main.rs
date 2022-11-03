use core::time;
use std::{fs, num, str::from_utf8, thread};

use rust_mapper::{pe::PEFile, process::Process};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER};
fn main()
{
    // let file = fs::read("test.dll").unwrap();
    // let headers = file.as_ptr() as *const IMAGE_DOS_HEADER;
    // let nt_headers;
    let proc = Process::init("Calculator.exe").unwrap();
    println!("{:?}", proc);
    let pe = PEFile::new("test.dll");
    println!("PEFile: name -> {} sections -> {:#?}", pe.name, pe.sections);
    // unsafe {
    //     nt_headers = (file
    //         .as_ptr()
    //         .offset((*headers).e_lfanew.try_into().unwrap()))
    //         as *const IMAGE_NT_HEADERS;
    // }

    // println!("dos headers: {:?}", headers);
    // println!("nt offset: {:?}", nt_headers as usize - headers as usize);
    // println!("nt headers: {:?}", nt_headers);
    // let image_size;
    // unsafe {
    //     image_size = (*nt_headers).OptionalHeader.SizeOfImage;
    //     println!("size of image: {:?}", image_size)
    // };
    // unsafe {
    //     let num_sections = (*nt_headers).FileHeader.NumberOfSections;
    //     println!("section count: {:?}", num_sections);
    //     let section_header = (file.as_ptr().offset(
    //         (*headers).e_lfanew as isize + std::mem::size_of::<IMAGE_NT_HEADERS>() as isize,
    //     )) as *const IMAGE_SECTION_HEADER;
    //     println!(
    //         "section offset: {:?}",
    //         section_header as usize - nt_headers as usize
    //     );
    //     let section_slice = std::slice::from_raw_parts(
    //         section_header,
    //         (*nt_headers).FileHeader.NumberOfSections as usize,
    //     );
    //     for &section in section_slice
    //     {
    //         println!(
    //             "section name: {} addr -> {:#x}",
    //             from_utf8(&section.Name).unwrap(),
    //             section.VirtualAddress
    //         );
    //     }
    // }
    thread::sleep(time::Duration::from_secs(5));
}
