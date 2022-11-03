use std::{fs, str::from_utf8};

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER};
#[derive(Debug, Clone)]
pub struct PEFile
{
    pub name:     String,
    pub sections: Vec<Section>,
    pub data:     Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct Section
{
    pub name:         String,
    pub virtual_addr: usize,
    pub data_size:    usize,
    pub data_ptr:     usize,
}
impl PEFile
{
    pub fn new(name: &str) -> Self
    {
        let file = fs::read(name).unwrap();

        let header = file.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_header = unsafe {
            (file.as_ptr().offset((*header).e_lfanew.try_into().unwrap()))
                as *const IMAGE_NT_HEADERS
        };
        let section_header = unsafe {
            (file.as_ptr().offset(
                (*header).e_lfanew as isize + std::mem::size_of::<IMAGE_NT_HEADERS>() as isize,
            )) as *const IMAGE_SECTION_HEADER
        };

        let section_slice = unsafe {
            std::slice::from_raw_parts(
                section_header,
                (*nt_header).FileHeader.NumberOfSections as usize,
            )
        };
        let mut sections: Vec<Section> = Vec::new();
        for &section in section_slice
        {
            sections.push(Section {
                name:         String::from_iter(
                    section
                        .Name
                        .to_vec()
                        .iter()
                        .take_while(|c| **c != 0)
                        .map(|c| *c as u8 as char),
                ),
                virtual_addr: section.VirtualAddress as _,
                data_size:    section.SizeOfRawData as _,
                data_ptr:     section.PointerToRawData as _,
            })
        }
        PEFile {
            name:     name.to_string(),
            sections: sections,
            data:     file,
        }
    }
}
