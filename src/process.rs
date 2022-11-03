use std::mem;

use winapi::{
    shared::{minwindef::FALSE, ntdef::HANDLE},
    um::{
        memoryapi::{VirtualAllocEx, VirtualFreeEx},
        processthreadsapi::OpenProcess,
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS},
    },
};

#[derive(Debug, Clone)]
pub struct Process
{
    pub name:   String,
    pub pid:    u32,
    pub handle: Option<HANDLE>,
}

pub fn zascii(buf: Vec<i8>) -> String
{
    String::from_iter(
        buf.iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8 as char),
    )
}

impl Process
{
    pub fn init(name: &str) -> Option<Process>
    {
        let mut entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

        unsafe {
            while Process32Next(snapshot, &mut entry) == 1
            {
                let exefile = zascii(entry.szExeFile.to_vec());
                if exefile == name.to_string()
                {
                    let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                    let process = Process {
                        name:   exefile,
                        pid:    entry.th32ProcessID,
                        handle: Some(handle),
                    };
                    return Some(process);
                }
            }
        }
        return None;
    }
    pub fn write_bytes<T>(&self, addr: usize, buf: &[u8]) -> bool { todo!() }
    pub fn write<T>(&self, addr: usize, value: T) -> bool { todo!() }
    pub fn read<T>(&self, addr: usize) -> Option<T> { todo!() }
    pub fn alloc(&self, size: usize) -> Option<usize>
    {
        unsafe {
            let alloc = VirtualAllocEx(
                self.handle.unwrap(),
                0 as _,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if alloc.is_null()
            {
                return None;
            }
            else
            {
                return Some(alloc as _);
            }
        }
    }
    pub fn free(&self, addr: usize) -> bool
    {
        unsafe { VirtualFreeEx(self.handle.unwrap(), addr as _, 0, MEM_RELEASE) != 0 }
    }
}
