use core::{slice, time};
use std::{
    io::{self, Read},
    mem::{self, size_of, transmute},
    path,
    process::Command,
    ptr::{null, null_mut},
    thread,
};

use iced_x86::code_asm::{CodeAssembler, *};
use winapi::{
    shared::{minwindef::FALSE, ntdef::HANDLE},
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        memoryapi::{
            ReadProcessMemory, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, WriteProcessMemory,
        },
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        psapi::{GetModuleFileNameExA, GetModuleFileNameExW},
        tlhelp32::{
            CreateToolhelp32Snapshot, Module32Next, Process32First, Process32Next, MODULEENTRY32,
            PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS,
        },
        winnt::{
            IMAGE_BASE_RELOCATION, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC,
            IMAGE_REL_BASED_DIR64, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PIMAGE_BASE_RELOCATION, PROCESS_ALL_ACCESS,
        },
    },
};

use crate::pe::PEFile;
#[derive(Debug, Clone)]
pub struct Module
{
    pub name: String,
    pub path: String,
    pub base: usize,
    pub size: usize,
}
#[derive(Debug, Clone)]
pub struct Process
{
    pub name:    String,
    pub pid:     u32,
    pub handle:  Option<HANDLE>,
    pub modules: Option<Vec<Module>>,
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
                        name:    exefile,
                        pid:     entry.th32ProcessID,
                        handle:  Some(handle),
                        modules: None,
                    };
                    return Some(process);
                }
            }
            CloseHandle(snapshot);
        }
        return None;
    }
    pub fn fetch_modules(&mut self)
    {
        let mut entry: MODULEENTRY32 = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;
        let mut modules: Vec<Module> = Vec::new();
        let mut pathbuf = vec![0; 255];
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid) };
        unsafe {
            while Module32Next(snapshot, &mut entry) == 1
            {
                let modname = zascii(entry.szModule.to_vec());

                // println!(
                //     "module found: name -> {:?} base addr-> {}",
                //     zascii(entry.szModule.to_vec()),
                //     entry.modBaseAddr as usize
                // );
                let res = GetModuleFileNameExW(
                    self.handle.unwrap(),
                    entry.hModule,
                    pathbuf.as_mut_ptr(),
                    255,
                ) as usize;
                modules.push(Module {
                    name: modname,
                    path: String::from_utf16_lossy(&pathbuf[..res]).to_string(),
                    base: entry.modBaseAddr as _,
                    size: entry.modBaseSize as _,
                })
            }
            CloseHandle(snapshot);
        }
        self.modules = Some(modules);
    }

    pub fn protect(&self, addr: usize, size: usize, protect: u32) -> Option<u32>
    {
        unsafe {
            let mut old = mem::zeroed();
            if VirtualProtectEx(
                self.handle.unwrap(),
                addr as _,
                size as _,
                protect,
                &mut old,
            ) != 0
            {
                return Some(old);
            }
            else
            {
                return None;
            }
        }
    }
    pub fn write_bytes(&self, addr: usize, buf: &[u8]) -> Option<usize>
    {
        unsafe {
            let mut wcount = 0;
            if WriteProcessMemory(
                self.handle.unwrap(),
                addr as _,
                buf.as_ptr() as _,
                buf.len(),
                &mut wcount,
            ) != 0
            {
                return Some(wcount);
            }
            else
            {
                println!("lasterror: {:?}", GetLastError());
                None
            }
        }
    }
    pub fn write_bytes_sized(&self, addr: usize, buf: &[u8], size: usize) -> Option<usize>
    {
        unsafe {
            let mut wcount = 0;
            if WriteProcessMemory(
                self.handle.unwrap(),
                addr as _,
                buf.as_ptr() as _,
                size,
                &mut wcount,
            ) != 0
            {
                return Some(wcount);
            }
            else
            {
                None
            }
        }
    }
    pub fn write<T>(&self, addr: usize, value: T) -> bool { todo!() }
    pub fn read<T>(&self, addr: usize) -> Option<T>
    {
        unsafe {
            let mut buf = mem::zeroed();
            let mut _read = 0;
            if ReadProcessMemory(
                self.handle.unwrap(),
                addr as _,
                &mut buf as *mut T as _,
                size_of::<T>(),
                &mut _read,
            ) == 0
            {
                return None;
            }
            else
            {
                return Some(buf);
            }
        }
    }

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

    pub fn create_thread(&self, addr: usize) -> (HANDLE, u32)
    {
        unsafe {
            let mut thread_id = 0;
            let handle = CreateRemoteThread(
                self.handle.unwrap(),
                null_mut(),
                0,
                mem::transmute(addr),
                null_mut(),
                0,
                &mut thread_id,
            );
            (handle, thread_id)
        }
    }

    pub fn manual_map(&self, bin: PEFile) -> bool
    {
        let bin_alloc = self.alloc(bin.opt_header.SizeOfImage as _).unwrap() as *const usize;
        println!("mapping alloc address: {:#?}", bin_alloc);
        let write = self
            .write_bytes_sized(
                bin_alloc as usize,
                &bin.data,
                bin.opt_header.SizeOfHeaders as _,
            )
            .unwrap();
        for section in &bin.sections
        {
            // println!("writing section {:#x?}", section);

            unsafe {
                // println!(
                //     "slice len {:#x?}",
                //     slice::from_raw_parts(
                //         (bin.data.as_ptr() as isize + section.data_ptr as isize) as *const u8,
                //         section.data_size,
                //     )
                //     .len()
                // );
                self.write_bytes_sized(
                    (bin_alloc as isize + section.data_ptr as isize) as usize,
                    slice::from_raw_parts(
                        (bin.data.as_ptr() as isize + section.data_ptr as isize) as *const u8,
                        section.data_size,
                    ),
                    section.data_size,
                );
            }
        }

        let datadir = bin.opt_header.DataDirectory;

        let mut base_relocation = unsafe {
            transmute::<usize, PIMAGE_BASE_RELOCATION>(
                bin.data.as_ptr() as usize
                    + bin
                        .clone()
                        .sections
                        .into_iter()
                        .find(|sec| sec.name == ".reloc")
                        .unwrap()
                        .data_ptr,
            )
        };
        let base_reloc_end = base_relocation as usize
            + bin
                .clone()
                .sections
                .into_iter()
                .find(|sec| sec.name == ".reloc")
                .unwrap()
                .data_size;
        println!("basereloc start: {:#x?}", base_relocation as usize);
        println!("basereloc end: {:#x?}", base_reloc_end);
        let delta = bin_alloc as isize - bin.opt_header.ImageBase as isize;
        println!("delta: {:#x?}", delta);
        pause();
        unsafe {
            while (*base_relocation).VirtualAddress != 0u32
                && base_relocation as usize <= base_reloc_end
                && (*base_relocation).SizeOfBlock != 0u32
            {
                let address =
                    (bin_alloc as usize + (*base_relocation).VirtualAddress as usize) as isize;

                let item = transmute::<usize, *const u16>(
                    base_relocation as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>(),
                );
                let count = ((*base_relocation).SizeOfBlock as usize
                    - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                    / std::mem::size_of::<u16>() as usize;
                // println!(
                //     "reloc rva -> {:#x?} sizeof block -> {:#x?} count -> {}",
                //     address,
                //     (*base_relocation).SizeOfBlock,
                //     count
                // );

                for i in 0..count
                {
                    let offset = item.offset(i as isize).read() & 0xFFF;
                    println!(
                        "entry addr -> {:#x?}",
                        ((address + offset as isize) as *mut isize)
                    );

                    // Add the delta to the value of each address where the relocation needs to be performed
                    let mut val = self
                        .read::<isize>(((address + offset as isize) as usize))
                        .unwrap();
                    println!("val -> {:#x?}", val);
                    val = val.wrapping_add(delta);
                    println!("val after -> {:#x?}", val);
                    self.write_bytes((address + offset as isize) as usize, &val.to_le_bytes());
                    //*((address + offset as isize) as *mut isize) += delta;
                }

                base_relocation = transmute::<usize, PIMAGE_BASE_RELOCATION>(
                    base_relocation as usize + (*base_relocation).SizeOfBlock as usize,
                );
            }
        }

        println!("entrypoint loc:{:#x?}", unsafe {
            bin_alloc as isize + bin.opt_header.AddressOfEntryPoint as isize
        } as isize);

        println!(
            "proc base:{:#x?}",
            self.modules
                .as_ref()
                .unwrap()
                .into_iter()
                .find(|module| module.name == self.name)
                .unwrap()
                .base
        );
        thread::sleep(time::Duration::from_secs(120));
        // self.call_dllmain(
        //     bin_alloc as _,
        //     self.modules
        //         .as_ref()
        //         .unwrap()
        //         .into_iter()
        //         .find(|module| module.name == self.name)
        //         .unwrap()
        //         .base
        //         + bin.opt_header.AddressOfEntryPoint as usize,
        // );

        return true;
    }

    #[allow(unused_must_use)]
    pub fn call_dllmain(&self, base: usize, entry: usize)
    {
        let mut assembler = CodeAssembler::new(32).unwrap();

        assembler.push(ebp).unwrap();
        assembler.push(0x0).unwrap();
        assembler.push(0x1).unwrap();
        assembler.push(base as u32).unwrap();
        assembler.mov(eax, entry as u32).unwrap();
        assembler.call(eax).unwrap();
        assembler.pop(ebp).unwrap();
        assembler.ret_1(0xC).unwrap();

        // assembler.push(ebp).unwrap();
        // assembler.mov(ebp, esp).unwrap();

        // assembler.mov(dword_ptr(esp + 0x38), 0x1337).unwrap();
        // assembler.mov(dword_ptr(esp), 0x1337).unwrap();

        // assembler.mov(eax, entry as u32).unwrap();
        // assembler.call(eax).unwrap();

        // assembler.pop(ebp).unwrap();
        // assembler.ret_1(0x8).unwrap();

        let shellcode = assembler.assemble(0x0).unwrap();
        println!("assembled: {:#x?}", shellcode);

        let shellcode_alloc = self.alloc(shellcode.len());
        println!("shellcode alloc: {:#x}", shellcode_alloc.unwrap());

        let _write_shellcode = self.write_bytes(shellcode_alloc.unwrap(), &shellcode);
        pause();
        let (thread_handle, _) = self.create_thread(shellcode_alloc.unwrap());

        unsafe { CloseHandle(thread_handle) };
    }
}
use std::io::Write;
pub fn pause()
{
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}
