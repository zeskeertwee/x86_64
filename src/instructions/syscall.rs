//! Functions to call and implement system calls

use core::hint::unreachable_unchecked;
use core::mem::{transmute, MaybeUninit};

#[derive(Debug)]
pub struct Args {
    rax: MaybeUninit<usize>,
    rdi: MaybeUninit<usize>,
    rsi: MaybeUninit<usize>,
    rdx: MaybeUninit<usize>,
    r10: MaybeUninit<usize>,
    r8: MaybeUninit<usize>,
    r9: MaybeUninit<usize>,
}

impl Args {
    #[inline]
    pub unsafe fn syscall(&self) -> (usize, usize) {
        let (r1, r2): (usize, usize);
        asm!(
            "syscall",
            in("rax") self.rax.assume_init(),
            in("rdi") self.rdi.assume_init(),
            in("rsi") self.rsi.assume_init(),
            in("rdx") self.rdx.assume_init(),
            in("r10") self.r10.assume_init(),
            in("r8") self.r8.assume_init(),
            in("r9") self.r9.assume_init(),
            lateout("rcx") _,
            lateout("r11") _,
            lateout("rax") r1,
            lateout("rdx") r2,
            options(nostack),
        );
        (r1, r2)
    }

    #[inline]
    pub unsafe fn syscall_with_carry(&self) -> (usize, usize, bool) {
        let (r1, r2, carry): (usize, usize, u8);
        asm!(
            "syscall",
            "setc {}",
            lateout(reg_byte) carry,
            in("rax") self.rax.assume_init(),
            in("rdi") self.rdi.assume_init(),
            in("rsi") self.rsi.assume_init(),
            in("rdx") self.rdx.assume_init(),
            in("r10") self.r10.assume_init(),
            in("r8") self.r8.assume_init(),
            in("r9") self.r9.assume_init(),
            lateout("rcx") _,
            lateout("r11") _,
            lateout("rax") r1,
            lateout("rdx") r2,
            options(nostack),
        );
        (r1, r2, transmute(carry))
    }
}

impl Default for Args {
    fn default() -> Self {
        Self {
            rax: MaybeUninit::uninit(),
            rdi: MaybeUninit::uninit(),
            rsi: MaybeUninit::uninit(),
            rdx: MaybeUninit::uninit(),
            r10: MaybeUninit::uninit(),
            r8: MaybeUninit::uninit(),
            r9: MaybeUninit::uninit(),
        }
    }
}

/// Raw binding to the syscall instruction

const SYS_WRITE: usize = 1;
const SYS_EXIT: usize = 60;

const STDOUT: usize = 1;

#[no_mangle]
pub fn my_exit(code: i32) -> ! {
    unsafe {
        Args {
            rax: MaybeUninit::new(SYS_EXIT),
            rdi: MaybeUninit::new(code as usize),
            ..Default::default()
        }
        .syscall();
        unreachable_unchecked()
    }
}

fn write_args(s: &str) -> Args {
    Args {
        rax: MaybeUninit::new(SYS_WRITE),
        rdi: MaybeUninit::new(STDOUT),
        rsi: MaybeUninit::new(s.as_ptr() as usize),
        rdx: MaybeUninit::new(s.len()),
        ..Default::default()
    }
}

#[no_mangle]
pub fn linux_write_stdout(s: &str) -> Result<usize, ()> {
    unsafe {
        let (ret, _) = write_args(s).syscall();
        if (ret as isize) < 0 {
            Err(())
        } else {
            Ok(ret)
        }
    }
}

pub fn mac_write_stdout(s: &str) -> Result<usize, ()> {
    unsafe {
        let (ret, _, carry) = write_args(s).syscall_with_carry();
        if carry {
            Err(())
        } else {
            Ok(ret)
        }
    }
}

struct CallerSaved {
    rax: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
}

struct CalleeSaved {
    rbx: u64,
    rsp: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

struct SyscallState {
    rip: usize,
    rflags: usize,
    regs: CallerSaved,
}

unsafe extern "sysv64" fn do_syscall(
    rdi: usize,
    rsi: usize,
    rdx: usize,
    regs: &mut CallerSaved,
    rax: usize,
) -> () {
}
