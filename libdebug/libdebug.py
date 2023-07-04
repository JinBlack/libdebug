from .ptrace import *
import struct
import subprocess
import errno
import collections
import os
import signal 
import time
import logging
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from .utils import u64, u32
from .signal import *
from threading import Thread, Event

#logging.basicConfig(level="DEBUG")
logging = logging.getLogger("libdebug")

class DebugFail(Exception):
    pass

class Memory(collections.abc.MutableSequence):

    def __init__(self, getter, setter):
        self.getword = getter
        self.setword = setter
        self.word_size = 8

    def _retrive_data(self, start, stop):
        data = b""
        for i in range(start, stop, self.word_size):
            n = self.getword(i)
            data += struct.pack("<q", n)
        return data

    def __getitem__(self, index):
        if isinstance(index, slice):
            start = index.start // self.word_size * self.word_size
            stop = (index.stop + self.word_size) // self.word_size * self.word_size
            return self._retrive_data(start, stop)[index.start-start: index.stop-start]
        else:
            return (self.getword(index) & 0xff).to_bytes(1, 'little')

    def _set_data(self, start, value):
        logging.debug("writing @%#x <- %s", start, value)
        for i in range(start, (start + len(value)), self.word_size):
            chunk = value[(i-start) : (i+self.word_size-start)]
            data = struct.unpack("<Q", chunk)[0]
            self.setword(i, data)

    def __setitem__(self, index, value):
        if isinstance(index, slice):
            start = index.start // self.word_size * self.word_size
            #TODO if is a slice ensure that value is not going after the end
            stop = (index.start + len(value) + self.word_size) // self.word_size * self.word_size
            index = index.start
        else:
            start = index // self.word_size * self.word_size
            stop = (index + len(value) + self.word_size) // self.word_size * self.word_size
        #Maybe all this alligment stuff is useless if I can do writes allinge per byte.
        logging.debug("mem index:%#x, value: %s, start:%#x, stop:%x", index, value, start, stop)
        orig_data = self._retrive_data(start, stop)
        new_data = orig_data[0:index-start] + value + orig_data[index-start+len(value):]
        self._set_data(start, new_data)


    def __len__(self):
        return 0

    def __delitem__(self, index):
        self.__setitem__(self, index, b'\x00')

    def insert(self, index, value):
        self.__setitem__(self, index, value)

class ThreadDebug():
    def __init__(self, tid, ptracer):
        self.tid = tid
        self.regs = {}
        self.fpregs = {}
        self.regs_names = AMD64_REGS
        self.reg_size = 8
        self.running = True
        self.ptrace = ptracer
        #This is specific to intel x86_64
        self.hw_breakpoints = {'DR0': None, 'DR1': None, 'DR2': None, 'DR3': None,}
        self.stopped = Event()

        #create property for registers
        for r in self.regs_names:
            setattr(ThreadDebug, r, self._get_reg(r))

        #create property for fpregisters. Avoid Long because conaint rip and we do not want to overload rip
        for r in FPREGS_SHORT+FPREGS_INT+FPREGS_80+FPREGS_128:
            setattr(ThreadDebug, r, self._get_fpreg(r))

    def __repr__(self) -> str:
        return "Thread [{}] <{:#x}>".format(self.tid, self.rip)

    ## Registers

    def _get_reg(self, name):
        #This is an helping function to generate properties to access registers        
        def getter(self):
            #reload registers
            self.get_regs()
            return self.regs[name]
        def setter(self, value):
            self.get_regs()
            self.regs[name] = value
            self.set_regs()
        return property(getter, setter, None, name)

    def set_regs(self):
        self._enforce_stop()

        regs_values = []
        for name in self.regs_names:
            regs_values.append(self.regs[name])
 
        data = struct.pack("<" + "Q"*len(self.regs_names), *regs_values)
        self.ptrace.setregs(self.tid, data)

    def get_regs(self):
        self._enforce_stop()

        buf = self.ptrace.getregs(self.tid)
        if buf is None:
            err = get_errno()
            #We use geT_regs as test for the process if it is running we may stoppit before executing something
            # ether the process is dead or is running
            if err == errno.ESRCH and self.running:
                #we should stop the process.
                return None
            elif err == errno.ESRCH and not self.running:
                logging.critical("The proccess %d is dead!", self.tid)
            else:
                logging.debug("getregs error: %d", err)
                raise PtraceFail("GetRegs Failed. Do you have permisions? Running as sudo?")

        buf_size = len(self.regs_names) * self.reg_size 
        regs = struct.unpack("<" + "Q"*len(self.regs_names), buf[:buf_size])

        for name, value in zip(self.regs_names, regs):
            self.regs[name] = value
        logging.debug("[TID %d] rax:%#x", self.tid, self.regs['rax'])
        return self.regs

    def _get_fpreg(self, name):
        #This is an helping function to generate properties to access fp registers        
        def getter(self):
            #reload registers
            self.get_fpregs()
            return self.fpregs[name]
        def setter(self, value):
            self.get_fpregs()
            self.fpregs[name] = value
            self.set_fpregs()
        return property(getter, setter, None, name)
   

    def get_fpregs(self):
        self._enforce_stop()
        buf = self.ptrace.getfpregs(self.tid)
        if buf is None:
            err = get_errno()
            #We use geT_regs as test for the process if it is running we may stoppit before executing something
            # ether the process is dead or is running
            if err == errno.ESRCH and self.running:
                #we should stop the process.
                return None
            elif err == errno.ESRCH and not self.running:
                logging.critical("The proccess is dead!")
            else:
                logging.debug("getregs error: %d", err)
                raise PtraceFail("GetRegs Failed. Do you have permisio? Running as sudo?")

        # FPREGS_SHORT = ["cwd", "swd", "ftw", "fop"]
        # FPREGS_LONG  = ["rip", "rdp"]
        # FPREGS_INT   = ["mxcsr", "mxcr_mask"]
        # FPREGS_64    = ["fp%d" %i for i in range(16)]
        # FPREGS_128   = ["xmm%d" %i for i in range(16)]

        buf_start = 0
        # SHORTS
        buf_size = len(FPREGS_SHORT) * 2
        regs = struct.unpack("<" + "H"*len(FPREGS_SHORT), self.buf[buf_start:buf_start+buf_size])
        for name, value in zip(FPREGS_SHORT, regs):
            self.fpregs[name] = value
        buf_start += buf_size

        # LONG
        buf_size = len(FPREGS_LONG) * 8
        regs = struct.unpack("<" + "Q"*len(FPREGS_LONG), self.buf[buf_start:buf_start+buf_size])
        for name, value in zip(FPREGS_LONG, regs):
            self.fpregs[name] = value
        buf_start += buf_size

        # INT
        buf_size = len(FPREGS_INT) * 4
        regs = struct.unpack("<" + "I"*len(FPREGS_INT), self.buf[buf_start:buf_start+buf_size])
        for name, value in zip(FPREGS_INT, regs):
            self.fpregs[name] = value
        buf_start += buf_size


        # ST 80bits
        for r in FPREGS_80:
            a, b =  struct.unpack("<QQ", self.buf[buf_start:buf_start+16])
            value = (b << 64) | a
            self.fpregs[r] = value
            buf_start += 16

        # XMM 128bits
        for r in FPREGS_128:
            a, b =  struct.unpack("<QQ", self.buf[buf_start:buf_start+16])
            value = (b << 64) | a
            self.fpregs[r] = value
            buf_start += 16

        return self.fpregs


    def set_fpregs(self):
        self._enforce_stop()

        data = b""
        for r in FPREGS_SHORT:
            data += struct.pack("<H", self.fpregs[r])
        for r in FPREGS_LONG:
            data += struct.pack("<Q", self.fpregs[r])
        for r in FPREGS_INT:
            data += struct.pack("<I", self.fpregs[r])
        for r in FPREGS_80:
            data += struct.pack("<QQ", self.fpregs[r] & 0xffffffffffffffff, self.fpregs[r] >> 64)
        for r in FPREGS_128:
            data += struct.pack("<QQ", self.fpregs[r] & 0xffffffffffffffff, self.fpregs[r] >> 64)
        self.ptrace.setfpregs(data)

    def _test_execution(self):
        # Test if the program is running or not.
        # If we are not able to get regs. The program is still running OR WE ARE NOT ATTACHED TO IT ANYMORE.
        regs = self.ptrace.getregs(self.tid)
        return not(regs is None)

    def _sig_stop(self):
        os.kill(self.tid, signal.SIGSTOP)

    # Per il momento penso di usare callback per interrompere tutti i thread appena si ferma uno dopo una wait globale [03/04/23]
    def wait(self, callback=None): 
        logging.debug(f"thread [{self.tid}] will wait")
        self.stopped.wait()
        logging.debug(f"thread [{self.tid}] finished waiting")
        if callback is not None:
            callback()
        logging.debug("finished waiting thread")

    def _stop_process(self):
        logging.debug("[TID %d] Stopping the process", self.tid)
        self._sig_stop()
        self.wait()
        self.running = False

    def _enforce_stop(self):
        # Can we trust self.running without any check?
        if self.running and self._test_execution() == False:
            #this should be a PTRACE_INTERRUPT # PTRACE_INTERRUPT causes issues
            self._stop_process()
            return True
        else:
            return False


    def step(self):
        """
        Execute the next instruction (Step Into)
        """
        #Step can stuck running into syscalls
        logging.debug(f"[TID {self.tid}] Step")
        self.running = True
        self.stopped.clear()
        self.ptrace.singlestep(self.tid)
        self.wait()


    def cont(self):
        """
        Continue the execution until the next breakpoint is hitted or the program is stopped
        """
        self.running = True
        self.stopped.clear()
        # Probably should implement a timeout
        logging.debug("[TID %d] cont", self.tid)
        self.ptrace.cont(self.tid)

    #Struct User
    def _peek_user(self, addr):
        self._enforce_stop()
        data = self.ptrace.peek_user(self.tid, addr)
        return data

    def _poke_user(self, addr, data):
        self._enforce_stop()
        data = self.ptrace.poke_user(self.tid, addr, data)

    #HW BreakPoints
    def hw_bp(self, addr, cond='X', length=8):
        #find first empty register
        for r in self.hw_breakpoints:
            if self.hw_breakpoints[r] is None:
                break
        if self.hw_breakpoints[r] is not None:
            logging.error("Failed to set hw_bp %#lx. All hw register are used!", addr)
            return False
        logging.debug("Setting bp %#lx in register %r", addr, r)
        #write value in the register
        self._poke_user(AMD64_DBGREGS_OFF[r], addr)


        #enable the register from the ctrl
        ctrl_reg = self._peek_user(AMD64_DBGREGS_OFF['DR7'])
        ctrl_reg |= AMD64_DBGREGS_CTRL_LOCAL[r]
        # If the corresponding RWn field in register DR7 is 00 (instruction execution), then the
        # LENn field should also be 00. The effect of using other lengths is undefined. See
        # Section 18.2.5, “Breakpoint Field Recognition,” below
        # https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/253669.pdf

        #clear condition values
        ctrl_reg &= ~(3 << AMD64_DBGREGS_CTRL_COND[r])
        ctrl_reg |= (AMD64_DBGREGS_CTRL_COND_VAL[cond] << AMD64_DBGREGS_CTRL_COND[r])

        #clear len values
        ctrl_reg &= ~(3 << AMD64_DBGREGS_CTRL_LEN[r])
        if cond != 'X':
            ctrl_reg |= (AMD64_DBGREGS_CTRL_LEN_VAL[length] << AMD64_DBGREGS_CTRL_LEN[r])

        self._poke_user(AMD64_DBGREGS_OFF['DR7'], ctrl_reg)

        #store that is in place        
        self.hw_breakpoints[r] = addr
        return True


    def del_hw_bp(self, addr):
        #find register containing the bp
        for r in self.hw_breakpoints:
            if self.hw_breakpoints[r] == addr:
                break
        if self.hw_breakpoints[r] != addr:
            logging.error("Failed to find a hw_bp for %#lx.", addr)
            return False
        logging.debug("Stopping bp %#lx in register %r", addr, r)
        #write value in the register (Not necessary to be onest)
        self._poke_user(AMD64_DBGREGS_OFF[r], 0x0)
        #enable the register from the ctrl
        ctrl_reg = self._peek_user(AMD64_DBGREGS_OFF['DR7'])
        ctrl_reg &= ~AMD64_DBGREGS_CTRL_LOCAL[r]
        self._poke_user(AMD64_DBGREGS_OFF['DR7'], ctrl_reg)
        #store that is in place        
        self.hw_breakpoints[r] = None
        return True

    # Devo gestire due casi: ptrace.detach non può essere chiamato mentre il processo sta runnando e devo garantire che una volta fatto detach da tutti i thread waitpid non sarà più chiamato
    def detach(self):
        """
        Detach from a thread

        If the thread isn't running when the function is called the process won't resume after behing detached
        """
        logging.info("Detach tid %d", self.tid)   
        stopped = self._enforce_stop()
        # Se stava runnando il thread si è fermato e abbiamo chiuso constant_wait.
        # Nel caso contrario è necessario triggerare una nuova interuzione. Questo però ci impedisce di sapere se l'utente ha mandato un SIGSTOP per evitare che il processo continui, quindi per default mi assicuro che rimanga fermo
        if not stopped:
            # send signal to prevent step from executing an instruction
            self._sig_stop()
            # Catch signal and close waitpid
            self.step()
            # send signal to stop the execution as soon as we detach
            self._sig_stop()
        self.ptrace.detach(self.tid)
        
class Debugger:

    def __init__(self, pid=None, multithread=True):
        self.pid = None
        self.threads = {}
        self.cur_tid = None
        self.old_pid = None
        self.process = None
        self.multithread = multithread
        #According to ptrace manual we need to keep track od the running state to discern if ESRCH is becouse the process is running or dead
        self.running = True
        self.ptrace = Ptracer()
        Thread(target=self.ptrace.start, daemon=True).start()
        self.regs_names = AMD64_REGS
        self.reg_size = 8
        self.mem = Memory(self.peek, self.poke)
        self.breakpoints = {}
        self.map = {}
        self.bases = {}
        self.terminal = ['tmux', 'splitw', '-h']

        self.should_exit = False
        self.stopped = Event()
        self.stop_status = 0
        self.__flag_hidden_step = False
        self.exited = Event()
        self.exited.set()
        
        #create property for registers
        for r in AMD64_REGS+FPREGS_SHORT+FPREGS_INT+FPREGS_80+FPREGS_128:
            setattr(Debugger, r, self._get_reg(r))

        if pid is not None:
            self.attach(pid)

    def __repr__(self) -> str:
        return "Debugger [{:d}]({:d}) <{:#x}>".format(self.pid, len(self.threads), self.rip)

    def _get_reg(self, name):
        #This is an helping function to generate properties to access registers        
        def getter(self):
            #reload registers
            r = self.threads[self.cur_tid].get_regs()
            return r[name]
        def setter(self, value):
            self.threads[self.cur_tid].get_regs()
            self.threads[self.cur_tid].regs[name] = value
            self.threads[self.cur_tid].set_regs()
        return property(getter, setter, None, name)

    def _sig_stop(self, pid):
        os.kill(pid, signal.SIGSTOP)

    def _find_new_tids(self):
        #identify threads for the current process
        path = "/proc/%d/task/" % self.pid
        tids = list(map(int, os.listdir(path)))
        logging.debug("tids: %r", tids)
        for t in tids:
            if t not in self.threads:
                logging.debug("New Thread %d", t)
                self.threads[t] = ThreadDebug(t, self.ptrace)
                # self._sig_stop(t)
                # self.attach(t)

    def _constant_wait(self):
        while self._wait_process():
            if self.should_exit: break
        logging.debug(f"libdebug [{self.pid}/{self.old_pid}] won't wait any more")
        self.stopped.set()
        self.exited.set()

    def _wait_process(self, pid=None):
        should_continue = False
        options = 0x40000000
        buf = create_string_buffer(100)
        # Ho paura che -1 crei grossi problemi quando vuoi debuggere diversi programmi nello stesso script. Già lo script dei test ha problemi perchè catcha l'exit di processi precedenti. Quando trovo il tempo miglioro questa parte, ma saranno grosse modifiche :(
        logging.debug("waiting...")
        if self.multithread:
            r = self.ptrace.waitpid(-1, buf, options) 
        else:
            r = self.ptrace.waitpid(self.pid, buf, options) 

        # In qualche modo evita molti problemi...
        time.sleep(0.02)

        status = u32(buf[:4])
        logging.debug("waitpid status: %#x, tid: %d, %s", status, r, WIFSTOPPED(status))

        # Da chiamare prima per poter controllare se r è nostro o meno
        self._retrieve_maps()
        self._find_new_tids()

        # Potrebbe essere fork, come potrebbe essere altro processo nello stesso script
        if r not in self.threads:
            if status == 0:
                logging.info(f"I think the process [{self.pid}] forked -> [{r}]")
            else:
                logging.warning(f"process [{r}] as been caught by debugger [{self.pid}] but is not a known thread")
            return True

        if WIFSTOPPED(status):
            sig = WSTOPSIG(status)
            logging.debug("wait stop, for %s(%#x)", signal_from_num(sig), sig)
            if sig == SIGTRAP:
                event = (status >> 16) & 0xff
                logging.debug("wait stoped event %s(%#x)", ptrace_event_from_num(event), event)
                if event == PTRACE_EVENT_CLONE:
                    self.__last_action = "continue" # Not sure, but I keep the hold behaviour just in case
                    should_continue = True 

            elif sig == SIGCHLD:
                logging.debug("signal SIGCHLD received. We will ignore it and continue")
                should_continue = True

        if WTERMSIG(status) == SIGKILL:
            logging.debug("process [{r}] received SIGKILL")
            return False

        if WIFEXITED(status):
            logging.info("Thread %d is dead", r)
            del self.threads[r]
            if len(self.threads) == 0:
                self.handle_exit()
                raise DebugFail("All threads are dead")
                return False
            return True

        if should_continue:
            #continue that thread
            if self.__last_action == "continue":
                self.threads[r].cont()
            elif self.__last_action == "step":
                self.threads[r].step()
        else:
        # I need to set back the instruction pointer before claiming that the process has stopped
            # Bugged
            #self.cur_tid = r
            self.stop_status = status
            self._retore_breakpoints()
            self.threads[r].stopped.set()
            if self.__flag_hidden_step:
                self.__flag_hidden_step = False
            else:
                # Can't be blocking
                Thread(target=self.handle_stop).start()
            self.stopped.set()
            self.running = False
        return True

    # Come facciamo quando ci sono più thread ? Interrompo tutti gli altri appena uno raggiunge un breakpoint ? [03/04/23]
    #def wait(self):
    #    for thread in self.threads.values():
    #        # Sarebbero da parallelizzare tutte
    #        thread.wait(callback=lambda: self._enforce_stop("wait"))
    #    logging.debug("finished waiting global")
    # Direi di si, ma per il momento te lo lascio più simile possibile a come funzionava prima
    def wait(self):
        self.stopped.wait()

    def _stop_process(self):
        logging.debug("Stopping the process")
        for tid, t in self.threads.items():
            t._stop_process()
        # self._sig_stop(self.pid)
        # self.wait()
        # self.running = False

    def handle_stop(self):
        pass

    def handle_exit(self):
        pass

    def _enforce_stop(self):
        # Can we trust self.running without any check?
        stopped = False
        for tid, t in self.threads.items():
            stopped |= t._enforce_stop()
        return stopped

    def _is_next_instr_call(self):
        rip = self.rip
        #fetch 6 bytes. 5 should be enough
        code = self.mem[rip: rip+6]
        #maybe we should check if it is 32 or 64 mode
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        (address, size, mnemonic, op_str) = next(md.disasm_lite(code, 0x1000))
        if mnemonic == "call":
            return True
        return False

    # I have to disable it for now... ToO active without handlers
    def _option_setup(self):
        #PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, PTRACE_O_TRACECLONE and PTRACE_O_TRACEEXIT
        self.ptrace.setoptions(self.pid, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT)
    
    def set_option(self, option):
        self.ptrace.setoptions(self.pid, option)

    ### Attach/Detach
    def run(self, path, args=[], sleep=None):
        # Gdb does tons of configuration when setting up a new process start
        # For now this is a simple as I can write it
        self.pid = self.ptrace.run(path, args)
        self.cur_tid = self.pid
        t = ThreadDebug(self.pid, self.ptrace)
        self.threads[self.pid] = t
        logging.info("new process <%d> %r", self.pid, args)
        logging.debug("waiting for child process %d", self.pid)
        self.should_exit = False # Se per qualche ragione vorresti tenere lo stesso Debugger per più analisi
        self.exited.clear()
        Thread(target=self._constant_wait, daemon=True).start() 
        self.wait()
        self._option_setup()
        if sleep is not None:
            self.cont(blocking=False)
            time.sleep(sleep)
            self._sig_stop(self.pid)

    def attach(self, pid, options=True):
        """
        Attach to a process using the pid
        """
        logging.info("attaching to pid %d", pid)      
        self.pid = pid
        self.cur_tid = pid

        try:
            self.ptrace.attach(pid)
        except PtraceFail:
            return False

        t = ThreadDebug(pid, self.ptrace)
        self.threads[pid] = t
        self.should_exit = False # Se per qualche ragione vorresti tenere lo stesso Debugger per più analisi
        self.exited.clear()
        Thread(target=self._constant_wait, daemon=True).start()
        self.wait()
        if options:
            self._option_setup()
        return True

    def reattach(self):
        """
        Reattach to the last process. This works only after detach.
        """

        logging.debug("RE-attaching to pid %d", self.old_pid)             
        if self.old_pid is None:
            raise DebugFail("ReAttach Failed. You never attached before! Use attach or run first. and detach")
        while True:
            try:
                self.attach(self.old_pid)
                self._option_setup()
                return
            except:
                logging.debug("Failed to attach")
                time.sleep(0.5)

    def detach(self):
        """
        Detach the current process

        The process dosn't restart if detach is called while at a stop.
        """
        # Mi devo assicurare che il thread di wait noti che siamo usciti altrimenti non potrò fare un nuovo attach. Quindi il processo deve interrompersi una volta dopo aver settato should_exit
        # Per il momento funziona bene solo in siglethread. Per farlo funzionare su più thread ci sono due strade: trovare come implementare un waitpid in ogni ThreadDebugger identificando correttamente i nuovi thread oppure tenendo l'ultimo thread e chiudere constant_wait solo quando facciamo detach di quel thread.
        self.should_exit = True
        for tid, thread in list(self.threads.items()):
            thread.detach()
            # Controlla che ti vada bene questo. Il mio obbiettivo è evitare che self.shutdown dopo un detach possa hangare. Il problema viene dal fatto che test_running non fa la differenza tra un processo che runna e un processo che non tracci.
            del self.threads[tid]
        # Settare pid = None troppo presto rompe waitpid
        self.exited.wait()
        if self.pid is not None:
            self.old_pid = self.pid
            self.pid = None

    def shutdown(self):
        """
        This sto the execution of the process executed with `run`
        """
        self.detach()
        os.kill(self.old_pid, signal.SIGKILL)
        if self.process is not None:
            os.kill(self.old_pid, signal.SIGKILL)
            self.detach()
            # self.process.terminate()
            # self.process.kill()
            os.kill(self.old_pid, signal.SIGKILL)


    def gdb(self, spawn=False):
        """
        Migrate the dubugging to gdb
        """

        #Stop the process so you can continue exactly form where you let in the script
        for tid in self.threads:
            # thread._enforce_stop() would be enough with the new detach(), but since multiple signals are blocked sending SIGSTOP if we are already at a stop won't bother us. 
            self._sig_stop(tid)
        #detach
        pid = self.pid
        self.detach()
        #correctly identify the binary
        # pwndbg example startup
        # gdb -q /home/jinblack/guesser/guesser 2312 -x "/tmp/tmp.Zo2Rv6ane"
        
        # Signal is already stopped but gdb send another SIGSTOP `-ex signal SIGCONT` 
        # will get read of on STOP with a continue
        bin = '/bin/gdb'
        args = ['-q', "--pid", "%d" % pid, "-ex", "signal SIGCONT"]
        if spawn:
            cmd_arr =  self.terminal + ["sudo", bin] + args
            cmd = " ".join(cmd_arr)
            logging.debug("system %s", cmd)
            os.system(cmd)
        else:
            os.execv(bin, args)




    ## Memory

    def peek(self, addr):
        self._check_mem_address(addr)
        self._enforce_stop()
        # according to man ptrace no difference for PTRACE_PEEKTEXT and PTRACE_PEEKDATA on linux
        data = self.ptrace.peek(self.pid, addr)
        return data
    
    def poke(self, addr, value):
        self._check_mem_address(addr)
        self._enforce_stop()
        # according to man ptrace no difference for PTRACE_POKETEXT and PTRACE_POKEDATA on linux
        self.ptrace.poke(self.pid, addr, value)

 
    def _base_guess(self):
        if len(self.map) == 0:
            logging.warning("Failed to guess the bases.")
            return

        self.bases["main"] = min([m for m in self.map if self.map[m]['file'] is not None])
        logging.debug("new base main guessed at %#x", self.bases["main"])

        for m in self.map:
            if self.map[m]['offset'] == 0 and self.map[m]['file'] is not None:
                name = self.map[m]['file']
                self.bases[name] = m
                logging.debug("new base %s guessed at %#x", name, m)

    def _retrieve_maps(self):
        # map file example
        # 560df069c000-560df069d000 r--p 00000000 fe:01 4859834                    /usr/bin/python3.10
        # 55c1b7eaf000-55c1b7eb0000 r--p 00000000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 55c1b7eb0000-55c1b7eb1000 r-xp 00001000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 55c1b7eb1000-55c1b7eb2000 r--p 00002000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 55c1b7eb2000-55c1b7eb3000 r--p 00002000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 55c1b7eb3000-55c1b7eb4000 rw-p 00003000 00:19 28246290                   /home/jinblack/Projects/libdebug/tests/test
        # 7f7fd6b48000-7f7fd6b4a000 rw-p 00000000 00:00 0 
        # 7f7fd6b4a000-7f7fd6b76000 r--p 00000000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6b76000-7f7fd6cec000 r-xp 0002c000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6cec000-7f7fd6d40000 r--p 001a2000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6d40000-7f7fd6d41000 ---p 001f6000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6d41000-7f7fd6d44000 r--p 001f6000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6d44000-7f7fd6d47000 rw-p 001f9000 00:19 9051255                    /usr/lib/libc.so.6
        # 7f7fd6d47000-7f7fd6d56000 rw-p 00000000 00:00 0 
        # 7f7fd6d96000-7f7fd6d98000 r--p 00000000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7f7fd6d98000-7f7fd6dbf000 r-xp 00002000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7f7fd6dbf000-7f7fd6dca000 r--p 00029000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7f7fd6dcb000-7f7fd6dcd000 r--p 00034000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7f7fd6dcd000-7f7fd6dcf000 rw-p 00036000 00:19 9051246                    /usr/lib/ld-linux-x86-64.so.2
        # 7ffcc2eef000-7ffcc2f10000 rw-p 00000000 00:00 0                          [stack]
        # 7ffcc2fab000-7ffcc2faf000 r--p 00000000 00:00 0                          [vvar]
        # 7ffcc2faf000-7ffcc2fb1000 r-xp 00000000 00:00 0                          [vdso]
        # ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
        l_regx = "(?P<start>[0-9a-f]+)-(?P<stop>[0-9a-f]+)\s+(?P<read>[r-])(?P<write>[w-])(?P<exec>[x-])([p-])\s+(?P<offset>[0-9a-f]+)\s+[0-9a-f]+:[0-9a-f]+\s+(?P<inode>[0-9]+)\s+(?P<pathname>\/.*[\w:]+|\[\w+\])?"
        pid = self.pid
        logging.debug("Retrieving mem maps")
        with open(f"/proc/{pid}/maps", 'r') as f:
            self.map = {}
            for l in f.readlines():
                m = re.match(l_regx, l)
                if m is None:
                    logging.warning("Failed loading map table: %s", l)
                    continue
                md = m.groupdict()
                perm = 4 if md['read']  == 'r' else 0 \
                     + 2 if md['write'] == 'w' else 0 \
                     + 1 if md['exec']  == 'x' else 0
                start = int(md['start'], 16)
                stop = int(md['stop'], 16)
                offset = int(md['offset'], 16)

                segment = {"start": start, 
                           "stop": stop,
                           "perms": perm,
                           "offset": offset, 
                           "pathname": md['pathname'],
                           "file": os.path.basename(md['pathname'])  if md['pathname'] is not None else None}
                self.map[start] = segment
        self._base_guess()

    def _check_mem_address(self, addr, warn=True):
        for m in self.map:
            if self.map[m]['start'] <= addr < self.map[m]['stop']:
                return True
        if warn:
            logging.warning("The address %#x is outside any memory reagion", addr)
        return False

    ## Control Flow
    def _set_breakpoints(self):
        for b in self.breakpoints:
            self.breakpoints[b] = self.mem[b]
            self.mem[b] = b"\xcc"

    def _retore_breakpoints(self):
        # Some time this stop exactly before the execution of the bp some time after.
        if self.rip not in self.breakpoints and self.rip-1 in self.breakpoints:
            self.rip -= 1
        for b in self.breakpoints:
            if self.breakpoints[b] != None:
                self.mem[b] = self.breakpoints[b]
                self.breakpoints[b] = None

    # step that won't send a message to the user.
    def __hidden_step(self):
        self.__flag_hidden_step = True
        self.step()

    #** Non ho capito perchè fai step di tutti i thread e non solo di quello su cui stai lavorando
    def step(self):
        """
        Execute the next instruction (Step Into)
        """
        self._enforce_stop()
        self.stopped.clear()    
        self.__last_action = "step"
        for tid, t in self.threads.items():
            t.step()

    def next(self):
        self._enforce_stop()
        if not self._is_next_instr_call():
            return self.__hidden_step()
        self.step()
        #if 32 bits this do not works
        saved_rip = u64(self.mem[self.rsp:self.rsp+self.reg_size])
        logging.debug("next on a call instruction, executing until %#x", saved_rip)
        #should we have a separate set of breakpoints?
        bp = self.breakpoint(saved_rip)
        self.cont()
        #this will couse the remove of an old break point placed in that part
        self.del_bp(bp)
        # input("next real done")

    def step_until(self, rip):
        """
        Execute using single step until the value of rip is equal to the argument
        """

        #Maybe punt a max stept or a timeout
        while True:
            self.step()
            if self.rip == rip:
                break

    def cont(self, blocking=True):
        """
        Continue the execution until the next breakpoint is hitted or the program is stopped
        """

        #I need to execute at least another instruction otherwise I get always in the same bp
        self.__hidden_step()
        self._set_breakpoints()
        self.running = True
        self.stopped.clear()
        self.__last_action = "continue"
        # Probably should implement a timeout
        # while self.running:
        for tid, t in self.threads.items():
            if t.stopped.is_set(): # if not t.running: 
                t.cont()
        if blocking:
            self.wait()
            logging.debug("Continue Stopped")

    def finish(self, blocking=True):
        """
        Execute until the end of the current function.
        This works only if the program use the rbp register as base address.
        """
        # This works only if the binary use the baseptr for the frames
        if not self._check_mem_address(self.rbp):
            logging.error("rbp %#x is not a valid frame. Impossible to execute finish", self.rbp)
            raise DebugFail("Finish Failed. Frame not found")
        ret_addr = u64(self.mem[self.rbp+0x8: self.rbp+0x10])
        logging.info("finish executing until Return Address found at %#x", ret_addr)
        self.bp(ret_addr)
        self.cont(blocking)
        self.del_bp(ret_addr)

    def bp(self, addr):
        """
        Set a breakpoint to specific address
        """
        if addr not in self.breakpoints:
            self._check_mem_address(addr)
            logging.info("new BreakPoint at %#x", addr)
            self.breakpoints[addr] = None
        return addr

    def _resolve_relative_address(self, addr, name):
        if name is None and self._check_mem_address(addr, warn=False):
            return addr
        # BP not found as valid address.
        if name is None:
            name = "main"
        #Look for the lib that start with that name
        if name not in self.bases:
            for x in self.bases:
                if x.startwith(name):
                    name = x
                    break
        # did not find any valid region. Try standard bp
        if name not in self.bases:
            return addr
        # compute and set the bp
        logging.info("relative address, region: %s, start:%#x", name, self.bases[name])
        return self.bases[name] + addr

    def watch(self, addr, cond='W', length=8, name=None):
        #normalize the condition
        if "W" in cond or "w" in cond:
            cond = "W"
        if "R" in cond or "r" in cond:
            cond = "RW"

        real_address = self._resolve_relative_address(addr, name)
        logging.info("Watchpoint: %#lx, cond %s", real_address, cond)
        if len(self.threads) > 1:
            logging.warning("There are more threads. I am setting the BP only for the main thread.")
        t = self.threads[self.pid]
        if t.hw_bp(real_address, cond=cond, length=length):
            return real_address
        logging.info("Failed to set hw breakpoint. Watchpoint was not setup")

    def del_watch(self, addr):
        self.del_bp(addr)

    def breakpoint(self, addr, name=None, hw=False):
        real_address = self._resolve_relative_address(addr, name)
        logging.info("Breakpoint: %#lx", real_address)
        if hw:
            if len(self.threads) > 1:
                logging.warning("There are more threads. I am setting the BP only for the main thread.")
            t = self.threads[self.pid]
            if t.hw_bp(real_address, cond='X'):
                return real_address
            logging.info("Failed to set hw breakpoint. Fall back to memory bp.")
        return self.bp(real_address)

    def del_bp(self, addr):
        """
        Remove the breakpoint
        """
        if addr in self.breakpoints:
            logging.info("delete BreakPoint at %#x", addr)
            del self.breakpoints[addr]
        else:
            t = self.threads[self.pid]
            t.del_hw_bp(addr)


    ## THREADS
    # https://stackoverflow.com/questions/7290018/ptrace-and-threads
    # https://stackoverflow.com/questions/18577956/how-to-use-ptrace-to-get-a-consistent-view-of-multiple-threads
    def _get_thread_area(self, tid):
        
        self._enforce_stop()

        self.libc.ptrace.argtypes = self.args_ptr

        #clean buffer. Probably there is a better way.
        for x in range(100):
             self.buf[x] = b"\x00"

        set_errno(0)
        if (self.libc.ptrace(PTRACE_GET_THREAD_AREA, self.pid, tid, self.buf) == -1):
            for x in range(100):
                print(self.buf[x])
            err = get_errno()
            #We use geT_regs as test for the process if it is running we may stoppit before executing something
            # ether the process is dead or is running
            if err == errno.ESRCH and self.running:
                #we should stop the process.
                return None
            elif err == errno.ESRCH and not self.running:
                logging.critical("The proccess is dead!")
            else:
                logging.debug("getregs error: %d", err)
                raise DebugFail("GetThreadArea Failed. is tid correct?")
        print(self.buf)
        return self.buf
