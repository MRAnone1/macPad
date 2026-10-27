"""Invented adapter fixtures, real self-owned host FD tests and child pipes only.

No device/native queries. FakeInputs is deliberately not historical authority;
retained_inputs tests independently exercise the pinned real v7 validators.
"""
import base64
from contextlib import ExitStack,redirect_stdout
import copy
import ctypes
import errno
import importlib.util
import io
import os
from pathlib import Path
import plistlib
import signal
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
MISC=HERE
sys.path.insert(0,str(MISC))
from macws_swap_pair import retained_observer as o
from macws_swap_pair import runtime_support as rs
spec=importlib.util.spec_from_file_location("synthetic_signed_observer_fixture",MISC/"test_macws_swap_pair_observer.py")
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
RAW=f.SYNTHETIC_BINARY
SIGNATURE=o.readonly.code_signature(RAW)
ROOTLESS="/private/preboot/synthetic/procursus"


def forbidden(*args,**kwargs):raise AssertionError("unexpected capability")


def record(ino=1,size=64,mode=0o700,kind="directory"):
    return {"dev":7,"ino":ino,"size":size,"mtime_ns":1000,"ctime_ns":2000,
            "mode":mode,"uid":0,"gid":0,"nlink":2 if kind=="directory" else 1,"kind":kind}


def token(info):return {k:v for k,v in info.items() if k!="kind"}


class FakeInputs:
    def __init__(self):
        self.context={"boot_private":"11111111-2222-3333-4444-555555555555","config_sha256":"a"*64,
                      "source_sha256":dict(o.cleanup.SOURCES),"retired_birth_private":[401,1000,5],
                      "UI_private":{"SpringBoard":[101,1000,1],"backboardd":[102,1000,2]},
                      "expected_file_sha256":{"job.plist":o.cleanup.digest(b"invented plist"),"probe.log":o.cleanup.digest(b"invented log")},
                      "exclusive_operator":True}
        self.expected_files={"job.plist":b"invented plist","probe.log":b"invented log"}
        self.original=SimpleNamespace(runtime=rs,config={"operation":"control_normal"})
        self.provenance_base={k:"b"*64 for k in o.cleanup.PROVENANCE_KEYS if k!="current_wire_sha256"}
        self.provenance_base["effective_config_sha256"]=self.context["config_sha256"]
        self.delivery={"created_directories_private":[{"path":o.CONTROLLER_DIR,"stat":token(record(20))},
            {"path":rs.ROOTFS+rs.executable({"arch":"arm64"}).rsplit("/",1)[0],"stat":token(record(21))}],
            "parents_private":[{"logical":"/var/jb/usr/libexec","resolved":ROOTLESS+"/usr/libexec","stat":token(record(10))}],
            "probe_signature":dict(SIGNATURE),"installed_files_private":[]}
        self.artifacts={}
        for index,name in enumerate(("controller.py","runtime_support.py","watchdog.py","offline-QA.canonical.private.json","probe.arm64")):
            directory=self.delivery["created_directories_private"][name=="probe.arm64"]["path"]
            path=directory+"/"+name
            raw=RAW if name=="probe.arm64" else ("invented "+name).encode()
            row={"name":name,"path":path,"stat":token(record(30+index,len(raw),0o755 if name=="probe.arm64" else 0o600,"regular")),"sha256":o.cleanup.digest(raw)}
            self.delivery["installed_files_private"].append(row)
            self.artifacts[path]=(raw,{**row["stat"],"kind":"regular"})
    def intact(self):return True


class FakeBackend:
    def __init__(self,inputs):
        self.inputs=inputs;self.time=100.0;self.commands=[];self.queries=[]
        self.command_bytes=0;self.native_count=0;self.clock_reads=0
        self.mutate=lambda phase:None
        self.rawlink=ROOTLESS+"/"
    def now(self):return self.time
    def metadata(self,name):
        self.mutate("metadata")
        return {"hw.machine":"iPad13,6","kern.osversion":"20E252","kern.uuid":"d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb","kern.bootsessionuuid":self.inputs.context["boot_private"]}[name]
    def thermal(self):self.mutate("thermal");return 0
    def command(self,argv,deadline):
        o.readonly.readonly_command_allowed(argv)
        self.mutate("command")
        if argv[0]=="/bin/ps":value=(0,"  PID COMM\n101 /System/SpringBoard\n102 /System/backboardd\n","")
        elif argv[1]=="print":value=f.absent(argv[-1].split("/")[-1])
        else:value=(0,"Jailbreak Trustcache 0 <UUID: "+"1"*32+"> (length: 1)\n| 1: "+SIGNATURE["cdhash"]+"\n","")
        self.commands.append({"argv_private":argv,"result_private":value});return value
    def process(self,pid,deadline):
        name="SpringBoard" if pid==101 else "backboardd"
        return {"path":"/System/"+name,"birth_private":list(self.inputs.context["UI_private"][name]),"stopped":False}
    def generation(self,birth,deadline):
        self.mutate("generation")
        return {"api":"proc_pidinfo","flavor":3,"requested_bytes":136,"returned":0,"errno":errno.ESRCH,
                "pid_private":birth[0],"expected_birth_private":list(birth),"outcome":"ESRCH"}
    def lstat(self,path):
        if path==o.RUN_SCRATCH:raise FileNotFoundError(path)
        self.mutate("anchor")
        return SimpleNamespace(st_dev=7,st_ino=99,st_size=len(self.rawlink),st_mtime_ns=1,st_ctime_ns=2,
                               st_mode=0o120777,st_uid=0,st_gid=0,st_nlink=1)
    def readlink(self,path):return self.rawlink
    def directory_stat(self,path):return record(10)
    def directory(self,path):
        logical="/var/jb"+path[len(ROOTLESS):] if path.startswith(ROOTLESS) else path
        row=next(x for x in self.inputs.delivery["created_directories_private"] if x["path"]==logical)
        names=sorted(x["name"] for x in self.inputs.delivery["installed_files_private"] if x["path"].rsplit("/",1)[0]==logical)
        return {**row["stat"],"kind":"directory"},names
    def read(self,path,limit):
        self.mutate("read")
        logical="/var/jb"+path[len(ROOTLESS):] if path.startswith(ROOTLESS) else path
        if path.endswith("SystemVersion.plist"):
            raw=plistlib.dumps({"ProductVersion":"13.4","ProductBuildVersion":"22F66"})
            return raw,record(70,len(raw),0o644,"regular")
        if logical in self.inputs.artifacts:return self.inputs.artifacts[logical]
        return RAW,record(80,len(RAW),0o755,"regular")


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.inputs=FakeInputs();self.backend=FakeBackend(self.inputs)
        deps={name:{"path":value["path"],"sha256":o.cleanup.digest(RAW),"architecture":SIGNATURE["architecture"],"uuid":SIGNATURE["uuid"]}for name,value in o.readonly.DEPENDENCIES.items()}
        p=patch.object(o.readonly,"DEPENDENCIES",deps);p.start();self.addCleanup(p.stop)
        self.observer=o.Observer(self.inputs,self.backend)
    def observe(self):return self.observer.observe("c"*64,"d"*64,108)
    def test_complete_invented_gates_preserve_oldest_time_and_no_authority(self):
        with patch.object(ctypes,"CDLL",forbidden),patch.object(os,"unlink",forbidden),patch.object(os,"kill",forbidden):gate=self.observe()
        self.assertEqual(gate["observed_monotonic"],100.0)
        self.assertEqual(len(self.backend.commands),4)
        self.assertFalse(self.observer.report()["cleanup_authorized"])
        self.assertTrue(self.observer.observations[-1]["completed"])
    def test_caller_deadline_may_be_later_but_cannot_extend_observer_global_deadline(self):
        self.backend.time=100.25
        gate=self.observer.observe("c"*64,"d"*64,108.25)
        self.assertEqual(gate["observed_monotonic"],100.25)
        self.assertEqual(self.observer.deadline,108.0)

    def test_real_archive_Cleaner_and_observer_API_interoperate_with_constructor_delay(self):
        from macws_swap_pair import retained_archive
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();path=root/"selection";path.mkdir(mode=0o700)
            for name,raw in self.inputs.expected_files.items():(path/name).write_bytes(raw);(path/name).chmod(0o600)
            wire=b'{"invented_capture":true}\n'
            provenance=dict(self.inputs.provenance_base,current_wire_sha256=o.cleanup.digest(wire))
            with patch.object(o.cleanup,"TARGET",str(path)),patch.object(o.cleanup,"OWNER",(os.geteuid(),os.getegid())):
                selection=o.cleanup.capture_selection(self.inputs.context)
                receipt=retained_archive.archive_bytes(root,"archive",wire=wire,manifest=selection["manifest"],provenance=provenance,files=self.inputs.expected_files)
                cleaner=o.cleanup.Cleaner(selection["manifest"],provenance,receipt,self.inputs.context,self.inputs.expected_files)
                self.backend.time=100.25
                result=cleaner.execute_once(self.observer)
            self.assertTrue(result["cleanup_verified"])
            self.assertFalse(result["device_acceptance"])
            self.assertEqual(len(self.observer.observations),5)
            self.assertFalse(path.exists())

    def test_declared_rootless_single_trailing_slash_is_pinned_literally(self):
        self.observe();self.backend.rawlink=ROOTLESS
        with self.assertRaises(o.cleanup.Refused):self.observe()
        self.assertFalse(self.observer.observations[-1]["completed"])
    def test_unrelated_rootless_target_and_multiple_slashes_refuse(self):
        for value in ("/private/preboot/foreign/procursus",ROOTLESS+"//"):
            self.backend.rawlink=value
            with self.subTest(value=value),self.assertRaises(o.cleanup.Refused):self.observe()
    def test_rootless_parent_token_changed_refuses(self):
        self.backend.directory_stat=lambda p:record(999)
        with self.assertRaises(o.cleanup.Refused):self.observe()
    def test_malformed_process_line_refuses_and_copies_offending_text(self):
        original=self.backend.command
        def command(argv,deadline):return (0,"PID COMM\nmalformed\n","")if argv[0]=="/bin/ps"else original(argv,deadline)
        self.backend.command=command
        with self.assertRaises(o.readonly.Refused):self.observe()
        self.assertIn("malformed",self.observer.observations[-1]["process_command_private"][1])
    def test_every_blocked_basename_is_checked(self):
        original=self.backend.command
        for name in o.readonly.BLOCKED_BASENAMES:
            def command(argv,deadline):
                value=original(argv,deadline)
                return (0,value[1]+"500 /synthetic/"+name+"\n","")if argv[0]=="/bin/ps"else value
            self.backend.command=command
            with self.subTest(name=name),self.assertRaises(o.cleanup.Refused):
                o.Observer(self.inputs,self.backend).observe("c"*64,"d"*64,108)
    def test_UI_wrong_birth_refuses(self):
        self.backend.process=lambda pid,deadline:{"path":"/System/SpringBoard","birth_private":[pid,9999,1],"stopped":False}
        with self.assertRaises(o.cleanup.Refused):self.observe()
    def test_uncertain_generation_is_retained_before_refusal(self):
        self.backend.generation=lambda b,d:{"api":"proc_pidinfo","flavor":3,"requested_bytes":136,"returned":0,"errno":errno.EIO,"pid_private":b[0],"expected_birth_private":b,"outcome":"uncertain"}
        with self.assertRaises(o.cleanup.Refused):self.observe()
        self.assertEqual(self.observer.observations[-1]["generation_absence_private"]["errno"],errno.EIO)
    def test_present_other_scratch_refuses(self):
        original=self.backend.lstat
        self.backend.lstat=lambda path:SimpleNamespace()if path==o.RUN_SCRATCH else original(path)
        with self.assertRaises(o.cleanup.Refused):self.observe()
    def test_float_thermal_cannot_be_nominal(self):
        self.backend.thermal=lambda:0.0
        with self.assertRaises(o.cleanup.Refused):self.observe()
    def test_extra_delivery_child_refuses(self):
        original=self.backend.directory
        self.backend.directory=lambda p:(original(p)[0],original(p)[1]+["foreign"])
        with self.assertRaises(o.cleanup.Refused):self.observe()
        self.assertIn("foreign",self.observer.observations[-1]["delivery_directories_private"][0]["entries_private"])
    def test_changed_delivered_content_keeps_actual_hash(self):
        path=next(iter(self.inputs.artifacts));raw,stat=self.inputs.artifacts[path]
        self.inputs.artifacts[path]=(b"x"*len(raw),stat)
        with self.assertRaises(o.cleanup.Refused):self.observe()
        self.assertEqual(self.observer.observations[-1]["artifacts_private"][path]["sha256"],o.cleanup.digest(b"x"*len(raw)))
    def test_malformed_trust_text_kept_before_parser_refuses(self):
        original=self.backend.command
        self.backend.command=lambda a,d:(0,"truncated","")if a[1]=="trustcache"else original(a,d)
        with self.assertRaises(o.readonly.Refused):self.observe()
        self.assertEqual(self.observer.observations[-1]["trust_command_private"][1],"truncated")
    def test_file_read_delay_is_not_reported_as_fresh_end_timestamp(self):
        self.backend.mutate=lambda phase:setattr(self.backend,"time",self.backend.time+.15)if phase=="read"else None
        with self.assertRaises(o.cleanup.Refused):self.observe()
        self.assertEqual(self.observer.observations[-1]["started_monotonic_private"],100.0)
    def test_regressing_clock_and_global_deadline_refuse(self):
        self.backend.time=99
        with self.assertRaises(o.cleanup.Refused):self.observe()
    def test_copied_byte_budget_fails_closed_before_read(self):
        self.observer.read_bytes=o.LIMITS["read_bytes"]
        with patch.object(self.backend,"read",forbidden),self.assertRaises(o.cleanup.Refused):self.observe()
    def test_observation_count_budget_fails_before_new_queries(self):
        self.observer.observations=[{}]*o.LIMITS["observations"]
        with patch.object(self.backend,"metadata",forbidden),self.assertRaises(o.cleanup.Refused):self.observe()
    def test_UI_duplicate_row_refuses(self):
        original=self.backend.command
        def command(a,d):
            value=original(a,d)
            return (0,value[1]+"103 /System/SpringBoard\n","")if a[0]=="/bin/ps"else value
        self.backend.command=command
        with self.assertRaises(o.cleanup.Refused):self.observe()
    def test_UI_stopped_refuses(self):
        original=self.backend.process
        def process(pid,deadline):return dict(original(pid,deadline),stopped=True)
        self.backend.process=process
        with self.assertRaises(o.cleanup.Refused):self.observe()
    def test_stat_equal_float_cannot_match_original_integer(self):
        original=self.backend.read
        def read(path,limit):
            raw,info=original(path,limit);info=dict(info,size=float(info["size"]));return raw,info
        self.backend.read=read
        with self.assertRaises(o.cleanup.Refused):self.observe()
    def test_selection_capture_copies_are_preserved_when_content_changes(self):
        with tempfile.TemporaryDirectory()as temp:
            path=Path(temp).resolve()/"selection";path.mkdir(mode=0o700)
            for name,raw in self.inputs.expected_files.items():(path/name).write_bytes(raw);(path/name).chmod(0o600)
            with patch.object(o.cleanup,"TARGET",str(path)),patch.object(o.cleanup,"OWNER",(os.geteuid(),os.getegid())):
                def changed(context):
                    (path/"probe.log").write_bytes(b"different current diagnostic log")
                    return o.read_selection(context)
                report=o.capture_observation(self.observer,changed)
            self.assertFalse(report["capture_completed"])
            self.assertEqual(base64.b64decode(report["selection_copies_private"][0]["files_private"]["probe.log"]),b"different current diagnostic log")
    def test_two_copy_capture_is_not_final_cleanup_provenance(self):
        with tempfile.TemporaryDirectory()as temp:
            path=Path(temp).resolve()/"selection";path.mkdir(mode=0o700)
            for name,raw in self.inputs.expected_files.items():(path/name).write_bytes(raw);(path/name).chmod(0o600)
            with patch.object(o.cleanup,"TARGET",str(path)),patch.object(o.cleanup,"OWNER",(os.geteuid(),os.getegid())):
                report=o.capture_observation(self.observer)
            self.assertTrue(report["capture_completed"])
            self.assertEqual(len(report["selection_copies_private"]),2)
            self.assertFalse(report["cleanup_authorized"])
            self.assertTrue(report["capture_only_not_cleanup_admission"])
            self.assertNotIn("current_wire_sha256",self.inputs.provenance_base)


class PhysicalReadTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="synthetic-physical-read-");self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.path=self.root/"file";self.path.write_bytes(b"invented")
    def test_regular_read_returns_full_stat_and_exactbytes(self):
        raw,info=o.nofollow_read(str(self.path),32);self.assertEqual(raw,b"invented");self.assertEqual(info["nlink"],1)
    def test_leaf_and_intermediate_symlinks_refuse(self):
        alias=self.root/"alias";alias.symlink_to(self.path)
        with self.assertRaises(OSError):o.nofollow_read(str(alias),32)
        (self.root/"dir").mkdir();(self.root/"dir/file").write_bytes(b"invented")
        alias.unlink();alias.symlink_to(self.root/"dir",target_is_directory=True)
        with self.assertRaises(OSError):o.nofollow_read(str(alias/"file"),32)
    def test_hardlink_and_FIFO_refuse_without_peer_wait(self):
        os.link(self.path,self.root/"link")
        with self.assertRaises(o.cleanup.Refused):o.nofollow_read(str(self.path),32)
        fifo=self.root/"fifo";os.mkfifo(fifo)
        actual=os.open
        def guarded(path,flags,*args,**kwargs):
            if path=="fifo":self.assertTrue(flags&os.O_NONBLOCK)
            return actual(path,flags,*args,**kwargs)
        with patch.object(os,"open",guarded),self.assertRaises(o.cleanup.Refused):o.nofollow_read(str(fifo),32)
    def test_shortreads_are_collected_and_prematureEOF_refuses(self):
        actual=os.read
        with patch.object(os,"read",lambda fd,size:actual(fd,min(size,2))):self.assertEqual(o.nofollow_read(str(self.path),32)[0],b"invented")
        with patch.object(os,"read",return_value=b""),self.assertRaises(o.cleanup.Refused):o.nofollow_read(str(self.path),32)
    def test_intermediate_symlink_substitution_during_read_refuses_even_same_destination(self):
        directory=self.root/"nested";directory.mkdir();path=directory/"file";path.write_bytes(b"invented")
        original=os.read;changed=False
        def read(fd,size):
            nonlocal changed
            result=original(fd,size)
            if not changed:
                changed=True;directory.rename(self.root/"retained");directory.symlink_to(self.root/"retained",target_is_directory=True)
            return result
        with patch.object(os,"read",read),self.assertRaises(o.cleanup.Refused):o.nofollow_read(str(path),32)
    def test_native_directory_method_rejects_intermediate_alias(self):
        (self.root/"dir").mkdir();(self.root/"alias").symlink_to(self.root/"dir",target_is_directory=True)
        with self.assertRaises(OSError):o.NativeReadOnlyBackend.directory(object(),str(self.root/"alias"))


class Call:
    def __init__(self,callback):self.callback=callback
    def __call__(self,*args):return self.callback(*args)


class NativeCopyTests(unittest.TestCase):
    def backend(self,returned=136,error=0,pid=401,seconds=1000):
        backend=o.NativeReadOnlyBackend.__new__(o.NativeReadOnlyBackend)
        backend.clock=SimpleNamespace(now=lambda:100.0);backend.clock_reads=0;backend.commands=[];backend.queries=[]
        backend.native_count=0;backend.command_bytes=0
        raw=bytearray(136);struct.pack_into("<I",raw,4,2);struct.pack_into("<I",raw,12,pid);struct.pack_into("<QQ",raw,120,seconds,5)
        def query(_pid,_flavor,_arg,buf,size):ctypes.memmove(buf,bytes(raw),min(136,max(0,returned)));ctypes.set_errno(error);return returned
        def path(_pid,buf,size):data=b"/System/SpringBoard\0";ctypes.memmove(buf,data,len(data));return len(data)
        backend.proc=SimpleNamespace(proc_pidinfo=Call(query),proc_pidpath=Call(path));return backend
    def test_ESRCH_keeps_exact_metadata_and_no_invented_rawblock(self):
        backend=self.backend(0,errno.ESRCH)
        self.assertEqual(backend.generation([401,1000,5],108)["outcome"],"ESRCH")
        self.assertEqual(backend.queries[0]["raw_bsdinfo_private_hex"],"")
    def test_reused_PID_and_short_query_keep_actual_raw_before_refusal(self):
        for returned,seconds in ((136,9999),(80,1000)):
            backend=self.backend(returned,0,401,seconds)
            with self.assertRaises(o.cleanup.Refused):backend.generation([401,1000,5],108)
            self.assertEqual(len(bytes.fromhex(backend.queries[0]["raw_bsdinfo_private_hex"])),returned)
            if returned==136:self.assertEqual(backend.queries[0]["observed_birth_private"],[401,9999,5])
    def test_UI_native_copy_retains_BSD_and_path_blocks(self):
        backend=self.backend();value=backend.process(401,108)
        self.assertEqual(value["birth_private"],[401,1000,5]);self.assertFalse(value["stopped"])
        self.assertEqual(len(bytes.fromhex(backend.queries[0]["raw_bsdinfo_private_hex"])),136)
        self.assertIn("path_private_b64",backend.queries[0])
    def test_fixed_command_allowlist_refuses_all_effects_before_Popen(self):
        backend=self.backend()
        for argv in ([rs.LAUNCHCTL,"kill","SIGKILL",o.cleanup.SERVICES[0]],[rs.JBCTL,"trustcache","add","file"],["/bin/sh","-c","true"]):
            with patch.object(subprocess,"Popen",forbidden),self.assertRaises(o.readonly.Refused):backend.command(argv,108)
    def test_streaming_invalid_utf8_retains_exit_and_original_bytes(self):
        backend=self.backend();backend.clock=SimpleNamespace(now=time.monotonic)
        actual=subprocess.Popen
        def popen(argv,**kwargs):return actual([sys.executable,"-c","import os;os.write(1,b'\\xff')"],**kwargs)
        with patch.object(subprocess,"Popen",popen),self.assertRaises(UnicodeError):backend.command(["/bin/ps","-eo","pid,comm"],time.monotonic()+3)
        self.assertTrue(backend.commands[0]["result_known"])
        self.assertEqual(base64.b64decode(backend.commands[0]["stdout_private_b64"]),b"\xff")
    def test_streaming_output_limit_preserves_prefix_and_refuses(self):
        backend=self.backend();backend.clock=SimpleNamespace(now=time.monotonic);actual=subprocess.Popen
        def popen(argv,**kwargs):return actual([sys.executable,"-c","import os;os.write(1,b'x'*4096)"],**kwargs)
        with patch.object(subprocess,"Popen",popen),patch.dict(o.LIMITS,{"command_stdout":1024}),self.assertRaises(o.cleanup.Refused):backend.command(["/bin/ps","-eo","pid,comm"],time.monotonic()+3)
        self.assertGreater(len(base64.b64decode(backend.commands[0]["stdout_private_b64"])),1024)
        self.assertEqual(backend.commands[0]["error_category"],"Refused")
    def test_streaming_timeout_cleans_only_own_read_child_and_retains_prefix(self):
        backend=self.backend();backend.clock=SimpleNamespace(now=time.monotonic);actual=subprocess.Popen
        def popen(argv,**kwargs):return actual([sys.executable,"-c","import os,time;os.write(1,b'prefix');time.sleep(2)"],**kwargs)
        with patch.object(subprocess,"Popen",popen),patch.dict(o.LIMITS,{"command_seconds":.2}),self.assertRaises(o.cleanup.Refused):
            backend.command(["/bin/ps","-eo","pid,comm"],time.monotonic()+3)
        self.assertTrue(backend.commands[0]["child_cleanup_attempted"])
        self.assertFalse(backend.commands[0]["result_known"])
        self.assertEqual(base64.b64decode(backend.commands[0]["stdout_private_b64"]),b"prefix")
    def test_import_and_default_CLI_have_no_native_IO_or_commands(self):
        source=(MISC/"macws_swap_pair/retained_observer.py").read_bytes()
        for name in ("synthetic_import","__main__"):
            output=io.StringIO()
            with ExitStack()as stack:
                for owner,attr in ((ctypes,"CDLL"),(os,"open"),(os,"unlink"),(os,"kill"),(subprocess,"Popen"),(signal,"setitimer")):
                    stack.enter_context(patch.object(owner,attr,forbidden))
                stack.enter_context(redirect_stdout(output));exec(compile(source,"<default>","exec"),{"__name__":name})
            self.assertEqual(bool(output.getvalue()),name=="__main__")


if __name__=="__main__":unittest.main()
