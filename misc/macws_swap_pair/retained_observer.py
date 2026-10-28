"""Default-inert, explicit read-only retained-artifact native adapter.

No worker/transport, job/probe execution, cleanup or authorization from JSON.
The native factory consumes the separately pinned historical Inputs builder.
All actual device use requires a reviewed bounded caller and current inventory.
"""
from __future__ import annotations
import base64
import ctypes
import errno
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import plistlib
import selectors
import stat
import struct
import subprocess

from macws_swap_pair import retained_cleanup as cleanup
from macws_swap_pair import readonly_observer as readonly

LIMITS = {"seconds": 8, "observations": 7, "read_bytes": 96*1024*1024,
          "command_count": 32, "command_seconds": 1,
          "command_stdout": 256*1024, "command_stderr": 16*1024,
          "all_command_bytes": 1024*1024, "native_queries": 128,
          "clock_reads": 8192, "max_gate_age": 1}
PINS = {"retained_cleanup.py": "da67d74855748fc60326a44073f51f9eb35186b5a4ed2fc2f2bbb55dc4d750c2",
        "readonly_observer.py": "717de31eb1d7a05ed363eca7c3dce0dbd7f4ff500bb8cb65377bd340babf1c7a"}
CONTROLLER_DIR = "/var/jb/usr/libexec/macws-swap-pair-controller-20261018"
ROOTFS = "/private/var/mnt/rootfs"
RUN_SCRATCH = "/private/var/tmp/macws-swap-pair-20261017"


def need(value, message):
    cleanup.need(value, message)


def finite(value):
    need(type(value) in (int,float) and math.isfinite(value) and value >= 0, "finite shared clock")
    return value


def typed_record(value,kind):
    cleanup.keys(value,cleanup.STAT_FIELDS)
    need(value["kind"]==kind and all(type(item)is int and 0<=item<1<<63
         for key,item in value.items() if key!="kind") and value["ino"]>0 and value["nlink"]>0,
         "strict complete native stat fields")
    return value


class PhysicalDirectory:
    """Hold and revalidate every physical path component; aliases refuse."""
    def __init__(self,path):
        self.chain=[]
        parts=PurePosixPath(path).parts
        need(parts and parts[0]=="/" and str(PurePosixPath(path))==path and
             all(x not in (".","..","") for x in parts[1:]),"literal absolute physical directory")
        try:
            self.add(None,os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK))
            for name in parts[1:]:
                self.add(name,os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.chain[-1][1]))
            self.fd=self.chain[-1][1];self.checked()
        except BaseException:
            self.close();raise

    def add(self,name,fd):
        try:record=cleanup.stat_record(os.fstat(fd))
        except BaseException:os.close(fd);raise
        self.chain.append((name,fd,record))

    def checked(self):
        for index,(name,fd,original) in enumerate(self.chain):
            current=cleanup.stat_record(os.fstat(fd))
            ident=lambda row:{k:row[k] for k in ("dev","ino","kind","mode","uid","gid")}
            need(current["kind"]=="directory" and ident(current)==ident(original),"held physical directory changed")
            entry=cleanup.stat_record(os.lstat("/")) if index==0 else cleanup.stat_record(
                os.stat(name,dir_fd=self.chain[index-1][1],follow_symlinks=False))
            need(ident(current)==ident(entry),"physical directory path or intermediate symlink changed")

    def close(self):
        for _,fd,_ in reversed(self.chain):os.close(fd)
        self.chain=[]


def nofollow_read(path,limit):
    """Complete physical no-follow chain; result is current observation only."""
    value=PurePosixPath(path)
    need(str(value)==path and value.name not in ("",".",".."),"literal physical file path")
    parent=PhysicalDirectory(str(value.parent));fd=None
    try:
        fd=os.open(value.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent.fd)
        before=cleanup.stat_record(os.fstat(fd))
        need(before["kind"]=="regular" and before["nlink"]==1 and 0<before["size"]<=limit,"bounded one-link regular artifact")
        data=bytearray()
        while len(data)<=before["size"]:
            block=os.read(fd,min(65536,before["size"]+1-len(data)))
            if not block:break
            data.extend(block)
        after=cleanup.stat_record(os.fstat(fd))
        need(before==after==cleanup.stat_record(os.stat(value.name,dir_fd=parent.fd,follow_symlinks=False)) and
             len(data)==before["size"],"stable complete artifact bytes")
        parent.checked();return bytes(data),before
    finally:
        if fd is not None:os.close(fd)
        parent.close()


class NativeReadOnlyBackend:
    """Explicit factory only. No method can mutate an existing job or process."""
    def __init__(self, original):
        rs=original.runtime
        self.clock=rs.NativeSharedClock()
        need(self.clock.profile==original.config["clock_info"],"shared clock profile")
        # Reuse only fixed metadata/thermal routines, not its command/parser/actions.
        self._primitive=rs.RealBackend(original.config,clock=self.clock)
        self.commands=[];self.queries=[];self.command_bytes=0;self.native_count=0
        self.proc=None;self.clock_reads=0

    def now(self):
        self.clock_reads+=1;need(self.clock_reads<=LIMITS["clock_reads"],"native shared clock count")
        return self.clock.now()

    def metadata(self,name):
        need(name in ("hw.machine","kern.osversion","kern.uuid","kern.bootsessionuuid"),"fixed metadata name")
        self.native_count+=1;need(self.native_count<=LIMITS["native_queries"],"native query budget")
        return self._primitive.metadata(name)

    def thermal(self):
        self.native_count+=1;need(self.native_count<=LIMITS["native_queries"],"native query budget")
        return self._primitive.thermal()

    def command(self,argv,deadline):
        readonly.readonly_command_allowed(argv)
        need(len(self.commands)<LIMITS["command_count"],"read command count")
        record={"argv_private":list(argv),"attempted":True,"result_known":False,
                "stdout_private_b64":"","stderr_private_b64":"","child_cleanup_attempted":False}
        self.commands.append(record)
        stop=min(deadline,self.now()+LIMITS["command_seconds"])
        need(self.now()<stop,"read command deadline")
        child=None;select=selectors.DefaultSelector();out={"stdout":bytearray(),"stderr":bytearray()}
        try:
            child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            for name in out:
                stream=getattr(child,name);os.set_blocking(stream.fileno(),False);select.register(stream,selectors.EVENT_READ,name)
            while select.get_map():
                left=stop-self.now();need(left>0,"read command timeout")
                for key,_ in select.select(min(left,.05)):
                    name=key.data;block=os.read(key.fileobj.fileno(),65536)
                    if not block:select.unregister(key.fileobj);continue
                    out[name].extend(block);self.command_bytes+=len(block)
                    need(len(out[name])<=LIMITS["command_"+name] and self.command_bytes<=LIMITS["all_command_bytes"],"copied command byte bound")
            code=child.wait(timeout=max(.001,stop-self.now()))
            need(self.now()<stop,"read command completed too late")
            record.update(returncode=code,result_known=True)
            result=(code,bytes(out["stdout"]).decode("utf-8","strict"),bytes(out["stderr"]).decode("utf-8","strict"))
            return result
        except Exception as error:
            record["error_category"]=type(error).__name__;raise
        finally:
            record.update({name+"_private_b64":base64.b64encode(raw).decode("ascii") for name,raw in out.items()})
            select.close()
            if child is not None:
                if child.poll() is None:
                    record["child_cleanup_attempted"]=True
                    child.kill();child.wait(timeout=.25)
                child.stdout.close();child.stderr.close()

    def _bsd(self,pid,expected_birth=None):
        need(type(pid)is int and 1<pid<=0x7fffffff,"native PID")
        self.native_count+=1;need(self.native_count<=LIMITS["native_queries"],"native query budget")
        if self.proc is None:self.proc=ctypes.CDLL("/usr/lib/libproc.dylib",use_errno=True)
        query=self.proc.proc_pidinfo
        query.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int];query.restype=ctypes.c_int
        raw=ctypes.create_string_buffer(136);ctypes.set_errno(0)
        returned=query(pid,3,0,raw,len(raw));error=ctypes.get_errno()
        data=bytes(raw)[:min(136,max(0,returned))]
        record={"api":"proc_pidinfo","flavor":3,"requested_bytes":136,"returned":returned,"errno":error,
                "pid_private":pid,"expected_birth_private":expected_birth,
                "raw_bsdinfo_private_hex":data.hex(),"raw_bsdinfo_sha256":cleanup.digest(data)}
        self.queries.append(record)
        return returned,error,data,record

    def generation(self,birth,deadline):
        cleanup.birth(birth);need(self.now()<deadline,"generation query deadline")
        returned,error,data,record=self._bsd(birth[0],list(birth))
        need(self.now()<deadline,"generation query result deadline")
        evidence={key:record[key] for key in ("api","flavor","requested_bytes","returned","errno","pid_private","expected_birth_private")}
        evidence["outcome"]="uncertain"
        if returned==0 and error==errno.ESRCH:
            evidence["outcome"]="ESRCH";record["outcome"]="ESRCH";return evidence
        if returned==136 and error==0:
            record["observed_birth_private"]=[struct.unpack_from("<I",data,12)[0],*struct.unpack_from("<QQ",data,120)]
            record["outcome"]="alive_or_PID_reused"
        raise cleanup.Refused("original generation absence uncertain or PID reused")

    def process(self,pid,deadline):
        returned,error,data,record=self._bsd(pid)
        need(returned==136 and error==0,"complete UI BSD-info")
        observed=[struct.unpack_from("<I",data,12)[0],*struct.unpack_from("<QQ",data,120)]
        cleanup.birth(observed);need(observed[0]==pid,"UI PID matches copied block")
        status=struct.unpack_from("<I",data,4)[0]
        need(status in (2,3,4),"known UI process status")
        self.native_count+=1;need(self.native_count<=LIMITS["native_queries"],"native query budget")
        query=self.proc.proc_pidpath;query.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32];query.restype=ctypes.c_int
        buf=ctypes.create_string_buffer(4096);length=query(pid,buf,len(buf))
        pathraw=bytes(buf)[:min(4096,max(0,length))]
        record.update(path_returned=length,path_private_b64=base64.b64encode(pathraw).decode("ascii"))
        need(0<length<len(buf) and self.now()<deadline,"bounded UI path query")
        path=pathraw.split(b"\0",1)[0].decode("utf-8","strict")
        return {"path":path,"birth_private":observed,"stopped":status==4,"native_status_private":status,
                "native_status_name":{2:"SRUN",3:"SSLEEP",4:"SSTOP"}[status],
                "raw_bsdinfo_private_hex":data.hex(),"raw_bsdinfo_sha256":cleanup.digest(data),
                "returned_bsdinfo_bytes":returned,"bsdinfo_errno":error,"state_source":"proc_bsdinfo.pbi_status"}

    def read(self,path,limit):return nofollow_read(path,limit)
    def lstat(self,path):return os.lstat(path)
    def readlink(self,path):return os.readlink(path)
    def directory_stat(self,path):
        parent=PhysicalDirectory(path)
        try:
            before=cleanup.stat_record(os.fstat(parent.fd))
            parent.checked();need(before==cleanup.stat_record(os.fstat(parent.fd)),"stable physical directory stat")
            return before
        finally:parent.close()

    def directory(self,path):
        parent=PhysicalDirectory(path)
        try:
            before=cleanup.stat_record(os.fstat(parent.fd));names=sorted(os.listdir(parent.fd))
            need(len(names)<=4096,"bounded directory entry count")
            need(before==cleanup.stat_record(os.fstat(parent.fd)) and names==sorted(os.listdir(parent.fd)),"stable physical directory entries")
            parent.checked();return before,names
        finally:parent.close()



class Observer:
    """Read-only observation; preserves private partial evidence on any refusal."""
    def __init__(self,inputs,backend):
        inputs.intact()
        self.inputs=inputs;self.backend=backend
        self.context=cleanup.context_checked(inputs.context)
        self.delivery=inputs.delivery
        self.rs=inputs.original.runtime
        self.expected_files=inputs.expected_files
        self.started=finite(backend.now());self.deadline=self.started+LIMITS["seconds"]
        self.last=self.started;self.clocks=0;self.read_bytes=0
        self.observations=[];self.trust_initial=None;self.anchor_initial=None
        parent=next(x for x in self.delivery["parents_private"] if x["logical"]=="/var/jb/usr/libexec")
        suffix="/usr/libexec"
        need(parent["resolved"].endswith(suffix),"original rootless parent suffix")
        self.rootless=parent["resolved"][:-len(suffix)]
        need(self.rootless.startswith("/private/preboot/") and not self.rootless.endswith("/"),"original physical rootless anchor")

    def now(self):
        self.clocks+=1;need(self.clocks<=LIMITS["clock_reads"],"observer clock count")
        value=finite(self.backend.now());need(self.last<=value<self.deadline,"observer shared deadline")
        self.last=value;return value

    def _check_anchor(self,entry):
        info=cleanup.stat_record(self.backend.lstat("/private/var/jb"))
        link=self.backend.readlink("/private/var/jb")
        entry.setdefault("rootless_anchor_private",[]).append({"stat_private":info,"link_private":link})
        # The historical resolved parent does not retain the lexical link text.
        # Accept only that exact root or its single directory trailing slash;
        # pin the actually copied literal and inode for this whole session.
        need(info["kind"]=="other" and (info["uid"],info["gid"])==(0,0) and
             link in (self.rootless,self.rootless+"/"),"exact original physical rootless target")
        current=entry["rootless_anchor_private"][-1]
        if self.anchor_initial is None:self.anchor_initial=current
        need(current==self.anchor_initial,"rootless literal or inode changed within session")
        expected=next(x["stat"] for x in self.delivery["parents_private"] if x["logical"]=="/var/jb/usr/libexec")
        parent=typed_record(self.backend.directory_stat(self.rootless+"/usr/libexec"),"directory")
        entry.setdefault("rootless_parent_observations_private",[]).append(parent)
        need(cleanup.canonical({k:parent[k] for k in ("dev","ino","mode","uid","gid")})==
             cleanup.canonical({k:expected[k] for k in ("dev","ino","mode","uid","gid")}),"original physical rootless parent identity")
        if len(entry["rootless_anchor_private"])>1:
            need(entry["rootless_anchor_private"][0]==entry["rootless_anchor_private"][-1],"rootless anchor changed within observation")

    def _physical(self,path):
        if path.startswith("/var/jb/"):return self.rootless+path[len("/var/jb"):]
        need(path.startswith(ROOTFS+"/"),"fixed artifact path")
        return path

    def _read(self,path,limit):
        self.now();left=LIMITS["read_bytes"]-self.read_bytes
        need(left>0,"remaining file read byte budget")
        allowed=min(limit,left);raw,record=self.backend.read(self._physical(path),allowed)
        typed_record(record,"regular")
        need(type(raw)is bytes and 0<len(raw)<=allowed,"bounded artifact copy")
        self.read_bytes+=len(raw);need(self.read_bytes<=LIMITS["read_bytes"],"observer copied file byte budget")
        need(type(record)is dict and record["kind"]=="regular" and record["nlink"]==1 and record["size"]==len(raw),"artifact regular stat")
        self.now();return raw,record

    def _artifacts(self,entry,trusted):
        records={}
        entry["artifacts_private"]=records
        entry["delivery_directories_private"]=[]
        for directory in self.delivery["created_directories_private"]:
            path=directory["path"];current,names=self.backend.directory(self._physical(path))
            typed_record(current,"directory")
            entry["delivery_directories_private"].append({"path_private":path,"stat_private":current,"entries_private":names})
            expected=directory["stat"]
            need(cleanup.canonical({k:current[k] for k in expected})==cleanup.canonical(expected) and current["kind"]=="directory","original delivery directory token")
            want=sorted(x["name"] for x in self.delivery["installed_files_private"] if x["path"].rsplit("/",1)[0]==path)
            need(names==want,"exact installed payload directory entries")
        for row in self.delivery["installed_files_private"]:
            raw,current=self._read(row["path"],128*1024)
            records[row["path"]]={"stat":current,"sha256":cleanup.digest(raw)}
            need(cleanup.canonical({k:current[k] for k in row["stat"]})==cleanup.canonical(row["stat"]) and cleanup.digest(raw)==row["sha256"],"original delivered artifact content/token")
            if row["name"]=="probe.arm64":
                signature=readonly.code_signature(raw);records[row["path"]]["signature"]=signature
                need(signature==self.delivery["probe_signature"] and signature["cdhash"] in trusted,"original trusted signed probe")
        for name,want in readonly.DEPENDENCIES.items():
            raw,current=self._read(want["path"],4*1024*1024)
            signature=readonly.code_signature(raw)
            records[name]={"stat":current,"sha256":cleanup.digest(raw),"signature":signature}
            need(cleanup.digest(raw)==want["sha256"] and all(signature[k]==want[k] for k in ("architecture","uuid")) and
                 signature["cdhash"] in trusted,"trusted frozen dependency exact identity")

    def observe(self,selection_sha256,provenance_sha256,deadline):
        cleanup.sha_word(selection_sha256);cleanup.sha_word(provenance_sha256)
        current=self.now()
        need(type(deadline)in(int,float) and math.isfinite(deadline) and 0<deadline-current<=LIMITS["seconds"],"caller observation deadline")
        need(len(self.observations)<LIMITS["observations"],"observer observation count")
        entry={"started_monotonic_private":current,"completed":False,"stage":"metadata"}
        self.observations.append(entry)
        stop=min(deadline,self.deadline)
        try:
            self._check_anchor(entry)
            meta={};entry["metadata_private"]=meta
            for name in ("hw.machine","kern.osversion","kern.uuid","kern.bootsessionuuid"):
                meta[name]=self.backend.metadata(name)
            need(meta["hw.machine"]=="iPad13,6" and meta["kern.osversion"]=="20E252" and
                 meta["kern.uuid"].lower()=="d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb" and
                 meta["kern.bootsessionuuid"]==self.context["boot_private"],"exact device/build/boot")
            raw,_=self._read(ROOTFS+"/System/Library/CoreServices/SystemVersion.plist",65536)
            version=plistlib.loads(raw);entry["rootfs_version_private"]=version
            need(version["ProductVersion"]=="13.4" and version["ProductBuildVersion"]=="22F66","exact rootfs build")
            entry["stage"]="processes"
            ps=self.backend.command(["/bin/ps","-eo","pid,comm"],stop)
            entry["process_command_private"]=list(ps)
            need(type(ps[0])is int and ps[0]==0 and ps[2]=="","complete ps output")
            rows=readonly.process_rows(ps[1]);entry["process_rows_private"]=rows
            blocked=[x for x in rows if x["basename"] in readonly.BLOCKED_BASENAMES or
                     ("macws" in x["basename"].lower() and any(w in x["basename"].lower() for w in ("windowserver","debug","producer","observer","swap-pair")))]
            need(blocked==[],"candidate or test workload present")
            ui={};entry["UI_details_private"]={}
            for name in ("SpringBoard","backboardd"):
                matches=[x for x in rows if x["basename"]==name];need(len(matches)==1,"unique complete UI row")
                state=self.backend.process(matches[0]["pid_private"],stop);entry["UI_details_private"][name]=state
                cleanup.birth(state["birth_private"])
                need(state["path"].rsplit("/",1)[-1]==name and state["stopped"]is False and
                     state["birth_private"]==self.context["UI_private"][name],"original running UI generation")
                ui[name]=list(state["birth_private"])
            entry["stage"]="job_and_generation_absence";jobs={};entry["jobs_private"]=jobs
            for operation in ("run","control_normal"):
                cfg=dict(self.inputs.original.config,operation=operation)
                service=self.rs.service_identifier(cfg)
                result=self.backend.command([self.rs.LAUNCHCTL,"print",service],stop);jobs[service]=list(result)
                need(self.rs.parsed_job(cfg,result)is None,"both original services absent")
            absent=self.backend.generation(self.context["retired_birth_private"],stop)
            entry["generation_absence_private"]=absent;cleanup._absence(absent,self.context["retired_birth_private"])
            try:self.backend.lstat(RUN_SCRATCH)
            except FileNotFoundError:pass
            else:raise cleanup.Refused("other scratch occupied")
            entry["thermal"]=self.backend.thermal();need(type(entry["thermal"])is int and entry["thermal"]==0,"nominal thermal")
            entry["stage"]="trust_and_artifacts"
            trust=self.backend.command([self.rs.JBCTL,"trustcache","info"],stop)
            entry["trust_command_private"]=list(trust)
            need(type(trust[0])is int and trust[0]==0 and trust[2]=="","complete trust query")
            trusted=readonly.trust_rows(trust[1]);entry["trust_members_private"]=sorted(trusted)
            if self.trust_initial is None:self.trust_initial=frozenset(trusted)
            need(frozenset(trusted)==self.trust_initial,"trust membership changed in this observer session")
            self._artifacts(entry,trusted);self._check_anchor(entry)
            finished=self.now();oldest=entry["started_monotonic_private"]
            need(finished<stop and finished-oldest<=LIMITS["max_gate_age"],"observation too slow or stale")
            gate={"schema":"macws.retained-artifact.gates.v1","selection_sha256":selection_sha256,
                  "provenance_sha256":provenance_sha256,"boot_private":self.context["boot_private"],
                  "config_sha256":self.context["config_sha256"],"source_sha256":dict(cleanup.SOURCES),
                  "UI_private":ui,"exclusive_operator":True,"observed_monotonic":oldest,
                  "jobs_absent":dict.fromkeys(cleanup.SERVICES,True),"no_candidate_or_test_workloads":True,
                  "other_scratch_absent":True,"artifacts_unchanged":True,"thermal":0,"generation_absence":absent}
            entry.update(completed=True,stage="complete",finished_monotonic_private=finished,gate_private=gate)
            return gate
        except Exception as error:
            entry["error_category"]=type(error).__name__
            entry["refusal"]=str(error) if type(error)is cleanup.Refused else None
            raise

    def report(self):
        return {"schema":"macws.retained-artifact.observer-report.v1","observations_private":self.observations,
                "commands_private":getattr(self.backend,"commands",[]),"native_queries_private":getattr(self.backend,"queries",[]),
                "copied_command_bytes":getattr(self.backend,"command_bytes",None),
                "native_query_count":getattr(self.backend,"native_count",None),
                "native_clock_read_count":getattr(self.backend,"clock_reads",None),
                "copied_file_bytes":self.read_bytes,"clock_reads":self.clocks,"limits":dict(LIMITS),
                "existing_workload_or_file_mutations":0,"candidate_executions":0,"existing_job_signals":0,
                "managed_read_child_cleanup_attempts":sum(x.get("child_cleanup_attempted")is True for x in getattr(self.backend,"commands",[])),
                "cleanup_authorized":False,"device_acceptance":False,"original_ownership_recovered":False}


def read_selection(context):
    """Copy bounded current bytes before applying old-content lineage refusal."""
    context=cleanup.context_checked(context)
    held=cleanup._Held()
    try:
        directory,files,content=held.checked()
        manifest={"schema":"macws.retained-artifact.selection.v1","path":cleanup.TARGET,
                  "boot_private":context["boot_private"],"config_sha256":context["config_sha256"],
                  "source_sha256":dict(cleanup.SOURCES),"directory":directory,"files":files}
        return {"manifest":manifest,"files":content}
    finally:held.close()


def copied_selection(value):
    cleanup.keys(value,("manifest","files"))
    manifest=cleanup.decode(cleanup.canonical(value["manifest"]))
    cleanup.keys(value["files"],cleanup.NAMES)
    encoded={}
    for name,raw in value["files"].items():
        need(type(raw)is bytes and len(raw)<=cleanup.LIMITS[name],"bounded copied selection bytes")
        encoded[name]=base64.b64encode(raw).decode("ascii")
    return {"manifest_private":manifest,"files_private":encoded}


def capture_observation(observer,selection_reader=None):
    """Two stable exact file copies surrounded by gates; never cleanup admission.

    The provenance base deliberately omits the future current-wire hash. These
    capture-phase gate hashes cannot match Cleaner's final archive provenance.
    Original serialized native stdout must still be persisted by the live caller.
    """
    selection_reader=read_selection if selection_reader is None else selection_reader
    report={"schema":"macws.retained-artifact.read-only-capture.v1","capture_completed":False,
            "capture_only_not_cleanup_admission":True,"cleanup_authorized":False,
            "device_acceptance":False,"existing_workload_or_file_mutations":0,"files_private":None,
            "manifest_private":None,"selection_copies_private":[],"error_category":None,"refusal":None}
    try:
        observer.inputs.intact()
        provenance=observer.inputs.provenance_base
        need(set(provenance)==set(cleanup.PROVENANCE_KEYS)-{"current_wire_sha256"},"historical provenance base only")
        provenance_sha=cleanup.digest(cleanup.canonical(provenance))
        report["pre_capture_gate_private"]=observer.observe("0"*64,provenance_sha,observer.deadline)
        need(observer.read_bytes+sum(cleanup.LIMITS.values())<=LIMITS["read_bytes"],"selection byte reserve")
        first=selection_reader(observer.context)
        report["selection_copies_private"].append(copied_selection(first))
        cleanup.selection_checked(first["manifest"],observer.context,observer.expected_files)
        observer.read_bytes+=sum(len(raw) for raw in first["files"].values())
        need(observer.read_bytes<=LIMITS["read_bytes"],"selection copy byte budget")
        manifest_sha=cleanup.digest(cleanup.canonical(first["manifest"]))
        report["post_capture_gate_private"]=observer.observe(manifest_sha,provenance_sha,observer.deadline)
        need(observer.read_bytes+sum(cleanup.LIMITS.values())<=LIMITS["read_bytes"],"selection byte reserve")
        second=selection_reader(observer.context)
        report["selection_copies_private"].append(copied_selection(second))
        cleanup.selection_checked(second["manifest"],observer.context,observer.expected_files)
        observer.read_bytes+=sum(len(raw) for raw in second["files"].values())
        need(observer.read_bytes<=LIMITS["read_bytes"] and
             cleanup.canonical(first["manifest"])==cleanup.canonical(second["manifest"]) and
             first["files"]==second["files"]==observer.expected_files,"selection changed across capture")
        need(observer.now()-report["post_capture_gate_private"]["observed_monotonic"]<=1,"capture final state stale")
        report.update(capture_completed=True,manifest_private=second["manifest"],
                      files_private=report["selection_copies_private"][-1]["files_private"])
    except Exception as error:
        report["error_category"]=type(error).__name__
        report["refusal"]=str(error) if type(error)is cleanup.Refused else None
    report["observer_private"]=observer.report()
    return report


def native_observer(inputs,*,dependency_sources=None):
    """Explicit native construction after exact dependencies and lineage checks.

    Embedded bytes are for a reviewed fresh worker that loaded these exact
    modules into an otherwise empty package namespace. They avoid staging new
    files on the device. Neither byte pins nor on-disk hashes attest already
    loaded Python objects; caller/process integrity remains a trusted premise.
    """
    if dependency_sources is None:
        sources={}
        for module in (cleanup,readonly):
            name=Path(module.__file__).name
            raw,_=nofollow_read(str(Path(module.__file__).resolve()),256*1024)
            sources[name]=raw
    else:
        need(type(dependency_sources)is dict and all(type(key)is str for key in dependency_sources) and
             set(dependency_sources)==set(PINS),
             "exact embedded observer dependency names")
        sources=dict(dependency_sources)
    need(set(sources)==set(PINS),"exact observer dependency names")
    # Validate the entire immutable byte snapshot before native construction.
    for name,expected in PINS.items():
        raw=sources[name]
        need(type(raw)is bytes and 0<len(raw)<=256*1024 and cleanup.digest(raw)==expected,
             "observer dependency source pin")
    need(inputs.intact()is True,"intact historical inputs")
    return Observer(inputs,NativeReadOnlyBackend(inputs.original))


def metadata():
    return {"schema":"macws.retained-artifact.observer-metadata.v1","default_inert":True,
            "device_commands":0,"worker_or_transport_provided":False,
            "cleanup_authorized":False,"device_acceptance":False}


if __name__=="__main__":
    import json
    print(json.dumps(metadata(),sort_keys=True))
