"""Portable negative tests for bounded task bytes; synthetic data only."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
import uuid
from unittest.mock import patch

import macos_producer_registration_probe as reader
def header(identity=uuid.UUID('11111111-2222-3333-4444-555555555555')):
    return struct.pack('<8I',0xfeedfacf,0x100000c,2,6,1,24,0,0)+struct.pack('<II',0x1b,24)+identity.bytes

class ReaderGuards(unittest.TestCase):
    def test_process_birth_metadata_exact_layout(self):
        data=bytearray(136);struct.pack_into('<I',data,12,42);struct.pack_into('<QQ',data,120,100,500)
        self.assertEqual(reader.parse_process_start_info(bytes(data),42),(100,500))
    def test_process_birth_metadata_refuses_wrong_PID_or_time(self):
        for pid,seconds,microseconds in ((43,100,500),(42,0,500),(42,1<<63,500),(42,100,1000000)):
            data=bytearray(136);struct.pack_into('<I',data,12,pid);struct.pack_into('<QQ',data,120,seconds,microseconds)
            with self.subTest(pid=pid,seconds=seconds,microseconds=microseconds):
                with self.assertRaises(reader.Refused):reader.parse_process_start_info(bytes(data),42)
    def test_process_birth_metadata_refuses_short_mutable_or_boolean_PID(self):
        for raw,pid in ((bytes(135),42),(bytearray(136),42),(bytes(136),True)):
            with self.assertRaises(reader.Refused):reader.parse_process_start_info(raw,pid)
    def test_path_terminates_at_mapping_end_without_next_page_read(self):
        data=b'abc\0';calls=[]
        def get(address,size):
            calls.append((address,size))
            self.assertLessEqual(address+size,4096)
            return data[address-4092:address-4092+size]
        self.assertEqual(reader.bounded_image_path(reader.BudgetReader(get,1,lambda:0),4092),'abc')
        self.assertEqual(calls,[(4092,4)])
    def test_path_has_strict_total_byte_bound(self):
        calls=[]
        def get(address,size):calls.append(size);return b'x'*size
        with self.assertRaisesRegex(reader.Refused,'image path bound'):
            reader.bounded_image_path(reader.BudgetReader(get,1,lambda:0),8192)
        self.assertEqual(sum(calls),384)
    def test_non_utf8_image_path_is_refused(self):
        with self.assertRaises(UnicodeDecodeError):
            reader.bounded_image_path(reader.BudgetReader(lambda a,n:b'\xff\0'+bytes(n-2),1,lambda:0),8192)
    def test_chunked_read_is_exact(self):
        calls=[]
        def get(address,size):calls.append((address,size));return bytes([address%256])*size
        result=reader.BudgetReader(get,1,lambda:0).read(0x1000,2050)
        self.assertEqual(len(result),2050);self.assertEqual([s for _,s in calls],[1024,1024,2])
    def test_short_task_read_refused(self):
        with self.assertRaises(reader.Refused):reader.BudgetReader(lambda a,n:b'X'*(n-1),1,lambda:0).read(4096,8)
    def test_mutable_callback_buffer_refused(self):
        with self.assertRaises(reader.Refused):reader.BudgetReader(lambda a,n:bytearray(n),1,lambda:0).read(4096,8)
    def test_deadline_refused_before_callback(self):
        calls=[]
        with self.assertRaises(reader.Refused):reader.BudgetReader(lambda a,n:calls.append(1),1,lambda:2).read(4096,8)
        self.assertEqual(calls,[])
    def test_read_call_budget_refused(self):
        with patch.object(reader,'MAX_READ_CALLS',1):
            with self.assertRaises(reader.Refused):reader.BudgetReader(lambda a,n:b'X'*n,1,lambda:0).read(4096,1025)
    def test_read_byte_budget_refused_before_callback(self):
        calls=[]
        with patch.object(reader,'MAX_READ_BYTES',7):
            with self.assertRaises(reader.Refused):reader.BudgetReader(lambda a,n:calls.append(1),1,lambda:0).read(4096,8)
        self.assertEqual(calls,[])
    def test_boolean_address_refused(self):
        with self.assertRaises(reader.Refused):reader.extent(True,8)
    def test_kernel_or_overflow_address_refused(self):
        for addr,size in [(0,8),(-1,8),(reader.USER_END,8),(reader.USER_END-4,8),(4096,65537)]:
            with self.subTest(addr=addr,size=size):
                with self.assertRaises(reader.Refused):reader.extent(addr,size)
    def test_mutable_header_is_refused(self):
        with self.assertRaises(reader.Refused):reader.parse_header(bytearray(header()))
    def test_exact_uuid_header(self):
        self.assertEqual(reader.parse_header(header()),'11111111-2222-3333-4444-555555555555')
    def test_nonarm64_header_refused(self):
        data=bytearray(header());struct.pack_into('<I',data,4,0x1000007)
        with self.assertRaises(reader.Refused):reader.parse_header(bytes(data))
    def test_truncated_commands_refused(self):
        with self.assertRaises(reader.Refused):reader.parse_header(header()[:-1])
    def test_zero_command_size_refused(self):
        data=bytearray(header());struct.pack_into('<I',data,36,0)
        with self.assertRaises(reader.Refused):reader.parse_header(bytes(data))
    def test_duplicate_uuid_command_refused(self):
        data=bytearray(header());struct.pack_into('<II',data,16,2,48);data.extend(data[32:56])
        with self.assertRaises(reader.Refused):reader.parse_header(bytes(data))
    def test_missing_uuid_refused(self):
        data=bytearray(header());struct.pack_into('<I',data,32,0x24)
        with self.assertRaises(reader.Refused):reader.parse_header(bytes(data))
    def test_fat_file_arm64_slice(self):
        data=header();fat=struct.pack('>7I',0xcafebabe,1,0x100000c,2,32,len(data),0)+b'\0'*4+data
        self.assertEqual(reader.executable_UUID(fat),reader.parse_header(bytes(data)))
    def test_ambiguous_fat_arm64_refused(self):
        data=header();fat=struct.pack('>2I',0xcafebabe,2)+struct.pack('>5I',0x100000c,0,48,len(data),0)+struct.pack('>5I',0x100000c,2,48+len(data),len(data),0)+data+data
        with self.assertRaises(reader.Refused):reader.executable_UUID(fat)
    def test_fat_slice_extent_refused(self):
        data=struct.pack('>7I',0xcafebabe,1,0x100000c,2,4096,32,0)
        with self.assertRaises(reader.Refused):reader.executable_UUID(data)
    def test_complete_synthetic_registration_preserves_private_scope(self):
        data=struct.pack('<QIIQQQ',4096,123,0,8192,12288,0)
        rows=reader.parse_registrations(data,1)
        self.assertEqual(rows[0]['client_name_private'],123)
        self.assertNotIn('physical_Framebuffer_binding_proven',rows[0])
    def test_alias_registration_refused(self):
        data=struct.pack('<QIIQQQ',4096,123,0,8192,12288,0)
        with self.assertRaises(reader.Refused):reader.parse_registrations(data*2,2)
    def test_null_active_registration_refused(self):
        with self.assertRaises(reader.Refused):reader.parse_registrations(bytes(40),1)
    def test_registration_overflow_or_boolean_count_refused(self):
        for count in (True,9,-1):
            with self.subTest(count=count):
                with self.assertRaises(reader.Refused):reader.parse_registrations(bytes(40),count)
    def test_empty_registration_is_not_fabricated(self):
        self.assertEqual(reader.parse_registrations(b'',0),[])
    def test_wrong_profile_bytes_refused_before_any_API(self):
        with self.assertRaises(reader.Refused):reader.run(123,b'{}')
    def test_oversized_profile_refused(self):
        with self.assertRaises(reader.Refused):reader.verify_profile(b' '*65537)

if __name__=='__main__':unittest.main()
