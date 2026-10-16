"""Execute the captured current-build native auth branch with boundary stubs.
Proves branch/state behavior, not Steam or multiplayer acceptance.
"""
import sys,hashlib,struct
from pathlib import Path
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
p=Path(sys.argv[1]);assert hashlib.sha256(p.read_bytes()).hexdigest()=='4de2acdd3b18e562f129bc488a2daea2da16b00341497304423e1e18c49a83ba'
pe=pefile.PE(str(p));image=pe.get_memory_mapped_image();base=pe.OPTIONAL_HEADER.ImageBase
for response,unknown,want_state,want_removes in [(0,False,2,0),(0x45534d01,False,1,1),(7,False,1,1),(0x45534d01,True,1,0)]:
 u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(base,(len(image)+4095)&~4095);u.mem_write(base,image)
 stack=0x200000000;backend=0x210000000;event=0x220000000;peer=0x230000000
 for addr,size in [(stack,0x10000),(backend,0x350000),(event,0x1000),(peer,0x1000)]:u.mem_map(addr,size)
 u.reg_write(UC_X86_REG_RSP,stack+0x8000);u.reg_write(UC_X86_REG_RBP,stack+0x8000)
 u.reg_write(UC_X86_REG_RDI,backend);u.reg_write(UC_X86_REG_RBX,event)
 u.mem_write(event+8,struct.pack('<Q',76561197960265729));u.mem_write(event+16,struct.pack('<I',response))
 u.mem_write(peer+0x98,b'\x01');u.mem_write(backend+0x348fc0+0x21c4,b'\x44\x00')
 calls=[]
 def hook(uc,address,size,data):
  rva=address-base
  if rva==0x9d4bb7:uc.emu_stop();return
  if rva in (0x9c4480,0x56eea0,0x55c480,0x9c7000,0x572ba0,0x9c2e90):
   calls.append(rva)
   if rva==0x9c4480:uc.mem_write(uc.reg_read(UC_X86_REG_RDX),struct.pack('<H',0 if unknown else 0x41))
   elif rva==0x9c7000:uc.reg_write(UC_X86_REG_RAX,peer)
   elif rva==0x9c2e90:
    assert uc.reg_read(UC_X86_REG_RCX)==backend+0x348fc0 and uc.reg_read(UC_X86_REG_RDX)==0x41
   rsp=uc.reg_read(UC_X86_REG_RSP);ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0];uc.reg_write(UC_X86_REG_RSP,rsp+8);uc.reg_write(UC_X86_REG_RIP,ret)
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(base+0x9d4a41,base+0x9d4bb7,count=5000)
 assert u.reg_read(UC_X86_REG_RIP)==base+0x9d4bb7,'native branch did not finish'
 assert u.mem_read(peer+0x98,1)==bytes([want_state])
 assert calls.count(0x9c2e90)==want_removes
 print(f'PASS native auth branch: response={response} unknown={unknown} peer_state={want_state} removals={want_removes}')

# Execute the actual removal implementation too. Its Steam EndAuthSession
# vtable slot is 0xd8 (verified against the pinned steam_api64.dll flat export).
# This reproduces why policy denial while pending needs explicit Steam cleanup.
for state,expected_ends in [(0,0),(1,0),(2,1)]:
 u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(base,(len(image)+4095)&~4095);u.mem_write(base,image)
 stack=0x200000000;backend=0x210000000;peer=0x230000000;steam=0x240000000;vtable=steam+0x1000;end=steam+0x2000;done=steam+0x3000
 for addr,size in [(stack,0x10000),(backend,0x4000),(peer,0x1000),(steam,0x4000)]:u.mem_map(addr,size)
 u.reg_write(UC_X86_REG_RSP,stack+0x8008);u.mem_write(stack+0x8008,struct.pack('<Q',done))
 u.reg_write(UC_X86_REG_RCX,backend);u.reg_write(UC_X86_REG_RDX,0x41)
 u.mem_write(backend+0x20,struct.pack('<Q',steam));u.mem_write(backend+0x21c0,b'\x01');u.mem_write(backend+0x21c2,b'\x01')
 u.mem_write(peer+2,struct.pack('<Q',76561197960265731));u.mem_write(peer+0x98,bytes([state]))
 u.mem_write(steam,struct.pack('<Q',vtable));u.mem_write(vtable+0xd8,struct.pack('<Q',end));ended=[]
 def removal_hook(uc,address,size,data):
  if address==done:uc.emu_stop();return
  if address==end:
   assert uc.reg_read(UC_X86_REG_RCX)==steam
   ended.append(uc.reg_read(UC_X86_REG_RDX))
  elif address-base in (0x55c480,0x9c7000,0x9bf460,0x56eea0,0x572ba0):
   if address-base==0x9c7000:uc.reg_write(UC_X86_REG_RAX,peer)
  else:return
  rsp=uc.reg_read(UC_X86_REG_RSP);ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0];uc.reg_write(UC_X86_REG_RSP,rsp+8);uc.reg_write(UC_X86_REG_RIP,ret)
 u.hook_add(UC_HOOK_CODE,removal_hook);u.emu_start(base+0x9c2e90,done,count=5000)
 assert u.reg_read(UC_X86_REG_RIP)==done and ended==[76561197960265731]*expected_ends
 print(f'PASS native removal Steam cleanup: peer_state={state} EndAuthSession_calls={len(ended)}')
