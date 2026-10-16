"""Runs only the owned no-network fixture, never a game server."""
import pathlib,subprocess,sys,tempfile,shutil,time,ctypes
build=pathlib.Path(sys.argv[1])
k=ctypes.WinDLL('kernel32',use_last_error=True);k.OpenProcess.restype=ctypes.c_void_p;k.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong];k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_ulong];k.CloseHandle.argtypes=[ctypes.c_void_p]
for mode in ('success','reject','missing-dll','crash','hang','launcher-killed','bad-patch','post-commit-reject','no-commit'):
 with tempfile.TemporaryDirectory(prefix='esm-admission-',dir=build.parent) as folder:
  root=pathlib.Path(folder)
  shutil.copy2(build/'admission_launch_fixture.exe',root/'admission_launch_fixture.exe')
  if mode in {'reject','crash','hang'}:(root/(mode+'-init.txt')).touch()
  if mode in {'bad-patch','post-commit-reject','no-commit'}:(root/(mode+'.txt')).touch()
  if mode=='launcher-killed':(root/'hang-init.txt').touch()
  dll=build/('missing.dll' if mode=='missing-dll' else 'admission_guard_fixture.dll')
  args=[str(build/'admission_launcher_tests_host.exe'),str(root/'admission_launch_fixture.exe'),str(dll)]
  if mode=='launcher-killed':
   process=subprocess.Popen(args,cwd=build,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   for _ in range(300):
    marker=root/'guard-entered.txt'
    if marker.exists() and marker.read_text():break
    time.sleep(.02)
   child=k.OpenProcess(0x100000,False,int(marker.read_text()));assert child
   process.kill();process.communicate(timeout=10)
   assert k.WaitForSingleObject(child,5000)==0,'job must terminate child when launcher dies before READY';k.CloseHandle(child)
   assert not (root/'entry-ran.txt').exists();print('PASS launcher-killed: contained child terminated before entry');continue
  r=subprocess.run(args,cwd=build,capture_output=True,text=True,timeout=40)
  if mode=='success':
   assert r.returncode==0,(mode,r.returncode,r.stdout,r.stderr)
   for _ in range(50):
    if (root/'entry-ran.txt').exists():break
    time.sleep(.02)
   assert (root/'guard-ready.txt').exists() and (root/'entry-ran.txt').exists(), 'entry must follow successful guard'
  else:
   assert r.returncode!=0,(mode,r.stdout)
   assert not (root/'entry-ran.txt').exists(),'failed guard must prevent entry point'
   if (root/'guard-entered.txt').exists():
    child=k.OpenProcess(0x100000,False,int((root/'guard-entered.txt').read_text()))
    if child:assert k.WaitForSingleObject(child,1000)==0,'failed child still running';k.CloseHandle(child)
  print(mode,r.stdout.strip())
print('PASS: owned process success and fail-closed startup')
