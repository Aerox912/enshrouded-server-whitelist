import pathlib,subprocess,sys,tempfile
build=pathlib.Path(sys.argv[1]);server=pathlib.Path(sys.argv[2])
with tempfile.TemporaryDirectory(prefix='esm-admission-pin-',dir=build.parent) as folder:
 r=subprocess.run([str(build/'esm_admission_launcher.exe'),str(server),str(build/'admission_guard_fixture.dll')],cwd=folder,capture_output=True,text=True,timeout=10)
 assert r.returncode!=0 and 'unrecognized admission guard artifact' in r.stderr,(r.returncode,r.stdout,r.stderr)
 assert not r.stdout and not list(pathlib.Path(folder).iterdir())
 print('PASS: genuine server plus a wrong ready-token DLL is rejected before process creation')
