#!/usr/bin/env python3
"""KakaoTalk(Mac) 채팅 목록 광고 배너 제거 파이프라인.

각 단계는 실행 전에 상태를 검사하고, 이미 끝난 단계는 건너뛰며,
예상과 다른 상태면 아무것도 바꾸지 않고 멈춘다.

  1. inspect  설치된 앱 상태 확인 (버전, 서명 주체, 패치 여부)
  2. backup   원본(카카오 서명) 앱을 버전별로 백업
  3. analyze  광고 표시 판단 함수 자동 탐색
              FSMainViewController.updateAdvertise 가 호출하는 함수 중
              `isCountryISOKorea` 를 호출하는 함수 = "광고 표시 여부" 함수
  4. build    작업 폴더에 앱 복사 → 함수를 `mov w0,#0; ret` 로 패치
              → 원본 entitlements 로 ad-hoc 재서명 (Hardened Runtime 제외)
  5. verify   빌드 결과 검사 (패치 바이트, 서명, entitlements 일치)
  6. install  관리자 권한으로 /Applications 교체 (비밀번호 창)
  7. check    설치본 실행 확인

사용법:
  python3 adblock.py            # 전체 파이프라인 (run)
  python3 adblock.py status     # 현재 상태만 출력
  python3 adblock.py analyze <실행파일>   # 탐색만
  python3 adblock.py restore    # 백업한 원본으로 복원
옵션:
  --force       이미 적용돼 있어도 다시 빌드/설치
  --no-install  빌드·검증까지만
"""
import os, platform, plistlib, re, shutil, struct, subprocess, sys, time

APP = "/Applications/KakaoTalk.app"
EXE_REL = "Contents/MacOS/KakaoTalk"
BASE = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(BASE, "backup")
BUILD_DIR = os.path.join(BASE, "build")
KAKAO_TEAM = "L75WVXX68A"
PATCH = struct.pack("<II", 0x52800000, 0xD65F03C0)  # mov w0,#0 ; ret
SELECTOR = b"isCountryISOKorea"
CLASS_NAME = b"_TtC9KakaoTalk20FSMainViewController"
METHOD_NAME = b"updateAdvertise"


class StepError(Exception):
    pass


def log(step, msg):
    print(f"[{step}] {msg}", flush=True)


def sh(*args, check=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise StepError(f"명령 실패: {' '.join(args)}\n{r.stdout}{r.stderr}")
    return r


# ---------------------------------------------------------------- Mach-O ---
class ArmSlice:
    """Universal 바이너리의 arm64 슬라이스를 vmaddr 기준으로 읽는다."""

    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        magic = struct.unpack_from(">I", d, 0)[0]
        self.base = None
        if magic == 0xCAFEBABE:
            for i in range(struct.unpack_from(">I", d, 4)[0]):
                cpu, _, off, _, _ = struct.unpack_from(">iiIII", d, 8 + i * 20)
                if cpu == 0x0100000C:
                    self.base = off
        elif struct.unpack_from("<I", d, 0)[0] == 0xFEEDFACF:
            self.base = 0
        if self.base is None:
            raise StepError("arm64 슬라이스가 없습니다")
        self.segs, self.sects = [], {}
        ncmds = struct.unpack_from("<I", d, self.base + 16)[0]
        p = self.base + 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", d, p)
            if cmd == 0x19:
                seg = d[p + 8:p + 24].rstrip(b"\0")
                vm, vs, fo, _ = struct.unpack_from("<QQQQ", d, p + 24)
                self.segs.append((vm, vs, fo))
                if seg == b"__TEXT":
                    self.image_base = vm
                nsect = struct.unpack_from("<I", d, p + 64)[0]
                for j in range(nsect):
                    s = p + 72 + j * 80
                    name = d[s:s + 16].rstrip(b"\0")
                    addr, sz = struct.unpack_from("<QQ", d, s + 32)
                    self.sects[(seg, name)] = (addr, sz)
            p += size

    def off(self, va):
        for vm, vs, fo in self.segs:
            if vm <= va < vm + vs:
                return self.base + fo + (va - vm)
        raise StepError(f"주소 범위 밖: {va:#x}")

    def u32(self, va):
        return struct.unpack_from("<I", self.data, self.off(va))[0]

    def ptr(self, va):
        raw = struct.unpack_from("<Q", self.data, self.off(va))[0]
        if raw >> 63:  # bind (외부 심볼) - 해석하지 않음
            return None
        t = raw & 0xFFFFFFFFF
        return t if t >= self.image_base else t + self.image_base

    def cstr(self, va):
        o = self.off(va)
        return self.data[o:self.data.index(b"\0", o)]

    def in_sect(self, va, seg, name):
        a = self.sects.get((seg, name))
        return a is not None and a[0] <= va < a[0] + a[1]

    # -- AArch64 helpers
    def branch_target(self, va):
        ins = self.u32(va)
        if ins & 0x7C000000 == 0x14000000:  # B / BL
            imm = ins & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            return va + imm * 4, bool(ins & 0x80000000)
        return None, None

    def stub_selref(self, va):
        """__objc_stubs 의 `adrp x1, P ; ldr x1,[x1,#o]` 에서 selref 주소를 얻는다."""
        a, b = self.u32(va), self.u32(va + 4)
        if a & 0x9F00001F != 0x90000001 or b & 0xFFC003FF != 0xF9400021:
            return None
        imm = ((a >> 5) & 0x7FFFF) << 2 | (a >> 29) & 3
        if imm & 0x100000:
            imm -= 0x200000
        return (va & ~0xFFF) + (imm << 12) + ((b >> 10) & 0xFFF) * 8

    def calls(self, va, limit):
        """함수 시작부터 ret 까지(최대 limit 명령) BL 대상 목록."""
        out = []
        for i in range(limit):
            pc = va + i * 4
            if self.u32(pc) == 0xD65F03C0:
                break
            t, link = self.branch_target(pc)
            if t is not None and link:
                out.append(t)
        return out

    # -- ObjC metadata
    def sect(self, name):
        for (_, n), v in self.sects.items():
            if n == name:
                return v
        raise StepError(f"{name.decode()} 섹션이 없습니다 (KakaoTalk 바이너리가 아님?)")

    def selref_of(self, name):
        addr, sz = self.sect(b"__objc_selrefs")
        for a in range(addr, addr + sz, 8):
            p = self.ptr(a)
            if p and self.cstr(p) == name:
                return a
        raise StepError(f"selector 없음: {name.decode()}")

    def method_imp(self, cls, meth):
        addr, sz = self.sect(b"__objc_classlist")
        for a in range(addr, addr + sz, 8):
            c = self.ptr(a)
            if c is None:
                continue
            ro = self.ptr(c + 32) & ~7
            if self.cstr(self.ptr(ro + 24)) != cls:
                continue
            ml = self.ptr(ro + 32)
            ef, cnt = self.u32(ml), self.u32(ml + 4)
            for i in range(cnt):
                if ef & 0x80000000:  # relative method list
                    e = ml + 8 + i * 12
                    n, _, imp = struct.unpack_from("<iii", self.data, self.off(e))
                    name = self.cstr(self.ptr(e + n))
                    impva = e + 8 + imp
                else:
                    e = ml + 8 + i * (ef & 0xFFFC)
                    name = self.cstr(self.ptr(e))
                    impva = self.ptr(e + 16)
                if name == meth:
                    return impva
        raise StepError(f"{cls.decode()}.{meth.decode()} 를 찾지 못했습니다")


def analyze(exe):
    """광고 표시 판단 함수 주소와 현재 패치 여부를 반환."""
    try:
        return _analyze(exe)
    except StepError:
        raise
    except Exception as e:  # 형식이 다른 파일 등 - 아무것도 바꾸지 않고 중단
        raise StepError(f"분석 실패 ({type(e).__name__}: {e})")


def _analyze(exe):
    m = ArmSlice(exe)
    sel = m.selref_of(SELECTOR)
    thunk = m.method_imp(CLASS_NAME, METHOD_NAME)
    bodies = [t for t in m.calls(thunk, 16) if m.in_sect(t, b"__TEXT", b"__text")]
    if len(bodies) != 1:
        raise StepError(f"updateAdvertise 구조가 예상과 다름 (본문 후보 {len(bodies)}개)")
    found = set()
    for cand in set(m.calls(bodies[0], 200)):
        if not m.in_sect(cand, b"__TEXT", b"__text"):
            continue
        for t in _calls_skip_patch(m, cand):
            if m.in_sect(t, b"__TEXT", b"__objc_stubs") and m.stub_selref(t) == sel:
                found.add(cand)
    if len(found) != 1:
        raise StepError(f"광고 판단 함수 후보가 {len(found)}개 - 버전이 크게 바뀐 것 같습니다")
    target = found.pop()
    o = m.off(target)
    patched = m.data[o:o + 8] == PATCH
    return target, o, patched


def _calls_skip_patch(m, va):
    # 이미 패치된 함수는 첫 두 명령이 mov/ret 이므로 원래 본문(+8 이후)을 검사한다
    o = m.off(va)
    start = va + 8 if m.data[o:o + 8] == PATCH else va
    return m.calls(start, 32)


# ------------------------------------------------------------- app state ---
def app_info(app):
    if not os.path.isdir(app):
        return None
    with open(os.path.join(app, "Contents/Info.plist"), "rb") as f:
        ver = plistlib.load(f).get("CFBundleShortVersionString")
    r = sh("codesign", "-dv", app, check=False).stderr
    team = re.search(r"TeamIdentifier=(\S+)", r)
    adhoc = "Signature=adhoc" in r
    valid = sh("codesign", "--verify", "--strict", app, check=False).returncode == 0
    try:
        _, _, patched = analyze(os.path.join(app, EXE_REL))
    except StepError as e:
        patched = f"분석 실패: {e}"
    return dict(path=app, version=ver, team=team.group(1) if team else None,
                adhoc=adhoc, valid=valid, patched=patched)


def is_original(info):
    return info and info["team"] == KAKAO_TEAM and info["valid"] and not info["adhoc"]


def backup_path(ver):
    return os.path.join(BACKUP_DIR, f"KakaoTalk-{ver}.app")


def describe(info):
    if not info:
        return "없음"
    signer = "ad-hoc" if info["adhoc"] else info["team"]
    return (f"v{info['version']} / 서명 {signer} ({'유효' if info['valid'] else '무효'})"
            f" / 패치 {info['patched']}")


# ----------------------------------------------------------------- steps ---
def step_inspect():
    if platform.machine() != "arm64":
        raise StepError("Apple Silicon(arm64) Mac 에서만 지원합니다")
    info = app_info(APP)
    if not info:
        raise StepError(f"{APP} 가 없습니다")
    log("1 inspect", f"{APP}: {describe(info)}")
    return info


def migrate_legacy_backup():
    legacy = os.path.join(BACKUP_DIR, "KakaoTalk.app.orig")
    if os.path.isdir(legacy):
        info = app_info(legacy)
        if is_original(info) and not os.path.exists(backup_path(info["version"])):
            os.rename(legacy, backup_path(info["version"]))
            log("2 backup", f"기존 백업을 {backup_path(info['version'])} 로 이름 변경")


def step_backup(info):
    migrate_legacy_backup()
    dst = backup_path(info["version"])
    if os.path.isdir(dst) and is_original(app_info(dst)):
        log("2 backup", f"건너뜀 - 원본 백업 있음: {dst}")
        return dst
    if not is_original(info):
        raise StepError(f"v{info['version']} 원본 백업이 없고, 설치본도 원본이 아닙니다. "
                        "App Store 에서 재설치 후 다시 실행하세요")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    sh("ditto", APP, dst)
    if not is_original(app_info(dst)):
        shutil.rmtree(dst)
        raise StepError("백업 검증 실패")
    log("2 backup", f"원본 백업 완료: {dst}")
    return dst


def step_analyze(src_app):
    target, off, patched = analyze(os.path.join(src_app, EXE_REL))
    if patched:
        raise StepError("원본이어야 할 소스가 이미 패치돼 있습니다")
    log("3 analyze", f"광고 판단 함수 {target:#x} (파일 오프셋 {off:#x})")
    return target


def step_build(src_app, target, force):
    dst = os.path.join(BUILD_DIR, "KakaoTalk.app")
    ver = app_info(src_app)["version"]
    if not force and os.path.isdir(dst):
        b = app_info(dst)
        if b["version"] == ver and b["patched"] is True and b["adhoc"] and b["valid"]:
            log("4 build", f"건너뜀 - 같은 버전 빌드 있음: {dst}")
            return dst
    if os.path.isdir(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
    os.makedirs(BUILD_DIR)
    sh("ditto", src_app, dst)

    exe = os.path.join(dst, EXE_REL)
    t, off, patched = analyze(exe)
    if t != target or patched:
        raise StepError("복사본 분석 결과가 원본과 다릅니다")
    with open(exe, "r+b") as f:
        f.seek(off)
        f.write(PATCH)
    log("4 build", f"패치 적용 ({off:#x})")

    ent = os.path.join(BUILD_DIR, "entitlements.plist")
    with open(ent, "w") as f:
        f.write(sh("codesign", "-d", "--entitlements", "-", "--xml", src_app).stdout)
    sh("codesign", "--force", "--sign", "-", "--entitlements", ent, dst)
    log("4 build", "ad-hoc 재서명 완료 (Hardened Runtime 제외)")
    return dst


def entitlements(app):
    out = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", app],
                         capture_output=True).stdout
    return plistlib.loads(out) if out else {}


def step_verify(build_app, src_app):
    b = app_info(build_app)
    problems = []
    if b["patched"] is not True:
        problems.append("패치 바이트 없음")
    if not (b["adhoc"] and b["valid"]):
        problems.append("서명 무효")
    if "runtime" in sh("codesign", "-dv", build_app, check=False).stderr.split("flags=")[1].split("\n")[0]:
        problems.append("Hardened Runtime 이 남아 있음")
    if entitlements(build_app) != entitlements(src_app):
        problems.append("entitlements 불일치")
    if b["version"] != app_info(src_app)["version"]:
        problems.append("버전 불일치")
    if problems:
        raise StepError("검증 실패: " + ", ".join(problems))
    log("5 verify", f"통과 - {describe(b)}")


def quit_kakao():
    subprocess.run(["osascript", "-e", 'tell application "KakaoTalk" to quit'], capture_output=True)
    for _ in range(10):
        if subprocess.run(["pgrep", "-x", "KakaoTalk"], capture_output=True).returncode:
            return
        time.sleep(1)
    subprocess.run(["pkill", "-x", "KakaoTalk"])
    time.sleep(2)


def admin_replace(src, prompt):
    for p in (src, APP):
        if "'" in p or '"' in p:
            raise StepError(f"경로에 따옴표가 있습니다: {p}")
    cmd = f"rm -rf '{APP}' && ditto '{src}' '{APP}' && chown -R root:wheel '{APP}'"
    r = subprocess.run(["osascript", "-e",
                        f'do shell script "{cmd}" with administrator privileges with prompt "{prompt}"'],
                       capture_output=True, text=True)
    if r.returncode:
        raise StepError(f"관리자 작업 실패/취소: {r.stderr.strip()}")


def step_install(build_app):
    quit_kakao()
    admin_replace(build_app, "광고가 숨겨진 KakaoTalk 패치본을 설치합니다 (원본은 백업됨).")
    log("6 install", f"{APP} 교체 완료")


def step_check(expect_patched=True):
    subprocess.run(["open", "-a", APP])
    time.sleep(8)
    r = subprocess.run(["pgrep", "-fl", "MacOS/KakaoTalk"], capture_output=True, text=True).stdout
    info = app_info(APP)
    ok = APP in r and info["patched"] is expect_patched and info["valid"]
    log("7 check", f"{'정상' if ok else '이상'} - 실행 중: {APP in r} / {describe(info)}")
    if not ok:
        raise StepError("설치 후 확인 실패 - `python3 adblock.py restore` 로 복원할 수 있습니다")


# --------------------------------------------------------------- commands ---
def cmd_run(force, no_install):
    info = step_inspect()
    if info["patched"] is True and info["valid"] and not force:
        log("done", "이미 패치본이 설치돼 있습니다 (--force 로 재적용)")
        return
    backup = step_backup(info)
    target = step_analyze(backup)
    build = step_build(backup, target, force)
    step_verify(build, backup)
    if no_install:
        log("done", f"빌드 완료 (설치 생략): {build}")
        return
    step_install(build)
    step_check()
    log("done", "광고 배너 제거 적용 완료")


def cmd_status():
    migrate_legacy_backup()
    print("설치본:", describe(app_info(APP)))
    if os.path.isdir(BACKUP_DIR):
        for n in sorted(os.listdir(BACKUP_DIR)):
            if n.endswith(".app"):
                print(f"백업 {n}:", describe(app_info(os.path.join(BACKUP_DIR, n))))
    b = os.path.join(BUILD_DIR, "KakaoTalk.app")
    print("빌드:", describe(app_info(b)))


def cmd_restore():
    migrate_legacy_backup()
    info = app_info(APP)
    cand = backup_path(info["version"]) if info else None
    if not cand or not os.path.isdir(cand):
        raise StepError(f"설치본 버전(v{info and info['version']})의 백업이 없습니다")
    if not is_original(app_info(cand)):
        raise StepError("백업 서명이 원본이 아닙니다")
    quit_kakao()
    admin_replace(cand, "KakaoTalk 을 백업한 원본으로 복원합니다.")
    log("restore", "원본 복원 완료")
    step_check(expect_patched=False)


def main():
    args = sys.argv[1:]
    force, no_install = "--force" in args, "--no-install" in args
    args = [a for a in args if not a.startswith("--")]
    cmd = args[0] if args else "run"
    try:
        if cmd == "run":
            cmd_run(force, no_install)
        elif cmd == "status":
            cmd_status()
        elif cmd == "analyze":
            t, o, p = analyze(args[1] if len(args) > 1 else os.path.join(APP, EXE_REL))
            print(f"target={t:#x} file_offset={o:#x} patched={p}")
        elif cmd == "restore":
            cmd_restore()
        else:
            print(__doc__)
            sys.exit(2)
    except StepError as e:
        print(f"중단: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
