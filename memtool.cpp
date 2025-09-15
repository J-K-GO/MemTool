// memtool.cpp
// UTF-16 콘솔 안정 입출력 + UTF-16LE 문자열 스캔/치환 + 보호 변경 패치 (읽기전용/IMAGE)
// + SeDebugPrivilege 활성화 + 패치 실패 원인 진단 로그
// Commands: detail <idx[,..]> | patch <idx[,..]|all> | find | new | quit
//
// 빌드: cl /std:c++17 /W4 /DUNICODE /DWIN32_LEAN_AND_MEAN /EHsc memtool.cpp user32.lib kernel32.lib
// 사용: memtool.exe [PID]
//
// 주의: 반드시 본인이 소유/허가된 프로세스에서만 사용하세요.

#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

struct Hit { BYTE* address; SIZE_T matchBytes; };

/* ===================== 콘솔 유틸: 항상 UTF-16로 안전 출력/입력 ===================== */

static void EnsureConsole() {
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();
        FILE* f;
        freopen_s(&f, "CONIN$", "r", stdin);
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
    }
}

static void PrintW(const std::wstring& s, bool nl = true) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    WriteConsoleW(h, s.c_str(), (DWORD)s.size(), &w, nullptr);
    if (nl) WriteConsoleW(h, L"\r\n", 2, &w, nullptr);
}
static void PrintF(const wchar_t* fmt, ...) {
    wchar_t buf[4096];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    PrintW(buf, false);
}
static std::wstring ReadLineW() {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    wchar_t buf[8192];
    DWORD n = 0;
    if (!ReadConsoleW(h, buf, _countof(buf) - 1, &n, nullptr) || n == 0) return L"";
    // CR/LF 제거
    while (n && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n')) --n;
    buf[n] = 0;
    return std::wstring(buf, n);
}
static std::wstring Trim(const std::wstring& s) {
    auto ws = [](wchar_t c) {return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; };
    size_t b = 0, e = s.size(); while (b < e && ws(s[b]))++b; while (e > b && ws(s[e - 1]))--e; return s.substr(b, e - b);
}

/* ===================== 권한 유틸 ===================== */

static bool EnableDebugPrivilege() {
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken); return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return (err == ERROR_SUCCESS);
}

/* ===================== 메모리 스캔/패치 유틸 ===================== */

static bool IsReadableProtect(DWORD p) {
    if (p & PAGE_GUARD) return false;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
        p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static std::vector<size_t> ParseIndices(const std::wstring& line, size_t maxN, bool& isAll) {
    std::vector<size_t> out; std::wstring s = Trim(line); isAll = (_wcsicmp(s.c_str(), L"all") == 0);
    if (isAll) return out;
    std::wstringstream ss(s); std::wstring tok;
    while (std::getline(ss, tok, L',')) {
        tok = Trim(tok); if (tok.empty()) continue;
        wchar_t* ep = nullptr; unsigned long v = wcstoul(tok.c_str(), &ep, 10);
        if (ep && *ep == 0 && v < maxN) out.push_back((size_t)v);
    }
    std::sort(out.begin(), out.end()); out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

static std::wstring ReadWString(HANDLE hProc, BYTE* addr, size_t maxChars = 256) {
    std::wstring out; out.reserve(maxChars);
    for (size_t i = 0; i < maxChars; i++) {
        wchar_t ch = 0; SIZE_T got = 0;
        if (!ReadProcessMemory(hProc, addr + i * 2, &ch, sizeof(ch), &got) || got != sizeof(ch)) break;
        if (ch == L'\0') break;
        out.push_back(ch < 0x20 ? L'·' : ch);
    }
    return out;
}
static std::wstring HexPreview(HANDLE hProc, BYTE* addr, size_t bytes = 32) {
    std::vector<BYTE> buf(bytes); SIZE_T got = 0; ReadProcessMemory(hProc, addr, buf.data(), bytes, &got);
    std::wstringstream ss; ss << std::hex << std::setfill(L'0');
    for (size_t i = 0; i < got; i++) ss << std::setw(2) << (unsigned)buf[i] << L' ';
    return ss.str();
}

static std::vector<Hit> ScanUTF16(HANDLE hProc, const std::wstring& needle, bool onlyPrivate) {
    std::vector<Hit> hits;
    const SIZE_T m = needle.size() * sizeof(wchar_t);
    if (m == 0) return hits;
    const wchar_t first = needle[0];
    const BYTE* pat = reinterpret_cast<const BYTE*>(needle.c_str());

    SYSTEM_INFO si; GetSystemInfo(&si);
    BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* maxA = (BYTE*)si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < maxA && VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && IsReadableProtect(mbi.Protect) &&
            (!onlyPrivate || mbi.Type == MEM_PRIVATE))
        {
            SIZE_T region = mbi.RegionSize;
            std::vector<BYTE> buf(region);
            SIZE_T got = 0;
            if (ReadProcessMemory(hProc, addr, buf.data(), region, &got) && got > 0) {
                for (SIZE_T i = 0; i + m <= got; i += 2) { // UTF-16 정렬
                    if (*(wchar_t*)(buf.data() + i) != first) continue;
                    if (memcmp(buf.data() + i, pat, m) == 0) hits.push_back({ addr + i, m });
                }
            }
        }
        addr += mbi.RegionSize;
    }
    return hits;
}

/* ===== 페이지 보호 임시 변경/복원 ===== */

static SIZE_T PageSize() { static SIZE_T s = 0; if (!s) { SYSTEM_INFO si; GetSystemInfo(&si); s = si.dwPageSize; } return s; }

static bool MakeWritableRange(HANDLE hProc, BYTE* start, SIZE_T len,
    std::vector<std::pair<LPVOID, DWORD>>& saved) {
    SIZE_T page = PageSize();
    BYTE* cur = (BYTE*)((ULONG_PTR)start & ~(page - 1));
    BYTE* endp = start + len;

    while (cur < endp) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProc, cur, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
        BYTE* regionEnd = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        BYTE* next = (BYTE*)std::min((ULONG_PTR)regionEnd, (ULONG_PTR)endp);
        if (mbi.Protect & PAGE_GUARD) return false;

        // 🔹 이미 쓰기 가능한 보호면 건너뜀
        bool writable = (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY ||
            mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY);
        if (!writable) {
            DWORD want = PAGE_READWRITE;
            if (mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ ||
                mbi.Protect == PAGE_EXECUTE_WRITECOPY)
                want = PAGE_EXECUTE_READWRITE;

            DWORD oldProt = 0;
            SIZE_T span = (SIZE_T)(next - (BYTE*)mbi.BaseAddress);
            if (!VirtualProtectEx(hProc, mbi.BaseAddress, span, want, &oldProt)) {
                if (want == PAGE_EXECUTE_READWRITE) {
                    if (!VirtualProtectEx(hProc, mbi.BaseAddress, span, PAGE_READWRITE, &oldProt))
                        return false;
                }
                else {
                    return false;
                }
            }
            saved.push_back({ mbi.BaseAddress, oldProt });
        }
        cur = next;
    }
    return true;
}


static void RestoreProtectRange(HANDLE hProc, const std::vector<std::pair<LPVOID, DWORD>>& saved) {
    for (auto it = saved.rbegin(); it != saved.rend(); ++it) {
        DWORD tmp = 0; VirtualProtectEx(hProc, it->first, PageSize(), it->second, &tmp);
    }
}

/* ===== 진단 보조 ===== */

static std::wstring ProtToStr(DWORD p) {
    if (p & PAGE_GUARD) return L"GUARD";
    switch (p) {
    case PAGE_NOACCESS: return L"NOACCESS";
    case PAGE_READONLY: return L"R";
    case PAGE_READWRITE: return L"RW";
    case PAGE_WRITECOPY: return L"WC";
    case PAGE_EXECUTE: return L"X";
    case PAGE_EXECUTE_READ: return L"XR";
    case PAGE_EXECUTE_READWRITE: return L"XRW";
    case PAGE_EXECUTE_WRITECOPY: return L"XWC";
    default: return L"?";
    }
}
static std::wstring TypeToStr(DWORD t) {
    switch (t) {
    case MEM_PRIVATE: return L"PRIVATE";
    case MEM_MAPPED:  return L"MAPPED";
    case MEM_IMAGE:   return L"IMAGE";
    default: return L"?";
    }
}

/* ===== 쓰기(보호 변경 포함) + 실패 이유 로깅 ===== */

static size_t g_failShown = 0;
static const size_t g_failShowMax = 8;

// 새 헬퍼: 실패할 때만 보호 변경
static bool PatchAt(HANDLE hProc, const Hit& h, const std::wstring& repl) {
    const SIZE_T rep = repl.size() * sizeof(wchar_t);
    SIZE_T toWrite = std::min(rep, h.matchBytes);

    // 0) 먼저 그냥 써보기
    SIZE_T wrote = 0;
    BOOL ok = WriteProcessMemory(hProc, h.address, repl.c_str(), toWrite, &wrote);

    // 패딩까지 포함
    if (ok && wrote == toWrite && toWrite < h.matchBytes) {
        SIZE_T pad = h.matchBytes - toWrite; std::vector<BYTE> zeros(pad, 0);
        SIZE_T w2 = 0; ok = WriteProcessMemory(hProc, h.address + toWrite, zeros.data(), pad, &w2) && (w2 == pad);
    }
    if (ok) return true; // 여기서 끝나면 보호 변경 불필요

    // 1) 실패하면 그때만 보호 변경 시도
    std::vector<std::pair<LPVOID, DWORD>> saved;
    if (!MakeWritableRange(hProc, h.address, h.matchBytes, saved)) {
        // (선택) 진단 로그
        MEMORY_BASIC_INFORMATION mbi{}; VirtualQueryEx(hProc, h.address, &mbi, sizeof(mbi));
        PrintF(L"[ProtectFail] addr=%p type=%lu prot=%lu err=%lu\r\n",
            h.address, mbi.Type, mbi.Protect, GetLastError());
        return false;
    }

    // 2) 다시 쓰기
    wrote = 0;
    ok = WriteProcessMemory(hProc, h.address, repl.c_str(), toWrite, &wrote);

    if (ok && wrote == toWrite && toWrite < h.matchBytes) {
        SIZE_T pad = h.matchBytes - toWrite; std::vector<BYTE> zeros(pad, 0);
        SIZE_T w2 = 0; ok = WriteProcessMemory(hProc, h.address + toWrite, zeros.data(), pad, &w2) && (w2 == pad);
    }

    RestoreProtectRange(hProc, saved);
    if (!ok) {
        MEMORY_BASIC_INFORMATION mbi{}; VirtualQueryEx(hProc, h.address, &mbi, sizeof(mbi));
        PrintF(L"[WriteFail] addr=%p type=%lu prot=%lu err=%lu\r\n",
            h.address, mbi.Type, mbi.Protect, GetLastError());
    }
    return ok ? true : false;
}


/* ===================== 메인 ===================== */

int wmain(int argc, wchar_t* argv[]) {
    EnsureConsole();

    // 디버그 권한 시도 (관리자 권한이면 주로 성공)
    if (EnableDebugPrivilege())
        PrintW(L"[i] SeDebugPrivilege enabled");
    else
        PrintW(L"[i] SeDebugPrivilege not enabled (continue)");

    DWORD pid = 0;
    if (argc >= 2) {
        pid = (DWORD)wcstoul(argv[1], nullptr, 10);
        if (!pid) { PrintW(L"[!] 잘못된 PID 인자"); return 2; }
        PrintF(L"[i] PID: %lu\r\n", pid);
    }
    else {
        PrintW(L"Target PID: ", false);
        std::wstring pidStr = ReadLineW(); pid = (DWORD)wcstoul(pidStr.c_str(), nullptr, 10);
        if (!pid) { PrintW(L"[!] Invalid PID"); return 2; }
    }

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        PrintF(L"[!] OpenProcess 실패: %lu\r\n", GetLastError());
        return 3;
    }

    size_t pageSize = 200;
    bool onlyPrivate = true;

    std::wstring findText;
    std::vector<Hit> hits;

    while (true) {
        if (findText.empty()) {
            PrintW(L"\n찾을 문자열 입력 (UTF-16, 비우면 종료): ", false);
            findText = Trim(ReadLineW());
            if (findText.empty()) break;

            PrintW(L"MEM_PRIVATE 만 스캔? (Y/n): ", false);
            std::wstring yn = ReadLineW();
            onlyPrivate = !(!yn.empty() && (yn[0] == L'n' || yn[0] == L'N'));

            PrintW(L"페이지 출력 행수 (기본 200): ", false);
            std::wstring ps = Trim(ReadLineW());
            if (!ps.empty()) {
                size_t v = (size_t)wcstoul(ps.c_str(), nullptr, 10);
                if (v > 0) pageSize = v;
            }
        }

        PrintW(L"[*] Scanning fast...");
        hits = ScanUTF16(hProc, findText, onlyPrivate);
        PrintF(L"[+] Matches: %zu\r\n", hits.size());
        if (hits.empty()) { findText.clear(); continue; }

        // 주소만 빠르게 페이지 출력
        size_t shown = 0;
        while (shown < hits.size()) {
            size_t end = std::min(shown + pageSize, hits.size());
            for (size_t i = shown; i < end; ++i) {
                std::wstringstream ss; ss << i << L") " << (void*)hits[i].address;
                PrintW(ss.str());
            }
            shown = end;
            if (shown >= hits.size()) break;
            PrintW(L"-- 더 보기 Enter / 중단 q: ", false);
            std::wstring cmd = ReadLineW();
            if (!cmd.empty() && (cmd[0] == L'q' || cmd[0] == L'Q')) break;
        }

        // 명령 루프
        while (true) {
            PrintW(L"\n명령: detail <idx[,..]> | patch <idx[,..]|all> | find | new | quit");
            PrintW(L"> ", false);
            std::wstring line = ReadLineW(); if (line.empty()) { PrintW(L""); return 0; }
            std::wstringstream ss(line); std::wstring cmd; ss >> cmd; cmd = Trim(cmd);
            if (cmd.empty()) continue;

            if (!_wcsicmp(cmd.c_str(), L"quit") || !_wcsicmp(cmd.c_str(), L"q")) { CloseHandle(hProc); return 0; }
            if (!_wcsicmp(cmd.c_str(), L"find") || !_wcsicmp(cmd.c_str(), L"f")) { break; }
            if (!_wcsicmp(cmd.c_str(), L"new") || !_wcsicmp(cmd.c_str(), L"n")) { findText.clear(); break; }

            if (!_wcsicmp(cmd.c_str(), L"detail") || !_wcsicmp(cmd.c_str(), L"d")) {
                std::wstring idxs; std::getline(ss, idxs); idxs = Trim(idxs);
                bool isAll = false; auto vi = ParseIndices(idxs, hits.size(), isAll);
                if (isAll) { vi.resize(hits.size()); for (size_t i = 0; i < hits.size(); ++i) vi[i] = i; }
                if (vi.empty()) { PrintW(L"[!] 인덱스 필요"); continue; }
                for (auto i : vi) {
                    auto& h = hits[i];
                    auto val = ReadWString(hProc, h.address);
                    auto hex = HexPreview(hProc, h.address, 32);
                    std::wstringstream os;
                    os << i << L") " << (void*)h.address << L" | 값: \"" << val << L"\" | hex: " << hex;
                    PrintW(os.str());
                }
                continue;
            }

            if (!_wcsicmp(cmd.c_str(), L"patch") || !_wcsicmp(cmd.c_str(), L"p")) {
                std::wstring sel; ss >> sel; sel = Trim(sel);
                bool isAll = false; auto vi = ParseIndices(sel, hits.size(), isAll);
                if (isAll) { vi.resize(hits.size()); for (size_t i = 0; i < hits.size(); ++i) vi[i] = i; }
                if (vi.empty()) { PrintW(L"[!] 인덱스(또는 all) 필요"); continue; }
                PrintW(L"치환할 문자열(UTF-16): ", false);
                std::wstring repl = Trim(ReadLineW());
                g_failShown = 0; // 새 라운드에서 다시 몇 건만 진단 표시
                size_t patched = 0; for (auto i : vi) if (PatchAt(hProc, hits[i], repl)) ++patched;
                std::wstringstream os; os << L"[+] Patched " << patched << L"/" << vi.size();
                PrintW(os.str());
                continue;
            }

            PrintW(L"[!] Unknown command");
        }
    }

    CloseHandle(hProc);
    PrintW(L"Bye");
    return 0;
}
