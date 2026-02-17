#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/uio.h>

// Для Android ARM64
#define CPSR_T_MASK (1u << 5)

long get_module_base(pid_t pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) snprintf(filename, sizeof(filename), "/proc/self/maps");
    else snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <pid> <path_to_so>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    const char *library_path = argv[2];

    // 1. Находим адреса dlopen
    long local_linker_base = get_module_base(-1, "linker64");
    long remote_linker_base = get_module_base(target_pid, "linker64");
    
    // В Android dlopen находится внутри linker или libdl, зависит от версии.
    // Упрощенный вариант: ищем __loader_dlopen в self и считаем смещение
    void *local_dlopen = dlsym(NULL, "__loader_dlopen");
    if (!local_dlopen) local_dlopen = dlsym(NULL, "dlopen"); // Фолбэк
    
    if (!local_dlopen) {
        printf("[-] Could not find dlopen symbol\n");
        return 1;
    }

    long offset = (long)local_dlopen - local_linker_base;
    long remote_dlopen = remote_linker_base + offset;

    printf("[+] Remote dlopen: %lx\n", remote_dlopen);

    // 2. Аттачимся
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_ATTACH failed");
        return 1;
    }
    waitpid(target_pid, NULL, 0);

    // 3. Сохраняем регистры
    struct user_pt_regs regs, original_regs;
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);
    ptrace(PTRACE_GETREGSET, target_pid, NT_PRSTATUS, &io);
    memcpy(&original_regs, &regs, sizeof(regs));

    // 4. Вызываем dlopen(library_path, RTLD_NOW)
    // В ARM64: X0 = arg1, X1 = arg2, LR = return address, PC = function
    
    // Пишем путь к либе в стек
    long sp = regs.sp;
    sp -= (strlen(library_path) + 1 + 16) & ~0xF; // Выравнивание
    
    // Запись строки в память процесса
    // (Упрощенно через ptrace POKE - медленно, но работает)
    for (int i = 0; i <= strlen(library_path); i += 8) {
        long val = 0;
        memcpy(&val, library_path + i, 8); // берем 8 байт из строки
        // Внимание: копирование хвоста строки может захватить мусор, но для путей это не критично
        // Лучше использовать process_vm_writev, но ptrace проще для примера
        ptrace(PTRACE_POKETEXT, target_pid, sp + i, val);
    }
    
    regs.regs[0] = sp;          // 1 аргумент: путь
    regs.regs[1] = RTLD_NOW;    // 2 аргумент: флаг
    regs.regs[30] = 0;          // LR (адрес возврата) - 0 вызовет крэш, который мы поймаем
    regs.pc = remote_dlopen;    // PC - адрес функции
    
    io.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, target_pid, NT_PRSTATUS, &io);

    // 5. Запускаем выполнение
    ptrace(PTRACE_CONT, target_pid, NULL, NULL);
    
    // Ждем, пока процесс упадет (из-за LR=0), это значит функция выполнилась
    waitpid(target_pid, NULL, 0);

    // 6. Восстанавливаем всё как было
    io.iov_base = &original_regs;
    ptrace(PTRACE_SETREGSET, target_pid, NT_PRSTATUS, &io);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

    printf("[+] Injection completed!\n");
    return 0;
}

