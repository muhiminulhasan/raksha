#include <windows.h>

int main(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    const char *msg = "hello from packed exe\n";
    DWORD written = 0;
    WriteFile(h, msg, 22, &written, NULL);
    return 0;
}
