#include <sys/sdt.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int idx = 0;
    while(1) {
        idx++;
        // 自定义的tracepoint
        DTRACE_PROBE1(test_grp, test_idx, idx);
        sleep(1);
    }
    return 0;
}

