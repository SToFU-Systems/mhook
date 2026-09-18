#include <mhook-lib/mhook.h>

static BOOL (*volatile set_hook)(PVOID*, PVOID) = &Mhook_SetHook;
static BOOL (*volatile unhook)(PVOID*) = &Mhook_Unhook;

int main(void)
{
    return (set_hook && unhook) ? 0 : 1;
}
