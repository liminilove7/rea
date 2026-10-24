#include <idc.idc>
static main()
{
  msg("[REA setup] Retrying the installed IDAPython plugin; database remains open.\n");
  auto ok = load_and_run_plugin("idapython3_64", 3);
  msg("[REA setup] IDAPython plugin returned: %d\n", ok);
}
