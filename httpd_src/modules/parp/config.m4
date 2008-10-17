APACHE_MODPATH_INIT(parp)

parp_objs="dnl
param_parser.lo dnl
mod_parp.lo dnl
"

APACHE_MODULE(parp, parp, $parp_objs, , shared)
APACHE_MODULE(parp_appl, parp test application, , , shared)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH

