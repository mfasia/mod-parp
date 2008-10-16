APACHE_MODPATH_INIT(param_parser)

param_parser_objs="dnl
param_parser.lo dnl
mod_param_parser.lo dnl
"

parp_objs="dnl
param_parser.lo dnl
mod_parp.lo dnl
"

APACHE_MODULE(param_parser, param parser module, $param_parser_objs, , shared)
APACHE_MODULE(parp, parp, $parp_objs, , shared)
APACHE_MODULE(parp_appl, parp test application, , , shared)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH

