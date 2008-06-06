APACHE_MODPATH_INIT(param_parser)

param_parser_objs="dnl
param_parser.lo dnl
mod_param_parser.lo dnl
"

APACHE_MODULE(param_parser, param parser module, $param_parser_objs, , shared)

# Ensure that other modules can pick up hsp util headers 
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH

