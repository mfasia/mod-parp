mod_parp.la: mod_parp.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_parp.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_parp.la
