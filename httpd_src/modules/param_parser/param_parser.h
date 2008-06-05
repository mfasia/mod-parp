/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 * The line above sets XEmacs indention to offset 2,
 * and does not insert tabs
 */

/**
 * @file
 * Header file for mod_http_1_1_gateway.c.
 * Exports used by other modules
 */

#ifndef PARAM_PARSER_H
#define PARAM_PARSER_H

#ifdef __cplusplus
extern "C" {
#ifndef undef
} /* Cheat xemacs auto indention */
#endif
#endif

/**************************************************************************
 * Public 
 **************************************************************************/
typedef struct parp_s parp_t;

AP_DECLARE(parp_t *) parp_new(request_rec *r);
AP_DECLARE(apr_status_t) parp_get_params(parp_t *self, apr_table_t **params);
AP_DECLARE (apr_status_t) parp_forward_filter(ap_filter_t * f, 
                                              apr_bucket_brigade * bb, 
					      ap_input_mode_t mode, 
					      apr_read_type_e block, 
					      apr_off_t nbytes); 

#ifdef __cplusplus
}
#endif

#endif 
