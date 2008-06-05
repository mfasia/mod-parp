/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 * The line above sets XEmacs indention to offset 2,
 * and does not insert tabs
 */

/**
 * @file
 */

/************************************************************************
 * Includes
 ***********************************************************************/
/* apache */
#include <httpd.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <util_filter.h>

/* apr */
#include <apr_buckets.h>

/* self */
#include "param_parser.h" 
/**************************************************************************
 * Private 
 **************************************************************************/
/**************************************************************************
 * Public
 **************************************************************************/
struct parp_s {
  int dummy;
};

AP_DECLARE(parp_t *) parp_new(request_rec *r);
AP_DECLARE(apr_status_t) parp_get_params(parp_t *self, apr_table_t **params);
AP_DECLARE (apr_status_t) parp_forward_filter(ap_filter_t * f, 
                                              apr_bucket_brigade * bb, 
					      ap_input_mode_t mode, 
					      apr_read_type_e block, 
					      apr_off_t nbytes); 

