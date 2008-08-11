/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 * The line above sets XEmacs indention to offset 2,
 * and does not insert tabs
 */

/**
 * @file
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

#define PARP_FLAGS_NONE 0
#define PARP_FLAGS_CONT_ON_ERR 1
AP_DECLARE(parp_t *) parp_new(request_rec *r, int flags);
AP_DECLARE(apr_status_t) parp_read_params(parp_t *self);
AP_DECLARE (apr_status_t) parp_forward_filter(ap_filter_t * f, 
                                              apr_bucket_brigade * bb, 
					      ap_input_mode_t mode, 
					      apr_read_type_e block, 
					      apr_off_t nbytes); 
AP_DECLARE(apr_status_t) parp_get_params(parp_t *self, apr_table_t **params);
AP_DECLARE(const char *) parp_get_error(parp_t *self); 

/**************************************************************************
 * Hooks 
 **************************************************************************/

/* Create a set of PARP_DECLARE(type), PARP_DECLARE_NONSTD(type) and 
 * PARP_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define PARP_DECLARE(type)            type
#define PARP_DECLARE_NONSTD(type)     type
#define PARP_DECLARE_DATA
#elif defined(PARP_DECLARE_STATIC)
#define PARP_DECLARE(type)            type __stdcall
#define PARP_DECLARE_NONSTD(type)     type
#define PARP_DECLARE_DATA
#elif defined(PARP_DECLARE_EXPORT)
#define PARP_DECLARE(type)            __declspec(dllexport) type __stdcall
#define PARP_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define PARP_DECLARE_DATA             __declspec(dllexport)
#else
#define PARP_DECLARE(type)            __declspec(dllimport) type __stdcall
#define PARP_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define PARP_DECLARE_DATA             __declspec(dllimport)
#endif

/**
 * Optional hook.  Unlike static hooks, this uses a macro
 * instead of a function.
 */
#define PARP_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(parp,name,fn,pre,succ,order)
/**
 * The hooks do return DECLINED if not registered any hooks. Do return
 * OK or HTTP_INTERNAL_SERVER_ERROR.  
 */
APR_DECLARE_EXTERNAL_HOOK(parp, PARP, int, validate, 
			  (request_rec *r, apr_table_t *params,
			   apr_status_t status, const char *error))


#ifdef __cplusplus
}
#endif

#endif 
