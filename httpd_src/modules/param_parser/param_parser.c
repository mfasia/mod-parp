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
#include <apr_strings.h>
#include <apr_buckets.h>
#include <apr_hash.h>

/* self */
#include "param_parser.h" 
/**************************************************************************
 * Private 
 **************************************************************************/
struct parp_s {
  apr_pool_t *pool;
  request_rec *r;
  apr_bucket_brigade *bb;
  apr_table_t *params;
  apr_hash_t *parsers;
  char *error; 
  int flags;
};

typedef apr_status_t (*parp_parser_f)(parp_t *, apr_table_t *, char *, 
                                      apr_size_t);

/**
 * Read payload of this request
 *
 * @param r IN request record
 * @param data OUT flatten payload
 * @param len OUT len of payload
 *
 * @return APR_SUCCESS, any apr status code on error
 */
static apr_status_t parp_get_payload(parp_t *self, char **data, 
                                     apr_size_t *len) {
  apr_status_t status;
  apr_bucket_brigade *bb;
  apr_bucket *b;
  const char *buf;
  apr_size_t buflen;

  request_rec *r = self->r;
  int seen_eos = 0;

  if ((status = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)) != OK) {
    self->error = apr_pstrdup(r->pool, "ap_setup_client_block failed");
    return status;
  }

  bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

  do {
    status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
 
    if (status == APR_SUCCESS) {
      for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb);
	  b = APR_BUCKET_NEXT(b))
      {
	status = apr_bucket_read(b, &buf, &buflen, APR_BLOCK_READ);
	if (status != APR_SUCCESS) {   
	  self->error = apr_pstrdup(r->pool, "Input filter: Failed reading input");
          return status;
	}

	if (APR_BUCKET_IS_EOS(b)) {
	    seen_eos = 1;
	}
      }

      APR_BRIGADE_CONCAT(self->bb, bb);
      apr_brigade_cleanup(bb);
    }
    else {
      seen_eos = 1;
    }
  } while (!seen_eos);
  
  
  return apr_brigade_pflatten(self->bb, data, len, r->pool);
}

/**
 * read the content type contents
 *
 * @param self IN instance
 * @param headers IN headers
 * @param result OUT
 *
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t parp_read_content_type(parp_t *self, apr_table_t *headers, 
                                           apr_table_t **result) {
  const char *rest;
  const char *ct;
  const char *pair;
  const char *key;
  const char *val;

  apr_table_t *tl = apr_table_make(self->pool, 3);
  
  *result = tl;
  ct = apr_table_get(headers, "Content-Type");
  if (ct == NULL) {
    return APR_EINVAL;
  }

  rest = ct;
  /* iterate over multipart key/value pairs */
  while (rest[0]) {
    pair = ap_getword(self->pool, &rest, ';');
    /* eat spaces */
    while (*pair == ' ') {
      ++pair;
    }
    /* get key/value */
    val = pair;
    key = ap_getword(self->pool, &val, '=');
    if (key) {
      apr_table_addn(tl, key, val);
    }
  }
  
  return APR_SUCCESS;
}

/**
 * read the all boundaries 
 *
 * @param self IN instance
 * @param data IN data to parse
 * @param len IN len of data
 * @param tag IN boundary tag
 * @param result OUT table of boundaries
 *
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t parp_read_boundaries(parp_t *self, char *data, 
                                         apr_size_t len, const char *tag,
					 apr_table_t **result) {
  apr_status_t status;
  apr_size_t i;
  apr_size_t start;
  apr_size_t match;
  apr_size_t tag_len;
  apr_table_t *tl;
  
  tl = apr_table_make(self->pool, 5);
  *result = tl;
  tag_len = strlen(tag);
  for (i = 0, match = 0, start = 0; i < len; i++) {
    /* test if match complete */
    if (match == tag_len) {
      /* prepare data */
      data[i - match] = 0;
      if (strncmp(&data[start], "\r\n", 2) == 0) {
	start += 2;
      }
      else if (data[start] == '\n') {
	start += 1;
      }
      /* got it, store it */
      if (data[start]) {
	apr_table_addn(tl, tag, &data[start]);
      }
      start = i;
    }
    /* pattern matching */
    if (match < tag_len && data[i] == tag[match]) {
      ++match;
    }
    else {
      match = 0;
    }
  }

  return APR_SUCCESS;
}

/**
 * Get headers from data, all lines until first empty line will be 
 * split into header/value stored in the headers table.
 *
 * @param self IN instance
 * @param data IN data
 * @param len IN len of data
 * @param headers OUT found headers
 *
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t parp_get_headers(parp_t *self, char **rdata, apr_size_t len,
                                     apr_table_t **headers) {
  apr_size_t i;
  apr_size_t start;
  char *last;
  char *key;
  char *val;
  char *data = *rdata;

  apr_table_t *tl = apr_table_make(self->pool, 3);
  *headers = tl;
  
  for (i = 0, start = 0; i < len; i++) {
    if (((len - i) >= 2 && strncmp(&data[i], "\r\n", 2) == 0) ||
	((len - i) == 1 && data[i] == '\n')) {
      /* end of line reached */
      data[i - 1] = 0;
      if (strncmp(&data[i], "\r\n", 2) == 0) {
	i += 1;
      }
      
      /** finished */
      if (!data[start]) {
        *rdata = &data[i];
	return APR_SUCCESS;
      }
      
      /* split header name and value */
      key = apr_strtok(&data[start], ":", &last); 
      val = apr_strtok(NULL, ":", &last);
      if (val) {
	while (*val == ' ') ++val;
      }
      apr_table_addn(tl, key, val);

      start = i;
    }
  }

  return APR_EINVAL;
}

/**
 * Urlencode parser
 *
 * @param self IN instance
 * @param headers IN headers with additional data 
 * @param data IN data with urlencoded content
 * @param len IN len of data
 *
 * @return APR_SUCCESS or APR_EINVAL on parser error
 *
 * @note: Get parp_get_error for more detailed report
 */
static apr_status_t parp_urlencode(parp_t *self, apr_table_t *headers,
                                   const char *data, apr_size_t len) {
  apr_status_t status;
  char *key;
  char *val;
  char *pair;

  const char *rest = data;
  
  while (rest[0]) {
    pair = ap_getword(self->pool, &rest, '&');
    /* get key/value */
    val = pair;
    key = ap_getword_nc(self->pool, &val, '=');
    if (key) {
      /* store it to a table */
      apr_table_addn(self->params, key, val);
    }
  }
  
  return APR_SUCCESS;
}

/**
 * Multipart parser
 *
 * @param self IN instance
 * @param headers IN headers with additional data 
 * @param data IN data
 * @param len IN len of data
 *
 * @return APR_SUCCESS or APR_EINVAL on parser error
 *
 * @note: Get parp_get_error for more detailed report
 */
static apr_status_t parp_multipart(parp_t *self, apr_table_t *headers, 
                                   char *data, apr_size_t len) {
  apr_status_t status;
  apr_size_t val_len;
  const char *boundary;
  apr_table_t *ctt;
  apr_table_t *bs;
  apr_table_entry_t *e;
  int i;
  char *bdata;

  apr_table_t *hs = apr_table_make(self->pool, 3);
  
  if ((status = parp_read_content_type(self, headers, &ctt)) != APR_SUCCESS) {
    return status;
  }

  if (!(boundary = apr_table_get(ctt, "boundary"))) {
    return APR_EINVAL;
  }
  
  /* prefix boundary wiht a -- */
  boundary = apr_pstrcat(self->pool, "--", boundary, NULL);

  if ((status = parp_read_boundaries(self, data, len, boundary, &bs)) != APR_SUCCESS) {
    return status;
  }
  
  /* iterate over boundaries and store their param/value pairs */ 
  e = (apr_table_entry_t *) apr_table_elts(bs)->elts;
  for (i = 0; i < apr_table_elts(bs)->nelts; ++i) {
    /* read boundary headers */
    bdata = e[i].val;
    if ((status = parp_get_headers(self, &bdata, strlen(bdata), &hs))) {
      return status;
    }
    /* get content type */
    /* call corresponding parser */
  }
    
  /* now do all boundaries */
  return APR_SUCCESS;
}

/**
 * Not implemented parser used if there is no corresponding parser found
 *
 * @param self IN instance
 * @param headers IN headers with additional data 
 * @param data IN data with urlencoded content
 * @param len IN len of data
 *
 * @return APR_ENOTIMPL
 */
static apr_status_t parp_not_impl(parp_t *self, apr_table_t *headers, 
                                  char *data, apr_size_t len) {
  return APR_ENOTIMPL;
}

/**
 * Get content type parser
 *
 * @param self IN instance
 * @param ct IN content type (or NULL)
 *
 * @return content type parser
 */
static parp_parser_f parp_get_parser(parp_t *self, const char *ct) {
  const char *lct;
  const char *type;

  parp_parser_f parser = NULL;
  
  if (ct) {
    lct = ct;
    type = ap_getword(self->pool, &lct, ';');
    if (type) {
      parser = apr_hash_get(self->parsers, type, APR_HASH_KEY_STRING);
    }
  }
  if (parser) {
    return parser;
  }
  else {
    return parp_not_impl;
  }
}

/**************************************************************************
 * Public
 **************************************************************************/
/**
 * Creates a new parameter parser.
 *
 * @param r IN request record
 *
 * @return new parameter parser instance
 */
AP_DECLARE(parp_t *) parp_new(request_rec *r, int flags) {
  parp_t *self = apr_pcalloc(r->pool, sizeof(parp_t));

  self->pool = r->pool;
  self->r = r;
  self->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
  self->params = apr_table_make(r->pool, 5);
  self->parsers = apr_hash_make(r->pool);
  apr_hash_set(self->parsers, "application/x-www-form-urlencoded", 
               APR_HASH_KEY_STRING, parp_urlencode);
  apr_hash_set(self->parsers, "multipart/form-data", 
               APR_HASH_KEY_STRING, parp_multipart);
  self->flags = flags;

  return self;
}

/**
 * Get all parameter/value pairs in this request
 *
 * @param self IN instance
 * @param params OUT table of key/value pairs
 *
 * @return APR_SUCCESS or APR_EINVAL on parser errors
 *
 * @note: see parap_error(self) for detailed error message
 */
AP_DECLARE(apr_status_t) parp_read_params(parp_t *self) {
  apr_status_t status;
  char *data;
  apr_size_t len;
  parp_parser_f parser;

  request_rec *r = self->r;
  
  if (r->method_number == M_POST) {
    if (r->args) {
      if ((status = parp_urlencode(self, r->headers_in, r->args, strlen(r->args))) 
	  != APR_SUCCESS) {
	return status;
      }
    }
    if ((status = parp_get_payload(self, &data, &len)) != APR_SUCCESS) {
      return status;
    }
    if (len > 2 && strncmp(&data[len-2], "\r\n", 2) == 0) {
      /* cut away the leading \r\n */
      data[len-2] = 0;
    }
    else if (len > 1 && data[len -1] == '\n'){
      /* cut away the leading \n */
      data[len-1] = 0;
    }
    else {
      data[len] = 0;
    }
    parser = parp_get_parser(self, apr_table_get(r->headers_in, 
	                                         "Content-Type"));  
    if ((status = parser(self, r->headers_in, data, len)) != APR_SUCCESS) {
      return status;
    }

  }
  else if (r->method_number == M_GET) {
    if (r->args) {
      if ((status = parp_urlencode(self, r->headers_in, r->args, strlen(r->args))) 
	  != APR_SUCCESS) {
	return status;
      }
    }
  }
  return APR_SUCCESS;
}

/**
 * Forward all data back to request.
 *
 * @param f IN filter
 * @param bb IN bucket brigade
 * @param mode IN 
 * @param block IN block mode
 * @param nbytes IN requested bytes
 *
 * @return any apr status
 */
AP_DECLARE (apr_status_t) parp_forward_filter(ap_filter_t * f, 
                                              apr_bucket_brigade * bb, 
					      ap_input_mode_t mode, 
					      apr_read_type_e block, 
					      apr_off_t nbytes) {
  apr_status_t rv;
  apr_bucket *e;
  apr_size_t len;
  const char *buf;

  apr_off_t read = 0;
  parp_t *self = f->ctx;

  /* do never send a bigger brigade than request with "nbytes"! */
  while (read < nbytes && !APR_BRIGADE_EMPTY(self->bb)) {
    e = APR_BRIGADE_FIRST(self->bb);
    rv = apr_bucket_read(e, &buf, &len, block);

    if (rv != APR_SUCCESS) {
      return rv;
    }

    if (len + read > nbytes) {
      apr_bucket_split(e, nbytes - read);
      APR_BUCKET_REMOVE(e);
      APR_BRIGADE_INSERT_TAIL(bb, e);
      return APR_SUCCESS;
    }

    APR_BUCKET_REMOVE(e);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    read += len; 
  }
  
  if (APR_BRIGADE_EMPTY(self->bb)) {
    /* our work is done so remove this filter */
    ap_remove_input_filter(f);
  }

  return APR_SUCCESS;
}

/**
 * Get all parameter/value pairs in this request
 *
 * @param self IN instance
 * @param params OUT table of key/value pairs
 *
 * @return APR_SUCCESS
 */
AP_DECLARE(apr_status_t) parp_get_params(parp_t *self, apr_table_t **params) {
  *params = self->params;
  return APR_SUCCESS;
}

/**
 * Get error message on error
 *
 * @param self IN instance
 *
 * @return error message, empty message or NULL if instance not valid
 */
AP_DECLARE(const char *) parp_get_error(parp_t *self) {
  if (self && self->error) {
    return apr_pstrdup(self->pool, self->error);
  }
  else {
    return NULL;
  }
}

