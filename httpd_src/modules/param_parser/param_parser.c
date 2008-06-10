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
  char *error; 
  int flags;
  parp_byte_range_t range;
};

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
 * Hex to char
 *
 * @param what IN hex number as a string
 *
 * @return char
 */
static unsigned char parp_hex_2_char(unsigned char *what) {
  register unsigned char digit;

  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

  return digit;
}

/**
 * Decode an urlencoded string
 *
 * @param string INOUT urlencoded string
 * @param len INOUT len of string
 * @param bottom IN bottom of allowed range
 * @param top IN top of allowed range
 *
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t parp_urldecode(parp_t *self, unsigned char *string) {
  apr_status_t status;
  unsigned char val;
  long int i;

  unsigned char *cur = string;
  apr_size_t len = strlen(string);

  if (!string) {
    return APR_EINVAL;
  }

  status  = APR_SUCCESS;
  i = 0;
  while (i < len) {
    if (string[i] == '%') {
      /* need two bytes -> %xx */
      if (i + 2 < len) {
	char c1 = string[i + 1];
	char c2 = string[i + 2];

	/* check if this is a hex number */
	if ( (((c1 >= '0')&&(c1 <= '9')) || ((c1 >= 'a')&&(c1 <= 'f')) ||
	      ((c1 >= 'A')&&(c1 <= 'F')))
	    && (((c2 >= '0')&&(c2 <= '9')) || ((c2 >= 'a')&&(c2 <= 'f')) ||
		((c2 >= 'A')&&(c2 <= 'F'))) ) {
	  val = parp_hex_2_char(&string[i + 1]);
	  /* check range */
	  if (val < self->range.from || val > self->range.to) {
	    val = ' ';
	    status = APR_EINVAL;
	  }
	  *cur++ = val;
	  i += 3;
	} else {
	  *cur++ = '%';
	  *cur++ = c1;
	  *cur++ = c2;
	  i += 3;
	}
      } else {
	*cur++ = '%';
	i++;

	if (i + 1 < len) {
	  *cur++ = string[i];
	  i++;
	}
      }
    }
    else {
      if (string[i] == '+') {
	*cur++ = ' ';
      } else {
	*cur++ = string[i];
      }

      i++;
    }
  }

  *cur = '\0';

  return status;
}
/**
 * Urlencode parser
 *
 * @param self IN instance
 * @param data IN data with urlencoded content
 * @param len IN len of data
 *
 * @return APR_SUCCESS or APR_EINVAL on parser error
 *
 * @note: Get parp_get_error for more detailed report
 */
static apr_status_t parp_urlencode(parp_t *self, const char *data, 
                                   apr_size_t len) {
  apr_status_t status;
  char *key;
  char *val;
  char *pair;

  const char *rest = data;
  
  while (rest[0]) {
    pair = ap_getword(self->pool, &rest, '&');
    val = pair;
    key = ap_getword_nc(self->pool, &val, '=');
    /* url decode key val */
    if (!key) {
      return APR_EINVAL;
    }

    if ((status = parp_urldecode(self, key)) == APR_SUCCESS) {
      if (val) {
        if ((status = parp_urldecode(self, val)) != APR_SUCCESS) {
	  return status;
        }
      }
      else {
        val = apr_pstrdup(self->pool, "");
      }
      /* store it to a table */
      apr_table_addn(self->params, key, val);
    }
    else {
      if (! self->flags & PARP_FLAGS_CONT_ON_ERR) {
	return status;
      }
    }
  }
  
  return APR_SUCCESS;
}

/**
 * Multipart parser
 *
 * @param self IN instance
 * @param data IN data with urlencoded content
 * @param len IN len of data
 *
 * @return APR_SUCCESS or APR_EINVAL on parser error
 *
 * @note: Get parp_get_error for more detailed report
 */
static apr_status_t parp_multipart(parp_t *self, const char *data, 
                                   apr_size_t len) {
  return APR_SUCCESS;
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
AP_DECLARE(parp_t *) parp_new(request_rec *r, int flags,
                              parp_byte_range_t range) {
  parp_t *self = apr_pcalloc(r->pool, sizeof(parp_t));

  self->pool = r->pool;
  self->r = r;
  self->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
  self->params = apr_table_make(r->pool, 5);
  self->flags = flags;
  self->range = range;

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

  request_rec *r = self->r;
  
  if (r->method_number == M_POST) {
    if (r->args) {
      if ((status = parp_urlencode(self, r->args, strlen(r->args))) 
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
    if ((status = parp_urlencode(self, data, len)) != APR_SUCCESS) {
      return status;
    }

  }
  else if (r->method_number == M_GET) {
    if (r->args) {
      if ((status = parp_urlencode(self, r->args, strlen(r->args))) 
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

