/*
 * ProFTPD - mod_charset
 * Copyright (c) 2012 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * $Id: utf8.c,v 1.16 2011/05/23 21:03:12 castaglia Exp $
 */

#include "conf.h"

#define MOD_CHARSET_VERSION	"mod_charset/0.0"

#if PROFTPD_VERSION_NUMBER < 0x0001030401
# error "ProFTPD 1.3.4rc1 or later required"
#endif

#ifdef HAVE_ICONV_H
# include <iconv.h>
#endif

#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif

module charset_module;

static int charset_engine = FALSE;
static pool *charset_pool = NULL;
static const char *local_charset = NULL;
static const char *trace_channel = "charset";

static int charset_utf8_free(void);
static int charset_utf8_init(void);

#if defined(PR_USE_NLS) && defined(HAVE_ICONV_H)
static iconv_t decode_conv = (iconv_t) -1;

static int utf8_convert(iconv_t conv, const char *inbuf, size_t *inbuflen,
    char *outbuf, size_t *outbuflen) {
# ifdef HAVE_ICONV

  /* Reset the state machine before each conversion. */
  (void) iconv(conv, NULL, NULL, NULL, NULL);

  while (*inbuflen > 0) {
    size_t nconv;

    pr_signals_handle();

    /* Solaris/FreeBSD's iconv(3) takes a const char ** for the input buffer,
     * whereas Linux/Mac OSX iconv(3) use char ** for the input buffer.
     */
#if defined(LINUX) || defined(DARWIN6) || defined(DARWIN7) || \
    defined(DARWIN8) || defined(DARWIN9) || defined(DARWIN10) || \
    defined(DARWIN11)
 
    nconv = iconv(conv, (char **) &inbuf, inbuflen, &outbuf, outbuflen);
#else
    nconv = iconv(conv, &inbuf, inbuflen, &outbuf, outbuflen);
#endif

    if (nconv == (size_t) -1) {

      /* Note: an errno of EILSEQ here can indicate badly encoded strings OR
       * (more likely) that the source character set used in the iconv_open(3)
       * call for this iconv_t descriptor does not accurately describe the
       * character encoding of the given string.  E.g. a filename may use
       * the ISO8859-1 character set, but iconv_open(3) was called using
       * US-ASCII.
       */

      return -1;
    }

    /* XXX We should let the loop condition work, rather than breaking out
     * of the loop here.
     */
    break;
  }

  return 0;

# else
  errno = ENOSYS;
  return -1;
# endif /* HAVE_ICONV */
}
#endif /* !PR_USE_NLS && !HAVE_ICONV_H */

static int charset_set_charset(const char *charset) {
  int res;

  if (charset == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (local_charset) {
    pr_trace_msg(trace_channel, 5,
      "attempting to switch local charset from %s to %s", local_charset,
      charset);

  } else {
    pr_trace_msg(trace_channel, 5, "attempting to use %s as local charset",
      charset);
  }

  (void) charset_utf8_free();

  res = charset_utf8_init();
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "failed to initialize encoding for local charset %s", charset);
    local_charset = NULL;
    return -1;
  }

  return res;
}

static int charset_utf8_free(void) {
# if defined(PR_USE_NLS) && defined(HAVE_ICONV)
  int res = 0;

  /* Close the iconv handles. */
  if (decode_conv != (iconv_t) -1) {
    res = iconv_close(decode_conv);
    if (res < 0) {
      pr_trace_msg(trace_channel, 1,
        "error closing decoding conversion handle from '%s' to '%s': %s",
          "UTF-8", local_charset, strerror(errno));
      res = -1;
    }

    decode_conv = (iconv_t) -1;
  }

  return res;
# else
  errno = ENOSYS;
  return -1;
# endif
}

static int charset_utf8_init(void) {
#if defined(PR_USE_NLS) && defined(HAVE_ICONV)
  if (local_charset == NULL) {
    local_charset = pr_encode_get_local_charset();

  } else {
    pr_trace_msg(trace_channel, 3,
      "using '%s' as local charset for UTF8 conversion", local_charset);
  }

  /* Get the iconv handles. */
  decode_conv = iconv_open(local_charset, "UTF-8");
  if (decode_conv == (iconv_t) -1) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1, "error opening conversion handle from '%s' "
      "to '%s': %s", "UTF-8", local_charset, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
# else
  errno = ENOSYS;
  return -1;
#endif /* HAVE_ICONV */
}

static char *charset_utf8_decode_str(pool *p, const char *str) {
#if defined(PR_USE_NLS) && defined(HAVE_ICONV_H)
  size_t inlen, inbuflen, outlen, outbuflen;
  char *inbuf, outbuf[PR_TUNABLE_PATH_MAX*2], *res = NULL;

  if (p == NULL ||
      str == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (decode_conv == (iconv_t) -1) {
    pr_trace_msg(trace_channel, 1, "decoding conversion handle is invalid, "
      "unable to decode UTF8 string");
    errno = EPERM;
    return NULL;
  }

  /* If the local charset matches the remote charset (i.e. local_charset is
   * "UTF-8"), then there's no point in converting; the charsets are the
   * same.  Indeed, on some libiconv implementations, attempting to
   * convert between the same charsets results in a tightly spinning CPU
   * (see Bug#3272).
   */
  if (strncasecmp(local_charset, "UTF-8", 6) == 0) {
    return (char *) str;
  }

  inlen = strlen(str) + 1;
  inbuf = pcalloc(p, inlen);
  memcpy(inbuf, str, inlen);
  inbuflen = inlen;

  outbuflen = sizeof(outbuf);

  if (utf8_convert(decode_conv, inbuf, &inbuflen, outbuf, &outbuflen) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1, "error decoding string: %s",
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  outlen = sizeof(outbuf) - outbuflen;
  res = pcalloc(p, outlen);
  memcpy(res, outbuf, outlen);

  return res;
#else
  errno = ENOSYS;
  return NULL;
#endif /* !PR_USE_NLS && !HAVE_ICONV_H */
}

/* Configuration Handlers
 */

/* usage: CharsetAllowFilter charset1 ... charsetN */
MODRET set_charsetallowfilter(cmd_rec *cmd) {
  config_rec *c;
  array_header *charsets;
  register unsigned int i;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  charsets = make_array(c->pool, 1, sizeof(char *));

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "utf8") == 0 ||
        strcasecmp(cmd->argv[i], "utf-8") == 0) {
      *((char **) push_array(charsets)) = pstrdup(c->pool, "utf8");

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported character set '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = (void *) charsets;

  return PR_HANDLED(cmd);
}

/* usage: CharsetDefault charset */
MODRET set_charsetdefault(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: CharsetEngine on|off */
MODRET set_charsetengine(cmd_rec *cmd) {
  config_rec *c;
  int engine = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* Command Handlers
 */

MODRET charset_pre_cmd(cmd_rec *cmd) {
  config_rec *c;
  array_header *charsets;
  char *res;

  if (charset_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* XXX In the future, retrieval of allowed charsets can be done using
   * CURRENT_CONF, to allow different allowed character sets based on
   * directory/.ftpaccess file.
   */
  c = find_config(main_server->conf, CONF_PARAM, "CharsetAllowFilter", FALSE);
  if (c == NULL) {
    return PR_DECLINED(cmd);
  }

  charsets = c->argv[0];

  /* XXX For now, we know that we only support UTF8.  So no need to do
   * anything truly complex/sophisticated here.  Yet.
   */

  res = charset_utf8_decode_str(cmd->tmp_pool, cmd->arg);
  if (res == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG3, MOD_CHARSET_VERSION
      ": %s denied: unable to UTF8-decode '%s': %s", cmd->argv[0], cmd->arg,
      strerror(xerrno));
    pr_response_add_err(R_501, "%s: %s", cmd->arg, strerror(xerrno));

    errno = xerrno;
    return PR_ERROR(cmd);

  } else {
    pr_trace_msg(trace_channel, 8, "UTF8-decoded %s path '%s' to '%s'",
      cmd->argv[0], cmd->arg, res);
  }

  return PR_DECLINED(cmd);
}

/* Event Listeners
 */

#if defined(PR_SHARED_MODULE)
static void charset_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_charset.c", (const char *) event_data) == 0) {
    destroy_pool(charset_pool);
    charset_pool = NULL;

    pr_event_unregister(&charset_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

/* Module Initialization
 */

static int charset_init(void) {
  charset_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(charset_pool, MOD_CHARSET_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&charset_module, "core.module-unload",
    charset_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  if (charset_utf8_init() < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG1, MOD_CHARSET_VERSION
      ": unable to initialize local charset: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int charset_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "CharsetEngine", FALSE);
  if (c != NULL) {
    charset_engine = *((int *) c->argv[0]);
  }

  if (charset_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "CharsetDefault", FALSE);
  if (c != NULL) {
    char *default_charset;

    default_charset = c->argv[0];
    if (charset_set_charset(default_charset) < 0) {
      pr_log_debug(DEBUG3, MOD_CHARSET_VERSION
        ": unable to use CharsetDefault %s: %s", default_charset,
        strerror(errno));
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable charset_conftab[] = {
  { "CharsetAllowFilter",	set_charsetallowfilter,	NULL },
  { "CharsetDefault",		set_charsetdefault,	NULL },
  { "CharsetEngine",		set_charsetengine,	NULL },
  { NULL }
};

static cmdtable charset_cmdtab[] = {
  { PRE_CMD,	C_APPE,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_MKD,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_RNTO,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_STOR,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },
  { PRE_CMD,	C_XMKD,	G_WRITE, charset_pre_cmd,	TRUE, FALSE },

  { 0, NULL }
};

module charset_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "charset",

  /* Module configuration handler table */
  charset_conftab,

  /* Module command handler table */
  charset_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  charset_init,

  /* Session initialization function */
  charset_sess_init,

  /* Module version */
  MOD_CHARSET_VERSION
};

