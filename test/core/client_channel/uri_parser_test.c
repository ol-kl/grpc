/*
 *
 * Copyright 2015, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "src/core/ext/client_channel/uri_parser.h"

#include <string.h>
#include <stdio.h>

#include <grpc/support/log.h>

#include "test/core/util/test_config.h"

#define ASSERT(x, msg, line_num)                      \
  do {                                                \
    if (!(x)) {                                       \
      gpr_log_message(__FILE__, line_num,             \
        GPR_LOG_SEVERITY_ERROR, msg);                 \
    }                                                 \
    GPR_ASSERT(x);                                    \
  } while (0)                                         \

#define TEST_SUCCEEDS(uri_text, scheme, authority,    \
                      path, query, fragment)          \
  test_succeeds(uri_text, scheme, authority,          \
		        path, query, fragment, __LINE__);


static const size_t msg_buf_size = 80;

static inline char *msg_neq(char *buf, const char *arg1,
		const char *arg2) {
  snprintf(buf, msg_buf_size, "%s != %s", arg1, arg2);
  return buf;
}

static void test_succeeds(const char *uri_text, const char *scheme,
                          const char *authority, const char *path,
                          const char *query, const char *fragment,
						              const int call_line_num) {
  grpc_uri *uri = grpc_uri_parse(uri_text, 0);
  char msg_buf[msg_buf_size];
  ASSERT(uri, "Uri empty", call_line_num);
  ASSERT(0 == strcmp(scheme, uri->scheme),
      msg_neq(msg_buf, scheme, uri->scheme), call_line_num);
  ASSERT(0 == strcmp(authority, uri->authority),
      msg_neq(msg_buf, authority, uri->authority), call_line_num);
  ASSERT(0 == strcmp(path, uri->path), msg_neq(msg_buf, path, uri->path),
      call_line_num);
  ASSERT(0 == strcmp(query, uri->query), msg_neq(msg_buf, query, uri->query),
      call_line_num);
  ASSERT(0 == strcmp(fragment, uri->fragment),
      msg_neq(msg_buf, fragment, uri->fragment), call_line_num);
  grpc_uri_destroy(uri);
}

#define TEST_FAILS(uri_text) test_fails(uri_text, __LINE__);

static void test_fails(const char *uri_text, const int call_line_num) {
  ASSERT(NULL == grpc_uri_parse(uri_text, 0), uri_text, call_line_num);
}

static void test_query_parts() {
  {
    const char *uri_text = "http://foo/path?a&b=B&c=&#frag";
    grpc_uri *uri = grpc_uri_parse(uri_text, 0);
    GPR_ASSERT(uri);

    GPR_ASSERT(0 == strcmp("http", uri->scheme));
    GPR_ASSERT(0 == strcmp("foo", uri->authority));
    GPR_ASSERT(0 == strcmp("/path", uri->path));
    GPR_ASSERT(0 == strcmp("a&b=B&c=&", uri->query));
    GPR_ASSERT(4 == uri->num_query_parts);

    GPR_ASSERT(0 == strcmp("a", uri->query_parts[0]));
    GPR_ASSERT(NULL == uri->query_parts_values[0]);

    GPR_ASSERT(0 == strcmp("b", uri->query_parts[1]));
    GPR_ASSERT(0 == strcmp("B", uri->query_parts_values[1]));

    GPR_ASSERT(0 == strcmp("c", uri->query_parts[2]));
    GPR_ASSERT(0 == strcmp("", uri->query_parts_values[2]));

    GPR_ASSERT(0 == strcmp("", uri->query_parts[3]));
    GPR_ASSERT(NULL == uri->query_parts_values[3]);

    GPR_ASSERT(NULL == grpc_uri_get_query_arg(uri, "a"));
    GPR_ASSERT(0 == strcmp("B", grpc_uri_get_query_arg(uri, "b")));
    GPR_ASSERT(0 == strcmp("", grpc_uri_get_query_arg(uri, "c")));
    GPR_ASSERT(NULL == grpc_uri_get_query_arg(uri, ""));

    GPR_ASSERT(0 == strcmp("frag", uri->fragment));
    grpc_uri_destroy(uri);
  }
  {
    /* test the current behavior of multiple query part values */
    const char *uri_text = "http://auth/path?foo=bar=baz&foobar==";
    grpc_uri *uri = grpc_uri_parse(uri_text, 0);
    GPR_ASSERT(uri);

    GPR_ASSERT(0 == strcmp("http", uri->scheme));
    GPR_ASSERT(0 == strcmp("auth", uri->authority));
    GPR_ASSERT(0 == strcmp("/path", uri->path));
    GPR_ASSERT(0 == strcmp("foo=bar=baz&foobar==", uri->query));
    GPR_ASSERT(2 == uri->num_query_parts);

    GPR_ASSERT(0 == strcmp("bar", grpc_uri_get_query_arg(uri, "foo")));
    GPR_ASSERT(0 == strcmp("", grpc_uri_get_query_arg(uri, "foobar")));

    grpc_uri_destroy(uri);
  }
  {
    /* empty query */
    const char *uri_text = "http://foo/path";
    grpc_uri *uri = grpc_uri_parse(uri_text, 0);
    GPR_ASSERT(uri);

    GPR_ASSERT(0 == strcmp("http", uri->scheme));
    GPR_ASSERT(0 == strcmp("foo", uri->authority));
    GPR_ASSERT(0 == strcmp("/path", uri->path));
    GPR_ASSERT(0 == strcmp("", uri->query));
    GPR_ASSERT(0 == uri->num_query_parts);
    GPR_ASSERT(NULL == uri->query_parts);
    GPR_ASSERT(NULL == uri->query_parts_values);
    GPR_ASSERT(0 == strcmp("", uri->fragment));
    grpc_uri_destroy(uri);
  }
}

int main(int argc, char **argv) {
  grpc_test_init(argc, argv);
  TEST_SUCCEEDS("http://www.google.com", "http", "www.google.com", "", "", "");
  TEST_SUCCEEDS("dns:///foo", "dns", "", "/foo", "", "");
  /* TODO(ol-kl): implement scheme normalization
   * TEST_SUCCEEDS("DnS:///foo", "dns", "", "/foo", "", "");
   */
  TEST_SUCCEEDS("http://www.google.com:90", "http", "www.google.com:90", "", "",
                "");
  TEST_SUCCEEDS("a192.4-df:foo.coom", "a192.4-df", "", "foo.coom", "", "");
  TEST_SUCCEEDS("a+b:foo.coom", "a+b", "", "foo.coom", "", "");
  TEST_SUCCEEDS("zookeeper://127.0.0.1:2181/foo/bar", "zookeeper",
                "127.0.0.1:2181", "/foo/bar", "", "");
  TEST_SUCCEEDS("http://www.google.com?yay-i'm-using-queries", "http",
                "www.google.com", "", "yay-i'm-using-queries", "");
  TEST_SUCCEEDS("dns:foo.com#fragment-all-the-things", "dns", "", "foo.com", "",
                "fragment-all-the-things");
  TEST_SUCCEEDS("http:?legit", "http", "", "", "legit", "");
  TEST_SUCCEEDS("unix:#this-is-ok-too", "unix", "", "", "", "this-is-ok-too");
  TEST_SUCCEEDS("http:?legit#twice", "http", "", "", "legit", "twice");
  TEST_SUCCEEDS("http://foo?bar#lol?", "http", "foo", "", "bar", "lol?");
  TEST_SUCCEEDS("http://foo?bar#lol?/", "http", "foo", "", "bar", "lol?/");

  /* scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
  TEST_SUCCEEDS("d://a@host:1/bar?q#f", "d", "a@host:1", "/bar", "q", "f");
  /* TODO(ol-kl): implement scheme normalization
   * TEST_SUCCEEDS("Dd://a@host:1/bar?q#f", "dd", "a@host:1", "/bar",
   *  "q", "f");
   */
  TEST_SUCCEEDS("a7+-.z://a@host:1/bar?q#f", "a7+-.z", "a@host:1", "/bar",
      "q", "f");

  /* hier-part     = "//" authority path-abempty
   *               / path-absolute
   *               / path-rootless
   *               / path-empty
   * path-abempty  = *( "/" segment )
   * path-absolute = "/" [ segment-nz *( "/" segment ) ]
   * path-noscheme = segment-nz-nc *( "/" segment )
   * path-rootless = segment-nz *( "/" segment )
   * path-empty    = 0<pchar>
   * segment       = *pchar
   * segment-nz    = 1*pchar
   * segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
   *               ; non-zero-length segment without any colon ":"
   */
  /* hier-part variations: path-empty */
  TEST_SUCCEEDS("ftp:", "ftp", "", "", "", "");

  /* hier-part variations: path-absolute */
  TEST_SUCCEEDS("ftp:/", "ftp", "", "/", "", "");
  TEST_SUCCEEDS("ftp:/ab", "ftp", "", "/ab", "", "");
  TEST_SUCCEEDS("ftp:/ab/cd", "ftp", "", "/ab/cd", "", "");
  TEST_SUCCEEDS("ftp:/ab/cd/", "ftp", "", "/ab/cd/", "", "");

  /* hier-part variations: path-rootless */
  /* TODO(ol-kl): implement %-encoded hex digits normalization to uppercase
   * TEST_SUCCEEDS("ftp:%fF", "ftp", "", "%FF", "", "");
   */
  TEST_SUCCEEDS("ftp:%FF/", "ftp", "", "%FF/", "", "");
  TEST_SUCCEEDS("ftp:%FF/a", "ftp", "", "%FF/a", "", "");
  TEST_SUCCEEDS("ftp:%FF/a/", "ftp", "", "%FF/a/", "", "");

  /* authority     = [ userinfo "@" ] host [ ":" port ]
   * userinfo      = *( unreserved / pct-encoded / sub-delims / ":Å" )
   * host          = IP-literal / IPv4address / reg-name
   * reg-name      = *( unreserved / pct-encoded / sub-delims )
   * port          = *DIGIT
   * unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
   * reserved      = gen-delims / sub-delims
   * gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
   * sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
   *               / "*" / "+" / "," / ";" / "="
   */
  /* hier-part variations: authority and path-abempty */
  TEST_SUCCEEDS("ftp://host", "ftp", "host", "", "", "");
  TEST_SUCCEEDS("ftp://host/", "ftp", "host", "/", "", "");
  TEST_SUCCEEDS("ftp://host/bar", "ftp", "host", "/bar", "", "");
  TEST_SUCCEEDS("ftp:///baz", "ftp", "", "/baz", "", "");

  /* authority variations: userinfo and port */
  TEST_SUCCEEDS("bar://@host:/bar", "bar", "@host:", "/bar", "", "");
  TEST_SUCCEEDS("bar://a-.:_~%AA@host:000000/bar", "bar",
      "a-.:_~%AA@host:000000", "/bar", "", "");
  TEST_SUCCEEDS("bar://aBc%DE:%FF%AD:::!$&'()*+,;=@host:2028282/bar", "bar",
      "aBc%DE:%FF%AD:::!$&'()*+,;=@host:2028282", "/bar", "", "");

  /* authority variations: host as reg-name */
  /* https://tools.ietf.org/html/rfc3986#section-3.2.2:
   * Although host is case-insensitive, producers and normalizers SHOULD use
   * lowercase for registered names and hexadecimal addresses for the sake of
   * uniformity, while only using uppercase letters for percent-encodings.
   */
  /* TODO(ol-kl): implement hostname normalization to lowercase
   * TEST_SUCCEEDS("bar://Z@HoSt:1/bar", "bar", "Z@host:1", "/bar", "", "");
   */
  TEST_SUCCEEDS("bar://:_:.:@host:1/bar", "bar", ":_:.:@host:1", "/bar", "",
      "");
  TEST_SUCCEEDS("bar://:_:.:@ho!$&'()*+,;=st%AB01-._~:1/bar", "bar",
      ":_:.:@ho!$&'()*+,;=st%AB01-._~:1", "/bar", "", "");

  /*
   * IP-literal = "[" ( IPv6address / IPv6addrz / IPvFuture  ) "]"
   * IPv6addrz = IPv6address "%25" ZoneID
   * ZoneID = 1*( unreserved / pct-encoded )
   * IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
   * IPv6address   =                            6( h16 ":" ) ls32
   *              /                       "::" 5( h16 ":" ) ls32
   *              / [               h16 ] "::" 4( h16 ":" ) ls32
   *              / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
   *              / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
   *              / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
   *              / [ *4( h16 ":" ) h16 ] "::"              ls32
   *              / [ *5( h16 ":" ) h16 ] "::"              h16
   *              / [ *6( h16 ":" ) h16 ] "::"
   * h16           = 1*4HEXDIG
   * ls32          = ( h16 ":" h16 ) / IPv4address
   * IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
   * dec-octet     = DIGIT                 ; 0-9
   *               / %x31-39 DIGIT         ; 10-99
   *               / "1" 2DIGIT            ; 100-199
   *               / "2" %x30-34 DIGIT     ; 200-249
   *               / "25" %x30-35          ; 250-255
   */
  /* authority variations: host as IPvFuture */
  TEST_SUCCEEDS("bar://[vF.a]:0/bar", "bar", "[vF.a]:0", "/bar", "", "");
  /* TODO(ol-kl): implement hexdigit normalization to uppercase in version part
   * TEST_SUCCEEDS("bar://[vfA0.a]:0/bar", "bar", "[vFA0.a]:0", "/bar", "", "");
   */
  TEST_SUCCEEDS("bar://[v12.a]:0/bar", "bar", "[v12.a]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://:_:@[vF.::Zz90:!$&'()*+,;=:-._~]:0/bar", "bar",
      ":_:@[vF.::Zz90:!$&'()*+,;=:-._~]:0", "/bar", "", "");

  /* authority variations: host as IPv6address */
  /* TODO(ol-kl): if host part matches IPv4 or IPv6 address format, then it
   *              must be converted to network order bytes as if it went
   *              through inet_pton() function, when implemented
   */
  TEST_SUCCEEDS("bar://[A:B:C:D:E:F:A:B]:0/bar", "bar", "[A:B:C:D:E:F:A:B]:0",
      "/bar", "", "");
  TEST_SUCCEEDS("bar://[0:12:345:6789:ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[0:12:345:6789:ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[0:12:345:6789:ABCD:EF:1.99.199.255]:0/bar", "bar",
      "[0:12:345:6789:ABCD:EF:1.99.199.255]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::12:345:6789:ABCD:EF:1.99.199.255]:0/bar", "bar",
      "[::12:345:6789:ABCD:EF:1.99.199.255]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::345:6789:ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[::345:6789:ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[AB01::345:6789:ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[AB01::345:6789:ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::6789:ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[::6789:ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1::6789:ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[1::6789:ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2::6789:ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[1:2::6789:ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[::ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1::ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[1::ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2::ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[1:2::ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3::ABCD:EF:0000:1B2F]:0/bar", "bar",
      "[1:2:3::ABCD:EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::EF:0000:1B2F]:0/bar", "bar",
      "[::EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::EF:0000:1B2F]:0/bar", "bar",
      "[::EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1::EF:0000:1B2F]:0/bar", "bar",
      "[1::EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2::EF:0000:1B2F]:0/bar", "bar",
      "[1:2::EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3::EF:0000:1B2F]:0/bar", "bar",
      "[1:2:3::EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4::EF:0000:1B2F]:0/bar", "bar",
      "[1:2:3:4::EF:0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::0000:1B2F]:0/bar", "bar",
      "[::0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1::0000:1B2F]:0/bar", "bar",
      "[1::0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2::0000:1B2F]:0/bar", "bar",
      "[1:2::0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3::0000:1B2F]:0/bar", "bar",
      "[1:2:3::0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4::0000:1B2F]:0/bar", "bar",
      "[1:2:3:4::0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4:5::0000:1B2F]:0/bar", "bar",
      "[1:2:3:4:5::0000:1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::1B2F]:0/bar", "bar", "[::1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1::1B2F]:0/bar", "bar", "[1::1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2::1B2F]:0/bar", "bar",
      "[1:2::1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3::1B2F]:0/bar", "bar",
      "[1:2:3::1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4::1B2F]:0/bar", "bar",
      "[1:2:3:4::1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4:5::1B2F]:0/bar", "bar",
      "[1:2:3:4:5::1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4:5:6::1B2F]:0/bar", "bar",
      "[1:2:3:4:5:6::1B2F]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[::]:0/bar", "bar", "[::]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1::]:0/bar", "bar", "[1::]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2::]:0/bar", "bar", "[1:2::]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3::]:0/bar", "bar", "[1:2:3::]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4::]:0/bar", "bar",
      "[1:2:3:4::]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4:5::]:0/bar", "bar",
      "[1:2:3:4:5::]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4:5:6::]:0/bar", "bar",
      "[1:2:3:4:5:6::]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4:5:6:7::]:0/bar", "bar",
      "[1:2:3:4:5:6:7::]:0", "/bar", "", "");

  /* authority variations: host as IPv6addrz (RFC 6874) */
  /* uppercase chars are normalized to lowercase, lowercase chars in percent
   * encoded tuples are normalized to uppercase
   */
  /* TODO(ol-kl): check parsed out and normalized zone id when implemented */
  TEST_SUCCEEDS("bar://[1:2:3:4:5:6::%25a]:0/bar", "bar",
        "[1:2:3:4:5:6::%25a]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4:5:6::%25%25]:0/bar", "bar",
          "[1:2:3:4:5:6::%25%25]:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://[1:2:3:4:5:6::%25a1234567890-._~%AF]:0/bar", "bar",
          "[1:2:3:4:5:6::%25a1234567890-._~%AF]:0", "/bar", "", "");
  /* TODO(ol-kl): implement zone id normalization to lowercase as part of
   *              hostname
   * TEST_SUCCEEDS("bar://[::1%25A]:0/bar", "bar", "[::1%25a]:0", "/bar",
   *     "", "");
   */

  /* authority variations: host as IPv4address */
  TEST_SUCCEEDS("bar://0.0.0.0:0/bar", "bar", "0.0.0.0:0", "/bar", "", "");
  TEST_SUCCEEDS("bar://0.10.111.245:0/bar", "bar", "0.10.111.245:0",
      "/bar", "", "");
  TEST_SUCCEEDS("bar://255.255.255.255:0/bar", "bar", "255.255.255.255:0",
      "/bar", "", "");

 /* query         = *( pchar / "/" / "?" )
  * fragment      = *( pchar / "/" / "?" )
  * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
  * unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
  * pct-encoded   = "%" HEXDIG HEXDIG
  * sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
  *              / "*" / "+" / "," / ";" / "="
  */
  /* query variations */
  TEST_SUCCEEDS("bar:a/b/?#1", "bar", "", "a/b/", "", "1");
  TEST_SUCCEEDS("bar:a/b/?/?///?#1", "bar", "", "a/b/", "/?///?", "1");
  /* TODO(ol-kl): fix ':' and '@' not being recognized as pchar in query
   * TEST_SUCCEEDS("bar:a/b/?/?aAzZ%AA%FF?-._~!$&'()*+,:=@:@?#1", "bar", "",
   *     "a/b/", "/?aAzZ%AA%FF?-._~!$&'()*+,:=@:@?", "1");
   */

  /* fragment variations */
  TEST_SUCCEEDS("bar:a/b/?#", "bar", "", "a/b/", "", "");
  TEST_SUCCEEDS("bar:a/b/?q#", "bar", "", "a/b/", "q", "");
  TEST_SUCCEEDS("bar:a/b/?q#/?///?", "bar", "", "a/b/", "q", "/?///?");
  /* TODO(ol-kl): fix ':' and '@' not being recognized as pchar in fragment
   * TEST_SUCCEEDS("bar:a/b/#/?aAzZ%aA%FF?-._~!$&'()*+,:=@:@?", "bar", "",
   *     "a/b/", "", "/?aAzZ%aA%FF?-._~!$&'()*+,:=@:@?");
   */

  TEST_FAILS("xyz");
  TEST_FAILS("http:?dangling-pct-%0");
  TEST_FAILS("http://foo?[bar]");
  TEST_FAILS("http://foo?x[bar]");
  TEST_FAILS("http://foo?bar#lol#");
  TEST_FAILS("http:/\xFF/foo?bar#lol#");

  /* Failures: scheme */
  TEST_FAILS("7scheme://hier-part?myquery#myfragment");
  TEST_FAILS("sch#me://hier-part?myquery#myfragment");
  TEST_FAILS("sch_me://hier-part?myquery#myfragment");
  TEST_FAILS("sch?me://hier-part?myquery#myfragment");
  TEST_FAILS("sch*me://hier-part?myquery#myfragment");
  TEST_FAILS("sch*me://hier-part?myquery#myfragment");
  TEST_FAILS("sch\xC6\xB1me://hier-part?myquery#myfragment");
  TEST_FAILS("sch\x01me://hier-part?myquery#myfragment");

  /* Failures: userinfo and port */
  /* TODO(ol-kl): implement userinfo and port parsing, then these must fail
   * TEST_FAILS("bar:///@host:1/bar");
   * TEST_FAILS("bar://?@host:1/bar");
   * TEST_FAILS("bar://#@host:1/bar");
   * TEST_FAILS("bar://[@host:1/bar");
   * TEST_FAILS("bar://]@host:1/bar");
   * TEST_FAILS("bar://@@host:1/bar");
   * TEST_FAILS("bar://%ZD@host:1/bar");
   * TEST_FAILS("bar://\xC6\xB1@host:1/bar");
   * TEST_FAILS("bar://a@host:-1/bar");
   * TEST_FAILS("bar://a@host:a/bar");
   * TEST_FAILS("bar://a@host:%AA/bar");
   * TEST_FAILS("bar://a@host://bar");
   * TEST_FAILS("bar://a@host:?/bar");
   * TEST_FAILS("bar://a@host:@/bar");
   * TEST_FAILS("bar://a@host:\x01/bar");
   */

  /* Failures: host reg-name */
  /* TODO(ol-kl): implement authority parsing, then these must fail
   * TEST_FAILS("bar://a@host::1/bar");
   * TEST_FAILS("bar://a@ho:st:1/bar");
   * TEST_FAILS("bar://a@ho/st:1/bar");
   * TEST_FAILS("bar://a@ho?st:1/bar");
   * TEST_FAILS("bar://a@ho#st:1/bar");
   * TEST_FAILS("bar://a@ho[st:1/bar");
   * TEST_FAILS("bar://a@ho]st:1/bar");
   * TEST_FAILS("bar://a@ho@st:1/bar");
   * TEST_FAILS("bar://a@ho%ZAst:1/bar");
   * TEST_FAILS("bar://a@ho\xC6\xB1st:1/bar");
   */

  /* Failures: host IPvFuture */
  TEST_FAILS("bar://[vF.]:0/bar");
  TEST_FAILS("bar://[vZ.a]:0/bar");
  TEST_FAILS("bar://[vFG.a]:0/bar");
  TEST_FAILS("bar://[v.a]:0/bar");
  TEST_FAILS("bar://[.a]:0/bar");
  TEST_FAILS("bar://[F.a]:0/bar");
  TEST_FAILS("bar://[vFa]:0/bar");
  TEST_FAILS("bar://[[vF.a]]:0/bar");
  TEST_FAILS("bar://[[vF.a]:0/bar");
  TEST_FAILS("bar://[vF.a]h:0/bar");
  TEST_FAILS("bar://a[vF.a]:0/bar");
  TEST_FAILS("bar://[vF.a\xC6\xB1]:0/bar");

  /* Failures: host IPv6address */
  TEST_FAILS("bar://[1:::]:0/bar");
  TEST_FAILS("bar://[1:2::3::]:0/bar");
  TEST_FAILS("bar://[:::]:0/bar");
  TEST_FAILS("bar://[:B:F:]:0/bar");
  TEST_FAILS("bar://[1:2]:0/bar");
  TEST_FAILS("bar://[::1.2.3.256]:0/bar");
  TEST_FAILS("bar://[::1111.1.1.1]:0/bar");
  TEST_FAILS("bar://[::AAAAA]:0/bar");
  TEST_FAILS("bar://[A:B:C:G:E:F:A:B]:0/bar");
  TEST_FAILS("bar://[A:B:CCCCC:D:E:F:A:B]:0/bar");
  TEST_FAILS("bar://[::\xC6\xB1]:0/bar");

  /* Failures: host IPv6addrz */
  TEST_FAILS("bar://[1:2:3:4:5:6::%a]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%ZD]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25%ZD]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25:]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25/]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25?]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25#]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25[]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25]]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25@]:0/bar");
  TEST_FAILS("bar://[1:2:3:4:5:6::%25\xC6\xB1]:0/bar");

  /* Failures: host IPv4address */
  TEST_FAILS("bar://0.0.0.:0/bar");
  TEST_FAILS("bar://1234.1.1.1:0/bar");
  TEST_FAILS("bar://FF.AA.DD.CC/bar");
  TEST_FAILS("bar://%01.%01.%01.%01/bar");
  TEST_FAILS("bar://%FF.%AA.%DD.%CC/bar");
  TEST_FAILS("bar://01.2.3.4:0/bar");
  TEST_FAILS("bar://1.002.3.4:0/bar");
  TEST_FAILS("bar://1.\xFF.3.4:0/bar");

  /* Failures: query */
  TEST_FAILS("bar:a/b/?q##1");
  TEST_FAILS("bar:a/b/?q[#1");
  TEST_FAILS("bar:a/b/?q]#1");
  TEST_FAILS("bar:a/b/?q\xC6\xB1#1");

  /* Failures: fragment */
  TEST_FAILS("bar:a/b/?q##");
  TEST_FAILS("bar:a/b/?q#f#f");
  TEST_FAILS("bar:a/b/?q#f[f");
  TEST_FAILS("bar:a/b/?q#f]f");
  TEST_FAILS("bar:a/b/?q#f\xC6\xB1");

  test_query_parts();
  return 0;
}
