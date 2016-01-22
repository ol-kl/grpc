/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

 /* This file was generated by err_data_generate.go. */

#include <openssl/base.h>
#include <openssl/err.h>
#include <openssl/type_check.h>


OPENSSL_COMPILE_ASSERT(ERR_LIB_NONE == 1, library_values_changed_1);
OPENSSL_COMPILE_ASSERT(ERR_LIB_SYS == 2, library_values_changed_2);
OPENSSL_COMPILE_ASSERT(ERR_LIB_BN == 3, library_values_changed_3);
OPENSSL_COMPILE_ASSERT(ERR_LIB_RSA == 4, library_values_changed_4);
OPENSSL_COMPILE_ASSERT(ERR_LIB_DH == 5, library_values_changed_5);
OPENSSL_COMPILE_ASSERT(ERR_LIB_EVP == 6, library_values_changed_6);
OPENSSL_COMPILE_ASSERT(ERR_LIB_BUF == 7, library_values_changed_7);
OPENSSL_COMPILE_ASSERT(ERR_LIB_OBJ == 8, library_values_changed_8);
OPENSSL_COMPILE_ASSERT(ERR_LIB_PEM == 9, library_values_changed_9);
OPENSSL_COMPILE_ASSERT(ERR_LIB_DSA == 10, library_values_changed_10);
OPENSSL_COMPILE_ASSERT(ERR_LIB_X509 == 11, library_values_changed_11);
OPENSSL_COMPILE_ASSERT(ERR_LIB_ASN1 == 12, library_values_changed_12);
OPENSSL_COMPILE_ASSERT(ERR_LIB_CONF == 13, library_values_changed_13);
OPENSSL_COMPILE_ASSERT(ERR_LIB_CRYPTO == 14, library_values_changed_14);
OPENSSL_COMPILE_ASSERT(ERR_LIB_EC == 15, library_values_changed_15);
OPENSSL_COMPILE_ASSERT(ERR_LIB_SSL == 16, library_values_changed_16);
OPENSSL_COMPILE_ASSERT(ERR_LIB_BIO == 17, library_values_changed_17);
OPENSSL_COMPILE_ASSERT(ERR_LIB_PKCS7 == 18, library_values_changed_18);
OPENSSL_COMPILE_ASSERT(ERR_LIB_PKCS8 == 19, library_values_changed_19);
OPENSSL_COMPILE_ASSERT(ERR_LIB_X509V3 == 20, library_values_changed_20);
OPENSSL_COMPILE_ASSERT(ERR_LIB_RAND == 21, library_values_changed_21);
OPENSSL_COMPILE_ASSERT(ERR_LIB_ENGINE == 22, library_values_changed_22);
OPENSSL_COMPILE_ASSERT(ERR_LIB_OCSP == 23, library_values_changed_23);
OPENSSL_COMPILE_ASSERT(ERR_LIB_UI == 24, library_values_changed_24);
OPENSSL_COMPILE_ASSERT(ERR_LIB_COMP == 25, library_values_changed_25);
OPENSSL_COMPILE_ASSERT(ERR_LIB_ECDSA == 26, library_values_changed_26);
OPENSSL_COMPILE_ASSERT(ERR_LIB_ECDH == 27, library_values_changed_27);
OPENSSL_COMPILE_ASSERT(ERR_LIB_HMAC == 28, library_values_changed_28);
OPENSSL_COMPILE_ASSERT(ERR_LIB_DIGEST == 29, library_values_changed_29);
OPENSSL_COMPILE_ASSERT(ERR_LIB_CIPHER == 30, library_values_changed_30);
OPENSSL_COMPILE_ASSERT(ERR_LIB_HKDF == 31, library_values_changed_31);
OPENSSL_COMPILE_ASSERT(ERR_LIB_USER == 32, library_values_changed_32);
OPENSSL_COMPILE_ASSERT(ERR_NUM_LIBS == 33, library_values_changed_num);

const uint32_t kOpenSSLReasonValues[] = {
    0xc3207ba,
    0xc3287d4,
    0xc3307e3,
    0xc3387f3,
    0xc340802,
    0xc34881b,
    0xc350827,
    0xc358844,
    0xc360856,
    0xc368864,
    0xc370874,
    0xc378881,
    0xc380891,
    0xc38889c,
    0xc3908b2,
    0xc3988c1,
    0xc3a08d5,
    0xc3a87c7,
    0xc3b00b0,
    0x10321478,
    0x10329484,
    0x1033149d,
    0x103394b0,
    0x10340de1,
    0x103494cf,
    0x103514e4,
    0x10359516,
    0x1036152f,
    0x10369544,
    0x10371562,
    0x10379571,
    0x1038158d,
    0x103895a8,
    0x103915b7,
    0x103995d3,
    0x103a15ee,
    0x103a9605,
    0x103b1616,
    0x103b962a,
    0x103c1649,
    0x103c9658,
    0x103d166f,
    0x103d9682,
    0x103e0b6c,
    0x103e96b3,
    0x103f16c6,
    0x103f96e0,
    0x104016f0,
    0x10409704,
    0x1041171a,
    0x10419732,
    0x10421747,
    0x1042975b,
    0x1043176d,
    0x104385d0,
    0x104408c1,
    0x10449782,
    0x10451799,
    0x104597ae,
    0x104617bc,
    0x10469695,
    0x104714f7,
    0x104787c7,
    0x104800b0,
    0x104894c3,
    0x14320b4f,
    0x14328b5d,
    0x14330b6c,
    0x14338b7e,
    0x18320083,
    0x18328e47,
    0x18340e75,
    0x18348e89,
    0x18358ec0,
    0x18368eed,
    0x18370f00,
    0x18378f14,
    0x18380f38,
    0x18388f46,
    0x18390f5c,
    0x18398f70,
    0x183a0f80,
    0x183b0f90,
    0x183b8fa5,
    0x183c8fd0,
    0x183d0fe4,
    0x183d8ff4,
    0x183e0b9b,
    0x183e9001,
    0x183f1013,
    0x183f901e,
    0x1840102e,
    0x1840903f,
    0x18411050,
    0x18419062,
    0x1842108b,
    0x184290bd,
    0x184310cc,
    0x18451135,
    0x1845914b,
    0x18461166,
    0x18468ed8,
    0x184709d9,
    0x18478094,
    0x18480fbc,
    0x18489101,
    0x18490e5d,
    0x18498e9e,
    0x184a119c,
    0x184a9119,
    0x184b10e0,
    0x184b8e37,
    0x184c10a4,
    0x184c866b,
    0x184d1181,
    0x203211c3,
    0x243211cf,
    0x24328907,
    0x243311e1,
    0x243391ee,
    0x243411fb,
    0x2434920d,
    0x2435121c,
    0x24359239,
    0x24361246,
    0x24369254,
    0x24371262,
    0x24379270,
    0x24381279,
    0x24389286,
    0x24391299,
    0x28320b8f,
    0x28328b9b,
    0x28330b6c,
    0x28338bae,
    0x2c32281d,
    0x2c32a82b,
    0x2c33283d,
    0x2c33a84f,
    0x2c342863,
    0x2c34a875,
    0x2c352890,
    0x2c35a8a2,
    0x2c3628b5,
    0x2c3682f3,
    0x2c3728c2,
    0x2c37a8d4,
    0x2c3828e7,
    0x2c38a8f5,
    0x2c392905,
    0x2c39a917,
    0x2c3a292b,
    0x2c3aa93c,
    0x2c3b1359,
    0x2c3ba94d,
    0x2c3c2961,
    0x2c3ca977,
    0x2c3d2990,
    0x2c3da9be,
    0x2c3e29cc,
    0x2c3ea9e4,
    0x2c3f29fc,
    0x2c3faa09,
    0x2c402a2c,
    0x2c40aa4b,
    0x2c4111c3,
    0x2c41aa5c,
    0x2c422a6f,
    0x2c429135,
    0x2c432a80,
    0x2c4386a2,
    0x2c4429ad,
    0x30320000,
    0x30328015,
    0x3033001f,
    0x30338038,
    0x3034004a,
    0x30348064,
    0x3035006b,
    0x30358083,
    0x30360094,
    0x303680a1,
    0x303700b0,
    0x303780bd,
    0x303800d0,
    0x303880eb,
    0x30390100,
    0x30398114,
    0x303a0128,
    0x303a8139,
    0x303b0152,
    0x303b816f,
    0x303c017d,
    0x303c8191,
    0x303d01a1,
    0x303d81ba,
    0x303e01ca,
    0x303e81dd,
    0x303f01ec,
    0x303f81f8,
    0x3040020d,
    0x3040821d,
    0x30410234,
    0x30418241,
    0x30420254,
    0x30428263,
    0x30430278,
    0x30438299,
    0x304402ac,
    0x304482bf,
    0x304502d8,
    0x304582f3,
    0x30460310,
    0x30468329,
    0x30470337,
    0x30478348,
    0x30480357,
    0x3048836f,
    0x30490381,
    0x30498395,
    0x304a03b4,
    0x304a83c7,
    0x304b03d2,
    0x304b83e1,
    0x304c03f2,
    0x304c83fe,
    0x304d0414,
    0x304d8422,
    0x304e0438,
    0x304e844a,
    0x304f045c,
    0x304f846f,
    0x30500482,
    0x30508493,
    0x305104a3,
    0x305184bb,
    0x305204d0,
    0x305284e8,
    0x305304fc,
    0x30538514,
    0x3054052d,
    0x30548546,
    0x30550563,
    0x3055856e,
    0x30560586,
    0x30568596,
    0x305705a7,
    0x305785ba,
    0x305805d0,
    0x305885d9,
    0x305905ee,
    0x30598601,
    0x305a0610,
    0x305a8630,
    0x305b063f,
    0x305b864b,
    0x305c066b,
    0x305c8687,
    0x305d0698,
    0x305d86a2,
    0x34320ac9,
    0x34328add,
    0x34330afa,
    0x34338b0d,
    0x34340b1c,
    0x34348b39,
    0x3c320083,
    0x3c328bd8,
    0x3c330bf1,
    0x3c338c0c,
    0x3c340c29,
    0x3c348c44,
    0x3c350c5f,
    0x3c358c74,
    0x3c360c8d,
    0x3c368ca5,
    0x3c370cb6,
    0x3c378cc4,
    0x3c380cd1,
    0x3c388ce5,
    0x3c390b9b,
    0x3c398cf9,
    0x3c3a0d0d,
    0x3c3a8881,
    0x3c3b0d1d,
    0x3c3b8d38,
    0x3c3c0d4a,
    0x3c3c8d60,
    0x3c3d0d6a,
    0x3c3d8d7e,
    0x3c3e0d8c,
    0x3c3e8db1,
    0x3c3f0bc4,
    0x3c3f8d9a,
    0x403217d3,
    0x403297e9,
    0x40331817,
    0x40339821,
    0x40341838,
    0x40349856,
    0x40351866,
    0x40359878,
    0x40361885,
    0x40369891,
    0x403718a6,
    0x403798b8,
    0x403818c3,
    0x403898d5,
    0x40390de1,
    0x403998e5,
    0x403a18f8,
    0x403a9919,
    0x403b192a,
    0x403b993a,
    0x403c0064,
    0x403c8083,
    0x403d1946,
    0x403d995c,
    0x403e196b,
    0x403e997e,
    0x403f1998,
    0x403f99a6,
    0x404019bb,
    0x404099cf,
    0x404119ec,
    0x40419a07,
    0x40421a20,
    0x40429a33,
    0x40431a47,
    0x40439a5f,
    0x40441a76,
    0x40448094,
    0x40451a8b,
    0x40459a9d,
    0x40461ac1,
    0x40469ae1,
    0x40471aef,
    0x40479b03,
    0x40481b18,
    0x40489b31,
    0x40491b48,
    0x40499b62,
    0x404a1b79,
    0x404a9b97,
    0x404b1baf,
    0x404b9bc6,
    0x404c1bdc,
    0x404c9bee,
    0x404d1c0f,
    0x404d9c31,
    0x404e1c45,
    0x404e9c52,
    0x404f1c69,
    0x404f9c79,
    0x40501c89,
    0x40509c9d,
    0x40511cb8,
    0x40519cc8,
    0x40521cdf,
    0x40529cf1,
    0x40531d09,
    0x40539d1c,
    0x40541d31,
    0x40549d54,
    0x40551d62,
    0x40559d7f,
    0x40561d8c,
    0x40569da5,
    0x40571dbd,
    0x40579dd0,
    0x40581de5,
    0x40589df7,
    0x40591e07,
    0x40599e20,
    0x405a1e34,
    0x405a9e44,
    0x405b1e5c,
    0x405b9e6d,
    0x405c1e80,
    0x405c9e91,
    0x405d1e9e,
    0x405d9eb5,
    0x405e1ed5,
    0x405e8a17,
    0x405f1ef6,
    0x405f9f03,
    0x40601f11,
    0x40609f33,
    0x40611f5b,
    0x40619f70,
    0x40621f87,
    0x40629f98,
    0x40631fa9,
    0x40639fbe,
    0x40641fd5,
    0x40649fe6,
    0x40652001,
    0x4065a018,
    0x40662030,
    0x4066a05a,
    0x40672085,
    0x4067a0a6,
    0x406820b9,
    0x4068a0da,
    0x406920f5,
    0x4069a123,
    0x406a2144,
    0x406aa164,
    0x406b22ec,
    0x406ba30f,
    0x406c2325,
    0x406ca551,
    0x406d2580,
    0x406da5a8,
    0x406e25c1,
    0x406ea5d9,
    0x406f25f8,
    0x406fa60d,
    0x40702620,
    0x4070a63d,
    0x40710782,
    0x4071a64f,
    0x40722662,
    0x4072a67b,
    0x40732693,
    0x407390bd,
    0x407426a7,
    0x4074a6c1,
    0x407526d2,
    0x4075a6e6,
    0x407626f4,
    0x40769286,
    0x40772719,
    0x4077a73b,
    0x40782756,
    0x4078a76b,
    0x40792782,
    0x4079a798,
    0x407a27a4,
    0x407aa7b7,
    0x407b27cc,
    0x407ba7de,
    0x407c27f3,
    0x407ca7fc,
    0x41f42217,
    0x41f922a9,
    0x41fe219c,
    0x41fea378,
    0x41ff2469,
    0x42032230,
    0x42082252,
    0x4208a28e,
    0x42092180,
    0x4209a2c8,
    0x420a21d7,
    0x420aa1b7,
    0x420b21f7,
    0x420ba270,
    0x420c2485,
    0x420ca345,
    0x420d235f,
    0x420da396,
    0x421223b0,
    0x4217244c,
    0x4217a3f2,
    0x421c2414,
    0x421f23cf,
    0x4221249c,
    0x4226242f,
    0x422b2535,
    0x422ba4fe,
    0x422c251d,
    0x422ca4d8,
    0x422d24b7,
    0x443206ad,
    0x443286bc,
    0x443306c8,
    0x443386d6,
    0x443406e9,
    0x443486fa,
    0x44350701,
    0x4435870b,
    0x4436071e,
    0x44368734,
    0x44370746,
    0x44378753,
    0x44380762,
    0x4438876a,
    0x44390782,
    0x44398790,
    0x443a07a3,
    0x4c3212b0,
    0x4c3292c0,
    0x4c3312d3,
    0x4c3392f3,
    0x4c340094,
    0x4c3480b0,
    0x4c3512ff,
    0x4c35930d,
    0x4c361329,
    0x4c36933c,
    0x4c37134b,
    0x4c379359,
    0x4c38136e,
    0x4c38937a,
    0x4c39139a,
    0x4c3993c4,
    0x4c3a13dd,
    0x4c3a93f6,
    0x4c3b05d0,
    0x4c3b940f,
    0x4c3c1421,
    0x4c3c9430,
    0x4c3d10bd,
    0x4c3d9449,
    0x4c3e1456,
    0x50322a92,
    0x5032aaa1,
    0x50332aac,
    0x5033aabc,
    0x50342ad5,
    0x5034aaef,
    0x50352afd,
    0x5035ab13,
    0x50362b25,
    0x5036ab3b,
    0x50372b54,
    0x5037ab67,
    0x50382b7f,
    0x5038ab90,
    0x50392ba5,
    0x5039abb9,
    0x503a2bd9,
    0x503aabef,
    0x503b2c07,
    0x503bac19,
    0x503c2c35,
    0x503cac4c,
    0x503d2c65,
    0x503dac7b,
    0x503e2c88,
    0x503eac9e,
    0x503f2cb0,
    0x503f8348,
    0x50402cc3,
    0x5040acd3,
    0x50412ced,
    0x5041acfc,
    0x50422d16,
    0x5042ad33,
    0x50432d43,
    0x5043ad53,
    0x50442d62,
    0x50448414,
    0x50452d76,
    0x5045ad94,
    0x50462da7,
    0x5046adbd,
    0x50472dcf,
    0x5047ade4,
    0x50482e0a,
    0x5048ae18,
    0x50492e2b,
    0x5049ae40,
    0x504a2e56,
    0x504aae66,
    0x504b2e86,
    0x504bae99,
    0x504c2ebc,
    0x504caeea,
    0x504d2efc,
    0x504daf19,
    0x504e2f34,
    0x504eaf50,
    0x504f2f62,
    0x504faf79,
    0x50502f88,
    0x50508687,
    0x50512f9b,
    0x58320e1f,
    0x68320de1,
    0x68328b9b,
    0x68330bae,
    0x68338def,
    0x68340dff,
    0x683480b0,
    0x6c320dbd,
    0x6c328b7e,
    0x6c330dc8,
    0x7432098d,
    0x783208f2,
    0x78328907,
    0x78330913,
    0x78338083,
    0x78340922,
    0x78348937,
    0x78350956,
    0x78358978,
    0x7836098d,
    0x783689a3,
    0x783709b3,
    0x783789c6,
    0x783809d9,
    0x783889eb,
    0x783909f8,
    0x78398a17,
    0x783a0a2c,
    0x783a8a3a,
    0x783b0a44,
    0x783b8a58,
    0x783c0a6f,
    0x783c8a84,
    0x783d0a9b,
    0x783d8ab0,
    0x783e0a06,
    0x7c3211b2,
};

const size_t kOpenSSLReasonValuesLen = sizeof(kOpenSSLReasonValues) / sizeof(kOpenSSLReasonValues[0]);

const char kOpenSSLReasonStringData[] =
    "ASN1_LENGTH_MISMATCH\0"
    "AUX_ERROR\0"
    "BAD_GET_ASN1_OBJECT_CALL\0"
    "BAD_OBJECT_HEADER\0"
    "BMPSTRING_IS_WRONG_LENGTH\0"
    "BN_LIB\0"
    "BOOLEAN_IS_WRONG_LENGTH\0"
    "BUFFER_TOO_SMALL\0"
    "DECODE_ERROR\0"
    "DEPTH_EXCEEDED\0"
    "ENCODE_ERROR\0"
    "ERROR_GETTING_TIME\0"
    "EXPECTING_AN_ASN1_SEQUENCE\0"
    "EXPECTING_AN_INTEGER\0"
    "EXPECTING_AN_OBJECT\0"
    "EXPECTING_A_BOOLEAN\0"
    "EXPECTING_A_TIME\0"
    "EXPLICIT_LENGTH_MISMATCH\0"
    "EXPLICIT_TAG_NOT_CONSTRUCTED\0"
    "FIELD_MISSING\0"
    "FIRST_NUM_TOO_LARGE\0"
    "HEADER_TOO_LONG\0"
    "ILLEGAL_BITSTRING_FORMAT\0"
    "ILLEGAL_BOOLEAN\0"
    "ILLEGAL_CHARACTERS\0"
    "ILLEGAL_FORMAT\0"
    "ILLEGAL_HEX\0"
    "ILLEGAL_IMPLICIT_TAG\0"
    "ILLEGAL_INTEGER\0"
    "ILLEGAL_NESTED_TAGGING\0"
    "ILLEGAL_NULL\0"
    "ILLEGAL_NULL_VALUE\0"
    "ILLEGAL_OBJECT\0"
    "ILLEGAL_OPTIONAL_ANY\0"
    "ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE\0"
    "ILLEGAL_TAGGED_ANY\0"
    "ILLEGAL_TIME_VALUE\0"
    "INTEGER_NOT_ASCII_FORMAT\0"
    "INTEGER_TOO_LARGE_FOR_LONG\0"
    "INVALID_BIT_STRING_BITS_LEFT\0"
    "INVALID_BMPSTRING_LENGTH\0"
    "INVALID_DIGIT\0"
    "INVALID_MODIFIER\0"
    "INVALID_NUMBER\0"
    "INVALID_OBJECT_ENCODING\0"
    "INVALID_SEPARATOR\0"
    "INVALID_TIME_FORMAT\0"
    "INVALID_UNIVERSALSTRING_LENGTH\0"
    "INVALID_UTF8STRING\0"
    "LIST_ERROR\0"
    "MALLOC_FAILURE\0"
    "MISSING_ASN1_EOS\0"
    "MISSING_EOC\0"
    "MISSING_SECOND_NUMBER\0"
    "MISSING_VALUE\0"
    "MSTRING_NOT_UNIVERSAL\0"
    "MSTRING_WRONG_TAG\0"
    "NESTED_ASN1_ERROR\0"
    "NESTED_ASN1_STRING\0"
    "NON_HEX_CHARACTERS\0"
    "NOT_ASCII_FORMAT\0"
    "NOT_ENOUGH_DATA\0"
    "NO_MATCHING_CHOICE_TYPE\0"
    "NULL_IS_WRONG_LENGTH\0"
    "OBJECT_NOT_ASCII_FORMAT\0"
    "ODD_NUMBER_OF_CHARS\0"
    "SECOND_NUMBER_TOO_LARGE\0"
    "SEQUENCE_LENGTH_MISMATCH\0"
    "SEQUENCE_NOT_CONSTRUCTED\0"
    "SEQUENCE_OR_SET_NEEDS_CONFIG\0"
    "SHORT_LINE\0"
    "STREAMING_NOT_SUPPORTED\0"
    "STRING_TOO_LONG\0"
    "STRING_TOO_SHORT\0"
    "TAG_VALUE_TOO_HIGH\0"
    "TIME_NOT_ASCII_FORMAT\0"
    "TOO_LONG\0"
    "TYPE_NOT_CONSTRUCTED\0"
    "TYPE_NOT_PRIMITIVE\0"
    "UNEXPECTED_EOC\0"
    "UNIVERSALSTRING_IS_WRONG_LENGTH\0"
    "UNKNOWN_FORMAT\0"
    "UNKNOWN_TAG\0"
    "UNSUPPORTED_ANY_DEFINED_BY_TYPE\0"
    "UNSUPPORTED_PUBLIC_KEY_TYPE\0"
    "UNSUPPORTED_TYPE\0"
    "WRONG_TAG\0"
    "WRONG_TYPE\0"
    "BAD_FOPEN_MODE\0"
    "BROKEN_PIPE\0"
    "CONNECT_ERROR\0"
    "ERROR_SETTING_NBIO\0"
    "INVALID_ARGUMENT\0"
    "IN_USE\0"
    "KEEPALIVE\0"
    "NBIO_CONNECT_ERROR\0"
    "NO_HOSTNAME_SPECIFIED\0"
    "NO_PORT_SPECIFIED\0"
    "NO_SUCH_FILE\0"
    "NULL_PARAMETER\0"
    "SYS_LIB\0"
    "UNABLE_TO_CREATE_SOCKET\0"
    "UNINITIALIZED\0"
    "UNSUPPORTED_METHOD\0"
    "WRITE_TO_READ_ONLY_BIO\0"
    "ARG2_LT_ARG3\0"
    "BAD_ENCODING\0"
    "BAD_RECIPROCAL\0"
    "BIGNUM_TOO_LONG\0"
    "BITS_TOO_SMALL\0"
    "CALLED_WITH_EVEN_MODULUS\0"
    "DIV_BY_ZERO\0"
    "EXPAND_ON_STATIC_BIGNUM_DATA\0"
    "INPUT_NOT_REDUCED\0"
    "INVALID_RANGE\0"
    "NEGATIVE_NUMBER\0"
    "NOT_A_SQUARE\0"
    "NOT_INITIALIZED\0"
    "NO_INVERSE\0"
    "PRIVATE_KEY_TOO_LARGE\0"
    "P_IS_NOT_PRIME\0"
    "TOO_MANY_ITERATIONS\0"
    "TOO_MANY_TEMPORARY_VARIABLES\0"
    "AES_KEY_SETUP_FAILED\0"
    "BAD_DECRYPT\0"
    "BAD_KEY_LENGTH\0"
    "CTRL_NOT_IMPLEMENTED\0"
    "CTRL_OPERATION_NOT_IMPLEMENTED\0"
    "DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH\0"
    "INITIALIZATION_ERROR\0"
    "INPUT_NOT_INITIALIZED\0"
    "INVALID_AD_SIZE\0"
    "INVALID_KEY_LENGTH\0"
    "INVALID_NONCE_SIZE\0"
    "INVALID_OPERATION\0"
    "IV_TOO_LARGE\0"
    "NO_CIPHER_SET\0"
    "NO_DIRECTION_SET\0"
    "OUTPUT_ALIASES_INPUT\0"
    "TAG_TOO_LARGE\0"
    "TOO_LARGE\0"
    "UNSUPPORTED_AD_SIZE\0"
    "UNSUPPORTED_INPUT_SIZE\0"
    "UNSUPPORTED_KEY_SIZE\0"
    "UNSUPPORTED_NONCE_SIZE\0"
    "UNSUPPORTED_TAG_SIZE\0"
    "WRONG_FINAL_BLOCK_LENGTH\0"
    "LIST_CANNOT_BE_NULL\0"
    "MISSING_CLOSE_SQUARE_BRACKET\0"
    "MISSING_EQUAL_SIGN\0"
    "NO_CLOSE_BRACE\0"
    "UNABLE_TO_CREATE_NEW_SECTION\0"
    "VARIABLE_HAS_NO_VALUE\0"
    "BAD_GENERATOR\0"
    "INVALID_PUBKEY\0"
    "MODULUS_TOO_LARGE\0"
    "NO_PRIVATE_VALUE\0"
    "BAD_Q_VALUE\0"
    "MISSING_PARAMETERS\0"
    "NEED_NEW_SETUP_VALUES\0"
    "BIGNUM_OUT_OF_RANGE\0"
    "COORDINATES_OUT_OF_RANGE\0"
    "D2I_ECPKPARAMETERS_FAILURE\0"
    "EC_GROUP_NEW_BY_NAME_FAILURE\0"
    "GROUP2PKPARAMETERS_FAILURE\0"
    "I2D_ECPKPARAMETERS_FAILURE\0"
    "INCOMPATIBLE_OBJECTS\0"
    "INVALID_COMPRESSED_POINT\0"
    "INVALID_COMPRESSION_BIT\0"
    "INVALID_ENCODING\0"
    "INVALID_FIELD\0"
    "INVALID_FORM\0"
    "INVALID_GROUP_ORDER\0"
    "INVALID_PRIVATE_KEY\0"
    "MISSING_PRIVATE_KEY\0"
    "NON_NAMED_CURVE\0"
    "PKPARAMETERS2GROUP_FAILURE\0"
    "POINT_AT_INFINITY\0"
    "POINT_IS_NOT_ON_CURVE\0"
    "SLOT_FULL\0"
    "UNDEFINED_GENERATOR\0"
    "UNKNOWN_GROUP\0"
    "UNKNOWN_ORDER\0"
    "WRONG_CURVE_PARAMETERS\0"
    "WRONG_ORDER\0"
    "KDF_FAILED\0"
    "POINT_ARITHMETIC_FAILURE\0"
    "BAD_SIGNATURE\0"
    "NOT_IMPLEMENTED\0"
    "RANDOM_NUMBER_GENERATION_FAILED\0"
    "OPERATION_NOT_SUPPORTED\0"
    "BN_DECODE_ERROR\0"
    "COMMAND_NOT_SUPPORTED\0"
    "CONTEXT_NOT_INITIALISED\0"
    "DIFFERENT_KEY_TYPES\0"
    "DIFFERENT_PARAMETERS\0"
    "DIGEST_AND_KEY_TYPE_NOT_SUPPORTED\0"
    "EXPECTING_AN_EC_KEY_KEY\0"
    "EXPECTING_AN_RSA_KEY\0"
    "EXPECTING_A_DH_KEY\0"
    "EXPECTING_A_DSA_KEY\0"
    "ILLEGAL_OR_UNSUPPORTED_PADDING_MODE\0"
    "INVALID_CURVE\0"
    "INVALID_DIGEST_LENGTH\0"
    "INVALID_DIGEST_TYPE\0"
    "INVALID_KEYBITS\0"
    "INVALID_MGF1_MD\0"
    "INVALID_PADDING_MODE\0"
    "INVALID_PSS_PARAMETERS\0"
    "INVALID_PSS_SALTLEN\0"
    "INVALID_SALT_LENGTH\0"
    "INVALID_TRAILER\0"
    "KEYS_NOT_SET\0"
    "NO_DEFAULT_DIGEST\0"
    "NO_KEY_SET\0"
    "NO_MDC2_SUPPORT\0"
    "NO_NID_FOR_CURVE\0"
    "NO_OPERATION_SET\0"
    "NO_PARAMETERS_SET\0"
    "OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE\0"
    "OPERATON_NOT_INITIALIZED\0"
    "PARAMETER_ENCODING_ERROR\0"
    "UNKNOWN_DIGEST\0"
    "UNKNOWN_MASK_DIGEST\0"
    "UNKNOWN_MESSAGE_DIGEST_ALGORITHM\0"
    "UNKNOWN_PUBLIC_KEY_TYPE\0"
    "UNKNOWN_SIGNATURE_ALGORITHM\0"
    "UNSUPPORTED_ALGORITHM\0"
    "UNSUPPORTED_MASK_ALGORITHM\0"
    "UNSUPPORTED_MASK_PARAMETER\0"
    "UNSUPPORTED_SIGNATURE_TYPE\0"
    "WRONG_PUBLIC_KEY_TYPE\0"
    "OUTPUT_TOO_LARGE\0"
    "UNKNOWN_NID\0"
    "BAD_BASE64_DECODE\0"
    "BAD_END_LINE\0"
    "BAD_IV_CHARS\0"
    "BAD_PASSWORD_READ\0"
    "CIPHER_IS_NULL\0"
    "ERROR_CONVERTING_PRIVATE_KEY\0"
    "NOT_DEK_INFO\0"
    "NOT_ENCRYPTED\0"
    "NOT_PROC_TYPE\0"
    "NO_START_LINE\0"
    "READ_KEY\0"
    "SHORT_HEADER\0"
    "UNSUPPORTED_CIPHER\0"
    "UNSUPPORTED_ENCRYPTION\0"
    "BAD_PKCS12_DATA\0"
    "BAD_PKCS12_VERSION\0"
    "CIPHER_HAS_NO_OBJECT_IDENTIFIER\0"
    "CRYPT_ERROR\0"
    "ENCRYPT_ERROR\0"
    "ERROR_SETTING_CIPHER_PARAMS\0"
    "INCORRECT_PASSWORD\0"
    "KEYGEN_FAILURE\0"
    "KEY_GEN_ERROR\0"
    "METHOD_NOT_SUPPORTED\0"
    "MISSING_MAC\0"
    "MULTIPLE_PRIVATE_KEYS_IN_PKCS12\0"
    "PKCS12_PUBLIC_KEY_INTEGRITY_NOT_SUPPORTED\0"
    "PKCS12_TOO_DEEPLY_NESTED\0"
    "PRIVATE_KEY_DECODE_ERROR\0"
    "PRIVATE_KEY_ENCODE_ERROR\0"
    "UNKNOWN_ALGORITHM\0"
    "UNKNOWN_CIPHER\0"
    "UNKNOWN_CIPHER_ALGORITHM\0"
    "UNKNOWN_HASH\0"
    "UNSUPPORTED_PRIVATE_KEY_ALGORITHM\0"
    "BAD_E_VALUE\0"
    "BAD_FIXED_HEADER_DECRYPT\0"
    "BAD_PAD_BYTE_COUNT\0"
    "BAD_RSA_PARAMETERS\0"
    "BAD_VERSION\0"
    "BLOCK_TYPE_IS_NOT_01\0"
    "BN_NOT_INITIALIZED\0"
    "CANNOT_RECOVER_MULTI_PRIME_KEY\0"
    "CRT_PARAMS_ALREADY_GIVEN\0"
    "CRT_VALUES_INCORRECT\0"
    "DATA_LEN_NOT_EQUAL_TO_MOD_LEN\0"
    "DATA_TOO_LARGE\0"
    "DATA_TOO_LARGE_FOR_KEY_SIZE\0"
    "DATA_TOO_LARGE_FOR_MODULUS\0"
    "DATA_TOO_SMALL\0"
    "DATA_TOO_SMALL_FOR_KEY_SIZE\0"
    "DIGEST_TOO_BIG_FOR_RSA_KEY\0"
    "D_E_NOT_CONGRUENT_TO_1\0"
    "EMPTY_PUBLIC_KEY\0"
    "FIRST_OCTET_INVALID\0"
    "INCONSISTENT_SET_OF_CRT_VALUES\0"
    "INTERNAL_ERROR\0"
    "INVALID_MESSAGE_LENGTH\0"
    "KEY_SIZE_TOO_SMALL\0"
    "LAST_OCTET_INVALID\0"
    "MUST_HAVE_AT_LEAST_TWO_PRIMES\0"
    "NO_PUBLIC_EXPONENT\0"
    "NULL_BEFORE_BLOCK_MISSING\0"
    "N_NOT_EQUAL_P_Q\0"
    "OAEP_DECODING_ERROR\0"
    "ONLY_ONE_OF_P_Q_GIVEN\0"
    "OUTPUT_BUFFER_TOO_SMALL\0"
    "PADDING_CHECK_FAILED\0"
    "PKCS_DECODING_ERROR\0"
    "SLEN_CHECK_FAILED\0"
    "SLEN_RECOVERY_FAILED\0"
    "UNKNOWN_ALGORITHM_TYPE\0"
    "UNKNOWN_PADDING_TYPE\0"
    "VALUE_MISSING\0"
    "WRONG_SIGNATURE_LENGTH\0"
    "APP_DATA_IN_HANDSHAKE\0"
    "ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT\0"
    "BAD_ALERT\0"
    "BAD_CHANGE_CIPHER_SPEC\0"
    "BAD_DATA_RETURNED_BY_CALLBACK\0"
    "BAD_DH_P_LENGTH\0"
    "BAD_DIGEST_LENGTH\0"
    "BAD_ECC_CERT\0"
    "BAD_ECPOINT\0"
    "BAD_HANDSHAKE_RECORD\0"
    "BAD_HELLO_REQUEST\0"
    "BAD_LENGTH\0"
    "BAD_PACKET_LENGTH\0"
    "BAD_RSA_ENCRYPT\0"
    "BAD_SRTP_MKI_VALUE\0"
    "BAD_SRTP_PROTECTION_PROFILE_LIST\0"
    "BAD_SSL_FILETYPE\0"
    "BAD_WRITE_RETRY\0"
    "BIO_NOT_SET\0"
    "CA_DN_LENGTH_MISMATCH\0"
    "CA_DN_TOO_LONG\0"
    "CCS_RECEIVED_EARLY\0"
    "CERTIFICATE_VERIFY_FAILED\0"
    "CERT_CB_ERROR\0"
    "CERT_LENGTH_MISMATCH\0"
    "CHANNEL_ID_NOT_P256\0"
    "CHANNEL_ID_SIGNATURE_INVALID\0"
    "CIPHER_OR_HASH_UNAVAILABLE\0"
    "CLIENTHELLO_PARSE_FAILED\0"
    "CLIENTHELLO_TLSEXT\0"
    "CONNECTION_REJECTED\0"
    "CONNECTION_TYPE_NOT_SET\0"
    "CUSTOM_EXTENSION_ERROR\0"
    "DATA_LENGTH_TOO_LONG\0"
    "DECRYPTION_FAILED\0"
    "DECRYPTION_FAILED_OR_BAD_RECORD_MAC\0"
    "DH_PUBLIC_VALUE_LENGTH_IS_WRONG\0"
    "DH_P_TOO_LONG\0"
    "DIGEST_CHECK_FAILED\0"
    "DTLS_MESSAGE_TOO_BIG\0"
    "ECC_CERT_NOT_FOR_SIGNING\0"
    "EMS_STATE_INCONSISTENT\0"
    "ENCRYPTED_LENGTH_TOO_LONG\0"
    "ERROR_ADDING_EXTENSION\0"
    "ERROR_IN_RECEIVED_CIPHER_LIST\0"
    "ERROR_PARSING_EXTENSION\0"
    "EXCESSIVE_MESSAGE_SIZE\0"
    "EXTRA_DATA_IN_MESSAGE\0"
    "FRAGMENT_MISMATCH\0"
    "GOT_NEXT_PROTO_WITHOUT_EXTENSION\0"
    "HANDSHAKE_FAILURE_ON_CLIENT_HELLO\0"
    "HTTPS_PROXY_REQUEST\0"
    "HTTP_REQUEST\0"
    "INAPPROPRIATE_FALLBACK\0"
    "INVALID_COMMAND\0"
    "INVALID_MESSAGE\0"
    "INVALID_SSL_SESSION\0"
    "INVALID_TICKET_KEYS_LENGTH\0"
    "LENGTH_MISMATCH\0"
    "LIBRARY_HAS_NO_CIPHERS\0"
    "MISSING_EXTENSION\0"
    "MISSING_RSA_CERTIFICATE\0"
    "MISSING_TMP_DH_KEY\0"
    "MISSING_TMP_ECDH_KEY\0"
    "MIXED_SPECIAL_OPERATOR_WITH_GROUPS\0"
    "MTU_TOO_SMALL\0"
    "NEGOTIATED_BOTH_NPN_AND_ALPN\0"
    "NESTED_GROUP\0"
    "NO_CERTIFICATES_RETURNED\0"
    "NO_CERTIFICATE_ASSIGNED\0"
    "NO_CERTIFICATE_SET\0"
    "NO_CIPHERS_AVAILABLE\0"
    "NO_CIPHERS_PASSED\0"
    "NO_CIPHER_MATCH\0"
    "NO_COMPRESSION_SPECIFIED\0"
    "NO_METHOD_SPECIFIED\0"
    "NO_P256_SUPPORT\0"
    "NO_PRIVATE_KEY_ASSIGNED\0"
    "NO_RENEGOTIATION\0"
    "NO_REQUIRED_DIGEST\0"
    "NO_SHARED_CIPHER\0"
    "NULL_SSL_CTX\0"
    "NULL_SSL_METHOD_PASSED\0"
    "OLD_SESSION_CIPHER_NOT_RETURNED\0"
    "OLD_SESSION_VERSION_NOT_RETURNED\0"
    "PARSE_TLSEXT\0"
    "PATH_TOO_LONG\0"
    "PEER_DID_NOT_RETURN_A_CERTIFICATE\0"
    "PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE\0"
    "PROTOCOL_IS_SHUTDOWN\0"
    "PSK_IDENTITY_NOT_FOUND\0"
    "PSK_NO_CLIENT_CB\0"
    "PSK_NO_SERVER_CB\0"
    "READ_TIMEOUT_EXPIRED\0"
    "RECORD_LENGTH_MISMATCH\0"
    "RECORD_TOO_LARGE\0"
    "RENEGOTIATION_ENCODING_ERR\0"
    "RENEGOTIATION_MISMATCH\0"
    "REQUIRED_CIPHER_MISSING\0"
    "RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION\0"
    "RESUMED_NON_EMS_SESSION_WITH_EMS_EXTENSION\0"
    "SCSV_RECEIVED_WHEN_RENEGOTIATING\0"
    "SERVERHELLO_TLSEXT\0"
    "SESSION_ID_CONTEXT_UNINITIALIZED\0"
    "SESSION_MAY_NOT_BE_CREATED\0"
    "SIGNATURE_ALGORITHMS_EXTENSION_SENT_BY_SERVER\0"
    "SRTP_COULD_NOT_ALLOCATE_PROFILES\0"
    "SRTP_UNKNOWN_PROTECTION_PROFILE\0"
    "SSL3_EXT_INVALID_SERVERNAME\0"
    "SSLV3_ALERT_BAD_CERTIFICATE\0"
    "SSLV3_ALERT_BAD_RECORD_MAC\0"
    "SSLV3_ALERT_CERTIFICATE_EXPIRED\0"
    "SSLV3_ALERT_CERTIFICATE_REVOKED\0"
    "SSLV3_ALERT_CERTIFICATE_UNKNOWN\0"
    "SSLV3_ALERT_CLOSE_NOTIFY\0"
    "SSLV3_ALERT_DECOMPRESSION_FAILURE\0"
    "SSLV3_ALERT_HANDSHAKE_FAILURE\0"
    "SSLV3_ALERT_ILLEGAL_PARAMETER\0"
    "SSLV3_ALERT_NO_CERTIFICATE\0"
    "SSLV3_ALERT_UNEXPECTED_MESSAGE\0"
    "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE\0"
    "SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION\0"
    "SSL_HANDSHAKE_FAILURE\0"
    "SSL_SESSION_ID_CONTEXT_TOO_LONG\0"
    "TLSV1_ALERT_ACCESS_DENIED\0"
    "TLSV1_ALERT_DECODE_ERROR\0"
    "TLSV1_ALERT_DECRYPTION_FAILED\0"
    "TLSV1_ALERT_DECRYPT_ERROR\0"
    "TLSV1_ALERT_EXPORT_RESTRICTION\0"
    "TLSV1_ALERT_INAPPROPRIATE_FALLBACK\0"
    "TLSV1_ALERT_INSUFFICIENT_SECURITY\0"
    "TLSV1_ALERT_INTERNAL_ERROR\0"
    "TLSV1_ALERT_NO_RENEGOTIATION\0"
    "TLSV1_ALERT_PROTOCOL_VERSION\0"
    "TLSV1_ALERT_RECORD_OVERFLOW\0"
    "TLSV1_ALERT_UNKNOWN_CA\0"
    "TLSV1_ALERT_USER_CANCELLED\0"
    "TLSV1_BAD_CERTIFICATE_HASH_VALUE\0"
    "TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE\0"
    "TLSV1_CERTIFICATE_UNOBTAINABLE\0"
    "TLSV1_UNRECOGNIZED_NAME\0"
    "TLSV1_UNSUPPORTED_EXTENSION\0"
    "TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST\0"
    "TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG\0"
    "TOO_MANY_EMPTY_FRAGMENTS\0"
    "TOO_MANY_WARNING_ALERTS\0"
    "UNABLE_TO_FIND_ECDH_PARAMETERS\0"
    "UNEXPECTED_EXTENSION\0"
    "UNEXPECTED_MESSAGE\0"
    "UNEXPECTED_OPERATOR_IN_GROUP\0"
    "UNEXPECTED_RECORD\0"
    "UNKNOWN_ALERT_TYPE\0"
    "UNKNOWN_CERTIFICATE_TYPE\0"
    "UNKNOWN_CIPHER_RETURNED\0"
    "UNKNOWN_CIPHER_TYPE\0"
    "UNKNOWN_KEY_EXCHANGE_TYPE\0"
    "UNKNOWN_PROTOCOL\0"
    "UNKNOWN_SSL_VERSION\0"
    "UNKNOWN_STATE\0"
    "UNSAFE_LEGACY_RENEGOTIATION_DISABLED\0"
    "UNSUPPORTED_COMPRESSION_ALGORITHM\0"
    "UNSUPPORTED_ELLIPTIC_CURVE\0"
    "UNSUPPORTED_PROTOCOL\0"
    "WRONG_CERTIFICATE_TYPE\0"
    "WRONG_CIPHER_RETURNED\0"
    "WRONG_CURVE\0"
    "WRONG_MESSAGE_TYPE\0"
    "WRONG_SIGNATURE_TYPE\0"
    "WRONG_SSL_VERSION\0"
    "WRONG_VERSION_NUMBER\0"
    "X509_LIB\0"
    "X509_VERIFICATION_SETUP_PROBLEMS\0"
    "AKID_MISMATCH\0"
    "BAD_PKCS7_VERSION\0"
    "BAD_X509_FILETYPE\0"
    "BASE64_DECODE_ERROR\0"
    "CANT_CHECK_DH_KEY\0"
    "CERT_ALREADY_IN_HASH_TABLE\0"
    "CRL_ALREADY_DELTA\0"
    "CRL_VERIFY_FAILURE\0"
    "IDP_MISMATCH\0"
    "INVALID_DIRECTORY\0"
    "INVALID_FIELD_NAME\0"
    "INVALID_TRUST\0"
    "ISSUER_MISMATCH\0"
    "KEY_TYPE_MISMATCH\0"
    "KEY_VALUES_MISMATCH\0"
    "LOADING_CERT_DIR\0"
    "LOADING_DEFAULTS\0"
    "NEWER_CRL_NOT_NEWER\0"
    "NOT_PKCS7_SIGNED_DATA\0"
    "NO_CERTIFICATES_INCLUDED\0"
    "NO_CERT_SET_FOR_US_TO_VERIFY\0"
    "NO_CRLS_INCLUDED\0"
    "NO_CRL_NUMBER\0"
    "PUBLIC_KEY_DECODE_ERROR\0"
    "PUBLIC_KEY_ENCODE_ERROR\0"
    "SHOULD_RETRY\0"
    "UNABLE_TO_FIND_PARAMETERS_IN_CHAIN\0"
    "UNABLE_TO_GET_CERTS_PUBLIC_KEY\0"
    "UNKNOWN_KEY_TYPE\0"
    "UNKNOWN_PURPOSE_ID\0"
    "UNKNOWN_TRUST_ID\0"
    "WRONG_LOOKUP_TYPE\0"
    "BAD_IP_ADDRESS\0"
    "BAD_OBJECT\0"
    "BN_DEC2BN_ERROR\0"
    "BN_TO_ASN1_INTEGER_ERROR\0"
    "CANNOT_FIND_FREE_FUNCTION\0"
    "DIRNAME_ERROR\0"
    "DISTPOINT_ALREADY_SET\0"
    "DUPLICATE_ZONE_ID\0"
    "ERROR_CONVERTING_ZONE\0"
    "ERROR_CREATING_EXTENSION\0"
    "ERROR_IN_EXTENSION\0"
    "EXPECTED_A_SECTION_NAME\0"
    "EXTENSION_EXISTS\0"
    "EXTENSION_NAME_ERROR\0"
    "EXTENSION_NOT_FOUND\0"
    "EXTENSION_SETTING_NOT_SUPPORTED\0"
    "EXTENSION_VALUE_ERROR\0"
    "ILLEGAL_EMPTY_EXTENSION\0"
    "ILLEGAL_HEX_DIGIT\0"
    "INCORRECT_POLICY_SYNTAX_TAG\0"
    "INVALID_BOOLEAN_STRING\0"
    "INVALID_EXTENSION_STRING\0"
    "INVALID_MULTIPLE_RDNS\0"
    "INVALID_NAME\0"
    "INVALID_NULL_ARGUMENT\0"
    "INVALID_NULL_NAME\0"
    "INVALID_NULL_VALUE\0"
    "INVALID_NUMBERS\0"
    "INVALID_OBJECT_IDENTIFIER\0"
    "INVALID_OPTION\0"
    "INVALID_POLICY_IDENTIFIER\0"
    "INVALID_PROXY_POLICY_SETTING\0"
    "INVALID_PURPOSE\0"
    "INVALID_SECTION\0"
    "INVALID_SYNTAX\0"
    "ISSUER_DECODE_ERROR\0"
    "NEED_ORGANIZATION_AND_NUMBERS\0"
    "NO_CONFIG_DATABASE\0"
    "NO_ISSUER_CERTIFICATE\0"
    "NO_ISSUER_DETAILS\0"
    "NO_POLICY_IDENTIFIER\0"
    "NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED\0"
    "NO_PUBLIC_KEY\0"
    "NO_SUBJECT_DETAILS\0"
    "ODD_NUMBER_OF_DIGITS\0"
    "OPERATION_NOT_DEFINED\0"
    "OTHERNAME_ERROR\0"
    "POLICY_LANGUAGE_ALREADY_DEFINED\0"
    "POLICY_PATH_LENGTH\0"
    "POLICY_PATH_LENGTH_ALREADY_DEFINED\0"
    "POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY\0"
    "SECTION_NOT_FOUND\0"
    "UNABLE_TO_GET_ISSUER_DETAILS\0"
    "UNABLE_TO_GET_ISSUER_KEYID\0"
    "UNKNOWN_BIT_STRING_ARGUMENT\0"
    "UNKNOWN_EXTENSION\0"
    "UNKNOWN_EXTENSION_NAME\0"
    "UNKNOWN_OPTION\0"
    "UNSUPPORTED_OPTION\0"
    "USER_TOO_LONG\0"
    "";
