# Test version and initialisation functions

use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay qw(lives_ok);

plan tests => 16;

lives_ok( sub { Net::SSLeay::randomize() }, 'seed pseudorandom number generator' );
lives_ok( sub { Net::SSLeay::ERR_load_crypto_strings() }, 'load libcrypto error strings' );
lives_ok( sub { Net::SSLeay::load_error_strings() }, 'load libssl error strings' );
lives_ok( sub { Net::SSLeay::library_init() }, 'register default TLS ciphers and digest functions' );
lives_ok( sub { Net::SSLeay::OpenSSL_add_all_digests() }, 'register all digest functions' );
#version numbers: 0x00903100 ~ 0.9.3, 0x0090600f ~ 0.6.9
ok( Net::SSLeay::SSLeay() >= 0x00903100, 'SSLeay (version min 0.9.3)' );
isnt( Net::SSLeay::SSLeay_version(), '', 'SSLeay (version string)' );
is( Net::SSLeay::SSLeay_version(),  Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_VERSION()), 'SSLeay_version optional argument' );
is(Net::SSLeay::hello(), 1, 'hello world');

if (exists &Net::SSLeay::OpenSSL_version)
{
    is(Net::SSLeay::SSLeay(), Net::SSLeay::OpenSSL_version_num(), 'OpenSSL_version_num');

    is(Net::SSLeay::OpenSSL_version(), Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_VERSION()), 'OpenSSL_version optional argument');

    is(Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_VERSION()),  Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_VERSION()),  'OpenSSL_version(OPENSSL_VERSION)');
    is(Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_CFLAGS()),   Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_CFLAGS()),   'OpenSSL_version(OPENSSL_CFLAGS)');
    is(Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_BUILT_ON()), Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_BUILT_ON()), 'OpenSSL_version(OPENSSL_BUILT_ON)');
    is(Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_PLATFORM()), Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_PLATFORM()), 'OpenSSL_version(OPENSSL_PLATFORM)');
    is(Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_DIR()),      Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_DIR()),      'OpenSSL_version(OPENSSL_DIR)');
}
else
{
  SKIP: {
      skip('Only on OpenSSL 1.1.0 or later', 7);
    }
}
