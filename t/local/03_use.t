# Basic module loading test, plus OS/Perl/libssl information to assist
# with diagnosing later test failures

use lib 'inc';

use Test::Net::SSLeay;

BEGIN {
    plan tests => 1;

    use_ok('Net::SSLeay');
}

diag("");
diag("Testing Net::SSLeay $Net::SSLeay::VERSION");
diag("");
diag("Perl information:");
diag("  Version:         '" . $]  . "'");
diag("  Executable path: '" . $^X . "'");
diag("");

my $version_num;
if (defined &Net::SSLeay::OpenSSL_version_num) {
    diag("Library version with OpenSSL_version_num():");
    $version_num = Net::SSLeay::OpenSSL_version_num();
} else {
    diag("Library version with SSLeay():");
    $version_num = Net::SSLeay::SSLeay();
}
diag("  OPENSSL_VERSION_NUMBER: " . sprintf("'0x%08x'", $version_num));
diag("");

my $have_openssl_version = defined &Net::SSLeay::OpenSSL_version;

diag("Library information with SSLeay_version()" . ($have_openssl_version ? " and OpenSSL_version()" : '') . ":");
diag("  SSLEAY_VERSION:              '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_VERSION())  . "'");
diag("  SSLEAY_CFLAGS:               '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_CFLAGS())   . "'");
diag("  SSLEAY_BUILT_ON:             '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_BUILT_ON()) . "'");
diag("  SSLEAY_PLATFORM:             '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_PLATFORM()) . "'");
diag("  SSLEAY_DIR:                  '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_DIR())      . "'");

# This constant was added about the same time as OpenSSL_version()
if ($have_openssl_version) {
	diag("  OPENSSL_ENGINES_DIR:         '" . Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_ENGINES_DIR()) . "'");
}

# These were added in OpenSSL 3.0.0
if (eval { Net::SSLeay::OPENSSL_MODULES_DIR(); 1; }) {
    diag("  OPENSSL_MODULES_DIR:         '" . Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_MODULES_DIR())         . "'");
    diag("  OPENSSL_CPU_INFO:            '" . Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_CPU_INFO())            . "'");
    diag("  OPENSSL_VERSION_STRING:      '" . Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_VERSION_STRING())      . "'");
    diag("  OPENSSL_FULL_VERSION_STRING: '" . Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_FULL_VERSION_STRING()) . "'");
}
