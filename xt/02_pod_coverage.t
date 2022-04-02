# Ensure all public symbols in Net::SSLeay, Net::SSLeay::Handle, and our private
# Test:: modules are appropriately documented

use lib 'inc';

use Test::Net::SSLeay;

use Test::Pod::Coverage;

plan tests => 4;

pod_coverage_ok('Net::SSLeay');
pod_coverage_ok('Net::SSLeay::Handle');
pod_coverage_ok('Test::Net::SSLeay');
pod_coverage_ok('Test::Net::SSLeay::Socket');
