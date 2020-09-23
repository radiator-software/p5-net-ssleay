package Test::Net::SSLeay;

use 5.008001;
use strict;
use warnings;
use base qw(Exporter);

use Carp qw(croak);
use Config;
use Cwd qw(abs_path);
use English qw( $EVAL_ERROR $OSNAME $PERL_VERSION -no_match_vars );
use File::Basename qw(dirname);
use File::Spec::Functions qw( abs2rel catfile );
use Test::Net::SSLeay::Socket;

our $VERSION = '1.89_02';

our @EXPORT_OK = qw(
    can_fork can_really_fork can_thread
    data_file_path
    is_libressl is_openssl
    tcp_socket
);

my $data_path = catfile( dirname(__FILE__), '..', '..', '..', 't', 'data' );

sub import {
    my ( $class, @imports ) = @_;

    # Enable strict and warnings in the caller
    strict->import;
    warnings->import;

    # Import common modules into the caller's namespace
    my $caller = caller;
    for (qw(Test::More)) {
        eval "package $caller; use $_; 1;" or croak $EVAL_ERROR;
    }

    # Import requested Test::Net::SSLeay symbols into the caller's namespace
    __PACKAGE__->export_to_level( 1, $class, @imports );

    return 1;
}

sub can_fork {
    return 1 if can_really_fork();

    # Some platforms provide fork emulation using ithreads
    return 1 if $Config{d_pseudofork};

    # d_pseudofork was added in Perl 5.10.0 - this is an approximation for
    # older Perls
    if (    ( $OSNAME eq 'Win32' or $OSNAME eq 'NetWare' )
        and $Config{useithreads}
        and $Config{ccflags} =~ /-DPERL_IMPLICIT_SYS/ )
    {
        return 1;
    }

    return can_thread();
}

sub can_really_fork {
    return 1 if $Config{d_fork};

    return 0;
}

sub can_thread {
    return 0 if not $Config{useithreads};

    # Threads are broken in Perl 5.10.0 when compiled with GCC 4.8 or above
    # (see GH #175)
    if (    $PERL_VERSION == 5.010000
        and $Config{ccname} eq 'gcc'
        and $Config{gccversion} )
    {
        my ( $gcc_major, $gcc_minor ) = split /\./, $Config{gccversion};

        return 0
            if ( $gcc_major > 4 or ( $gcc_major == 4 and $gcc_minor >= 8 ) );
    }

    # Devel::Cover doesn't (currently) work with threads
    return 0 if $INC{'Devel/Cover.pm'};

    return 1;
}

sub data_file_path {
    my ($data_file) = @_;

    my $abs_path = catfile( abs_path($data_path), $data_file );
    my $rel_path = abs2rel($abs_path);

    croak "$rel_path: data file does not exist"
        if not -e $abs_path;

    return $rel_path;
}

sub is_libressl {
    eval { require Net::SSLeay; 1; } or croak $EVAL_ERROR;

    # The most foolproof method of checking whether libssl is provided by
    # LibreSSL is by checking OPENSSL_VERSION_NUMBER: every version of
    # LibreSSL identifies itself as OpenSSL 2.0.0, which is a version number
    # that OpenSSL itself will never use (version 3.0.0 follows 1.1.1)
    return 0
        if Net::SSLeay::constant('OPENSSL_VERSION_NUMBER') != 0x20000000;

    return 1;
}

sub is_openssl {
    eval { require Net::SSLeay; 1; } or croak $EVAL_ERROR;

    # "OpenSSL 2.0.0" is actually LibreSSL
    return 0
        if Net::SSLeay::constant('OPENSSL_VERSION_NUMBER') == 0x20000000;

    return 1;
}

sub tcp_socket {
    return Test::Net::SSLeay::Socket->new( proto => 'tcp' );
}

1;

__END__

=head1 NAME

Test::Net::SSLeay - Helper module for the Net-SSLeay test suite

=head1 VERSION

This document describes version 1.89_01 of Test::Net::SSLeay.

=head1 SYNOPSIS

In a Net-SSLeay test script:

    # Optional summary of the purpose of the tests in this script

    use lib 'inc';

    use Net::SSLeay;        # if required by the tests
    use Test::Net::SSLeay;  # also importing helper functions if required

    # Imports of other modules specific to this test script

    # Plan tests, or skip them altogether if certain preconditions aren't met
    if (disqualifying_condition) {
        plan skip_all => ...;
    } else {
        plan tests => ...;
    }

    # One or more Test::More-based tests

=head1 DESCRIPTION

This is a helper module that makes it easier (or, at least, less repetitive)
to write test scripts for the Net-SSLeay test suite. For consistency, all test
scripts should import this module and follow the preamble structure given in
L</SYNOPSIS>.

Importing this module has the following effects on the caller, regardless of
whether any exports are requested:

=over 4

=item *

C<strict> and C<warnings> are enabled;

=item *

L<Test::More|Test::More>, the test framework used by the Net-SSLeay test
suite, is imported.

=back

No symbols are exported by default. If desired, individual helper functions
may be imported into the caller's namespace by specifying their name in the
import list; see L</"HELPER FUNCTIONS"> for a list of available helper
functions.

=head1 HELPER FUNCTIONS

=head2 can_fork

    if (can_fork()) {
        # Run tests that rely on a working fork() implementation
    }

Returns true if this system natively supports the C<fork()> system call, or if
Perl can emulate C<fork()> on this system using interpreter-level threads.
Otherwise, returns false.

=head2 can_really_fork

    if (can_really_fork()) {
        # Run tests that rely on a native fork() implementation
    }

Returns true if this system natively supports the C<fork()> system call, or
false if not.

=head2 can_thread

    if (can_thread()) {
        # Run tests that rely on working threads support
    }

Returns true if reliable interpreter-level threads support is available in
this Perl, or false if not.

=head2 data_file_path

    my $cert_path = data_file_path('wildcard-cert.cert.pem');
    my $key_path  = data_file_path('wildcard-cert.key.pem');

Returns the relative path to a given file in the test suite data directory
(C<t/local/>). Dies if the file does not exist.

=head2 is_libressl

    if (is_libressl()) {
        # Run LibreSSL-specific tests
    }

Returns true if libssl is provided by LibreSSL, or false if not.

=head2 is_openssl

    if (is_openssl()) {
        # Run OpenSSL-specific tests
    }

Returns true if libssl is provided by OpenSSL, or false if not.

=head2 tcp_socket

    my $server = tcp_socket();

    # Accept connection from client:
    my $sock_in = $server->accept();

    # Create connection to server:
    my $sock_out = $server->connect();

Creates a TCP server socket that listens on localhost on an arbitrarily-chosen
free port. Convenience methods are provided for accepting, establishing and
closing connections.

Returns a L<Test::Net::SSLeay::Socket|Test::Net::SSLeay::Socket> object. Dies
on failure.

=head1 BUGS

If you encounter a problem with this module that you believe is a bug, please
report it in one of the following ways:

=over 4

=item *

create a new issue under the
L<Net-SSLeay GitHub project|https://github.com/radiator-software/p5-net-ssleay/issues/new>;

=item *

open a ticket using the
L<CPAN RT bug tracker's web interface|https://rt.cpan.org/Public/Bug/Report.html?Queue=Net-SSLeay>;

=item *

send an email to the
L<CPAN RT bug tracker's bug-reporting system|mailto:bug-Net-SSLeay@rt.cpan.org>.

=back

Please make sure your bug report includes the following information:

=over

=item *

the code you are trying to run (ideally a minimum working example that
reproduces the problem), or the full output of the Net-SSLeay test suite if
the problem relates to a test failure;

=item *

your operating system name and version;

=item *

the output of C<perl -V>;

=item *

the version of Net-SSLeay you are using;

=item *

the version of OpenSSL or LibreSSL you are using.

=back

=head1 AUTHORS

Originally written by Chris Novakovic.

Maintained by Chris Novakovic, Tuure Vartiainen and Heikki Vatiainen.

=head1 COPYRIGHT AND LICENSE

Copyright 2020- Chris Novakovic <chris@chrisn.me.uk>.

Copyright 2020- Tuure Vartiainen <vartiait@radiatorsoftware.com>.

Copyright 2020- Heikki Vatiainen <hvn@radiatorsoftware.com>.

This module is released under the terms of the Artistic License 2.0. For
details, see the C<LICENSE> file distributed with Net-SSLeay's source code.

=cut
