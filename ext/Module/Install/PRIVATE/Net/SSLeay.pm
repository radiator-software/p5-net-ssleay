#line 1
package Module::Install::PRIVATE::Net::SSLeay;

use strict;
use Module::Install::Base;
use File::Basename ();
use File::Spec;
use Config;
use Symbol qw(gensym);

use vars qw{$VERSION @ISA};
BEGIN {
    $VERSION = 0.01;
    @ISA     = qw{Module::Install::Base};
}

# Define this to one if you want to link the openssl libraries statically into 
# the Net-SSLeay loadable object on Windows
my $win_link_statically = 0;

sub ssleay {
    my ($self) = @_;

    $self->requires_external_cc;

    my $prefix = $self->find_openssl_prefix;
    my $exec   = $self->find_openssl_exec($prefix);

    unless (-x $exec) {
        die <<EOM;
*** Could not find OpenSSL
    If it's already installed, please set the OPENSSL_PREFIX environment
    variable accordingly. If it isn't installed yet, get the latest version
    from http://www.openssl.org/.
EOM
    }

    $self->check_openssl_version($prefix, $exec);
    my $opts = $self->ssleay_get_build_opts($prefix, $exec);

    $self->makemaker_args(
        CCCDLFLAGS => $opts->{cccdlflags},
        OPTIMIZE => $opts->{optimize},
        INC => join(' ', map {"-I$_"} @{$opts->{inc_paths}}),
        LIBS => join(' ', (map {"-L$_"} @{$opts->{lib_paths}}), (map {"-l$_"} @{$opts->{lib_links}})),
    );

    if ( $self->prompt(
            "Do you want to run external tests?\n".
            "These tests *will* *fail* if you do not have network connectivity.",
            'n',
    ) =~ /^y/i ) {
        $self->tests('t/*/*.t t/*/*/*.t');
    } else {
        $self->tests('t/local/*.t t/handle/local/*.t');
    }
}

sub ssleay_get_build_opts {
    my ($self, $prefix, $exec) = @_;

    my $opts = {
        inc_paths  => ["$prefix/include", "$prefix/inc32", '/usr/kerberos/include'],
        lib_paths  => [$prefix, "$prefix/lib", "$prefix/out32dll"],
        lib_links  => [],
        cccdlflags => '',
    };

    my $rsaref  = $self->ssleay_is_rsaref;

    print <<EOM;
*** Be sure to use the same compiler and options to compile your OpenSSL, perl,
    and Net::SSLeay. Mixing and matching compilers is not supported.
EOM

    if ($^O eq 'MSWin32') {
        print "*** RSAREF build on Windows not supported out of box" if $rsaref;
        if ($win_link_statically) {
            # Link to static libs
            push @{ $opts->{lib_paths} }, "$prefix/lib/VC/static";
        }
        else {
            push @{ $opts->{lib_paths} }, "$prefix/lib/VC";
        }
        # Library names depend on the compiler. We expect either 
        # libeay32MD and ssleay32MD or
        # libeay32 and ssleay32.
        # This construction will not complain as long as it find at least one
        # libssl32.a is made by openssl onWin21 with the ms/minw32.bat builder
        push @{ $opts->{lib_links} }, qw( libeay32MD ssleay32MD libeay32 ssleay32 libssl32);
    }
    else {
        $opts->{optimize} = '-O2 -g';
        push @{ $opts->{lib_links} },
             ($rsaref
              ? qw( ssl crypto RSAglue rsaref z )
              : qw( ssl crypto z )
             );

        if (($Config{cc} =~ /aCC/i) && $^O eq 'hpux') {
            print "*** Enabling HPUX aCC options (+e)\n";
            $opts->{optimize} = '+e '. $opts->{optimize};
        }

        if ( (($Config{ccname} || $Config{cc}) eq 'gcc') && ($Config{cccdlflags} =~ /-fpic/) ) {
            print "*** Enabling gcc -fPIC optimization\n";
            $opts->{cccdlflags} .= '-fPIC';
        }
    }

    return $opts;
}

sub ssleay_is_rsaref {
    my ($self) = @_;

    return $ENV{OPENSSL_RSAREF};
}

my $other_try = 0;
my @nopath;
sub check_no_path {            # On OS/2 it would be typically on default paths
    my $p;
    if (not($other_try++) and $] >= 5.008001) {
       require ExtUtils::Liblist;              # Buggy before this
       my ($list) = ExtUtils::Liblist->ext("-lssl");
       return unless $list =~ /-lssl\b/;
        for $p (split /\Q$Config{path_sep}/, $ENV{PATH}) {
           @nopath = ("$p/openssl$Config{_exe}",       # exe name
                      '.')             # dummy lib path
               if -x "$p/openssl$Config{_exe}"
       }
    }
    @nopath;
}

sub find_openssl_prefix {
    my ($self, $dir) = @_;

    if (defined $ENV{OPENSSL_PREFIX}) {
        return $ENV{OPENSSL_PREFIX};
    }

    my %guesses = (
            '/usr/bin/openssl'               => '/usr',
            '/usr/sbin/openssl'              => '/usr',
            '/opt/ssl/bin/openssl'           => '/opt/ssl',
            '/opt/ssl/sbin/openssl'          => '/opt/ssl',
            '/usr/local/ssl/bin/openssl'     => '/usr/local/ssl',
            '/usr/local/openssl/bin/openssl' => '/usr/local/openssl',
            '/apps/openssl/std/bin/openssl'  => '/apps/openssl/std',
            '/usr/sfw/bin/openssl'           => '/usr/sfw', # Open Solaris
            'C:\OpenSSL\bin\openssl.exe'     => 'C:\OpenSSL',
            $Config{prefix} . '\bin\openssl.exe'      => $Config{prefix},           # strawberry perl
            $Config{prefix} . '\..\c\bin\openssl.exe' => $Config{prefix} . '\..\c', # strawberry perl
    );

    while (my ($k, $v) = each %guesses) {
        if ( -x $k ) {
            return $v;
        }
    }
    (undef, $dir) = $self->check_no_path
       and return $dir;

    return;
}

sub find_openssl_exec {
    my ($self, $prefix) = @_;

    my $exe_path;
    for my $subdir (qw( bin sbin out32dll )) {
        my $path = File::Spec->catfile($prefix, $subdir, "openssl$Config{_exe}");
        if ( -x $path ) {
            return $path;
        }
    }
    ($prefix) = $self->check_no_path
       and return $prefix;
    return;
}

sub check_openssl_version {
    my ($self, $prefix, $exec) = @_;
    my ($major, $minor, $letter);

    {
        my $pipe = gensym();
        open($pipe, "$exec version |")
            or die "Could not execute $exec";
        my $output = <$pipe>;
        chomp $output;
        close $pipe;

        unless ( ($major, $minor, $letter) = $output =~ /^OpenSSL\s+(\d+\.\d+)\.(\d+)([a-z]?)/ ) {
            die <<EOM
*** OpenSSL version test failed
    (`$output' has been returned)
    Either you have bogus OpenSSL or a new version has changed the version
    number format. Please inform the authors!
EOM
        }
    }

    print "*** Found OpenSSL-${major}.${minor}${letter} installed in $prefix\n";

    if ($major < 0.9 || ($major == 0.9 && $minor < 3)) {
        die <<EOM;
*** That's too old!
    Please upgrade OpenSSL to the latest version (http://www.openssl.org/)
EOM
    }

    if ($major > 1.0 || ($major == 1.0 && $minor > 0)) {
        print <<EOM;
*** That's newer than what this module was tested with
    You should consider checking if there is a newer release of this module
    available. Everything will probably work OK, though.
EOM
    }
}

sub fixpath {
    my ($self, $text) = @_;

    my $sep = File::Spec->catdir('');
    $text =~ s{\b/}{$sep}g;

    return $text;
}

1;
