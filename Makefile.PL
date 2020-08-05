use 5.8.1;

use strict;
use warnings;
use ExtUtils::MakeMaker;
use Config;
use File::Spec;
use File::Basename ();
use Symbol qw(gensym);

# Define this to one if you want to link the openssl libraries statically into 
# the Net-SSLeay loadable object on Windows
my $win_link_statically = 0;

my $tests = prompt(
  "Do you want to run external tests?\n".
  "These tests *will* *fail* if you do not have network connectivity.",
  'n',
) =~ /^y/i ? 't/*/*.t t/*/*/*.t' : 't/local/*.t t/handle/local/*.t';

my %eumm_args = (
  NAME => 'Net::SSLeay',
  ABSTRACT => 'Perl extension for using OpenSSL',
  LICENSE => 'artistic_2',
  AUTHOR => [
    'Sampo Kellomäki <sampo@iki.fi>',
    'Florian Ragwitz <rafl@debian.org>',
    'Mike McCauley <mikem@airspayce.com>',
    'Chris Novakovic <chris@chrisn.me.uk>',
    'Tuure Vartiainen <vartiait@radiatorsoftware.com>',
    'Heikki Vatiainen <hvn@radiatorsoftware.com>'
  ],
  VERSION_FROM => 'lib/Net/SSLeay.pm',
  MIN_PERL_VERSION => '5.8.1',
  CONFIGURE_REQUIRES => {
    'ExtUtils::MakeMaker' => '0',
  },
  TEST_REQUIRES => {
    'Carp' => '0',
    'Config' => '0',
    'English' => '0',
    'Scalar::Util' => '0',
    'SelectSaver' => '0',
    'Socket' => '0',
    'Test::More' => '0.60_01',
    'base' => '0',
  },
  PREREQ_PM => {
    'MIME::Base64' => '0',
  },
  test => { TESTS => $tests },
  clean => { FILES => join ' ', map fixpath($_), qw(
      makecert.out
      makecert.err
      sslecho.log
      tcpecho.log
      t/local/ptr_cast_test
      examples/cert.pem
      examples/key.pem
      examples/key.pem.e
      examples/*.0
  ) },
  META_MERGE => {
    "meta-spec" => { version => 2 },
    dynamic_config => 0,
    resources => {
      repository => {
        type => 'git',
        url => 'git://github.com/radiator-software/p5-net-ssleay.git',
        web => 'https://github.com/radiator-software/p5-net-ssleay',
      },
      bugtracker  => {
        web => 'https://rt.cpan.org/Public/Dist/Display.html?Name=net-ssleay',
      },
    },
    no_index => { directory => [ qw(helper_script examples) ] },
    prereqs => {
      develop => {
        requires => {
          'Test::Pod::Coverage' => '1.00',
          'Test::Kwalitee' => '1.00',
        },
      },
    },
  },
  ssleay(),
);

# This can go when EU::MM older than 6.58 are gone
$eumm_args{AUTHOR} = join(', ', @{$eumm_args{AUTHOR}}) unless eval { ExtUtils::MakeMaker->VERSION(6.58); };

# This can go when EU::MM older than 6.64 are gone
delete $eumm_args{TEST_REQUIRES} unless eval { ExtUtils::MakeMaker->VERSION(6.64); };

WriteMakefile(%eumm_args);

sub MY::postamble {
my $regen_script = File::Spec->catfile('helper_script', 'regen_openssl_constants.pl');
my $constants_t = File::Spec->catfile('t', 'local', '21_constants.t');
<<"MAKE";
constants.c : $regen_script
	\$(ABSPERLRUN) $regen_script -gen-c constants.c

$constants_t : $regen_script
	\$(ABSPERLRUN) $regen_script -gen-t $constants_t

SSLeay$Config{'obj_ext'} : constants.c $constants_t

MAKE
}

sub ssleay {
    my $prefix = find_openssl_prefix();
    my $exec   = find_openssl_exec($prefix);
    unless (defined $exec && -x $exec) {
        print <<EOM;
*** Could not find OpenSSL
    If it's already installed, please set the OPENSSL_PREFIX environment
    variable accordingly. If it isn't installed yet, get the latest version
    from http://www.openssl.org/.
EOM
        exit 0; # according http://wiki.cpantesters.org/wiki/CPANAuthorNotes this is best-practice when "missing library"
    }
    check_openssl_version($prefix, $exec);
    my $opts = ssleay_get_build_opts($prefix, $exec);
    my %args = (
        CCCDLFLAGS => $opts->{cccdlflags},
        OPTIMIZE => $opts->{optimize},
        INC => join(' ', map qq{-I"$_"}, @{$opts->{inc_paths}}),
        LIBS => join(' ', (map '-L'.maybe_quote($_), @{$opts->{lib_paths}}), (map {"-l$_"} @{$opts->{lib_links}})),
    );
    # From HMBRAND to handle multple version of OPENSSL installed
    if (my $lp = join " " => map '-L'.maybe_quote($_), @{$opts->{lib_paths} || []})
    {
	($args{uc $_} = $Config{$_}) =~ s/-L/$lp -L/ for qw(lddlflags ldflags);
    }
    %args;
}

sub maybe_quote { $_[0] =~ / / ? qq{"$_[0]"} : $_[0] }

sub ssleay_get_build_opts {
    my ($prefix, $exec) = @_;

    my $opts = {
        lib_links  => [],
        cccdlflags => '',
    };
    for ("$prefix/include", "$prefix/inc32", '/usr/kerberos/include') {
      push @{$opts->{inc_paths}}, $_ if -f "$_/openssl/ssl.h";
    }
    for ($prefix, "$prefix/lib64", "$prefix/lib", "$prefix/out32dll") {
      push @{$opts->{lib_paths}}, $_ if -d $_;
    }

    my $rsaref  = ssleay_is_rsaref();

    print <<EOM;
*** Be sure to use the same compiler and options to compile your OpenSSL, perl,
    and Net::SSLeay. Mixing and matching compilers is not supported.
EOM

    if ($^O eq 'MSWin32') {
        print "*** RSAREF build on Windows not supported out of box" if $rsaref;
        if ($win_link_statically) {
            # Link to static libs
            push @{ $opts->{lib_paths} }, "$prefix/lib/VC/static" if -d "$prefix/lib/VC/static";
        }
        else {
            push @{ $opts->{lib_paths} }, "$prefix/lib/VC" if -d "$prefix/lib/VC";
        }

        my $found = 0;
        my @pairs = ();
        # Library names depend on the compiler
        @pairs = (['eay32','ssl32'],['crypto.dll','ssl.dll'],['crypto','ssl']) if $Config{cc} =~ /gcc/;
        @pairs = (['libeay32','ssleay32'],['libeay32MD','ssleay32MD'],['libeay32MT','ssleay32MT'],['libcrypto','libssl'],['crypto','ssl']) if $Config{cc} =~ /cl/;
        for my $dir (@{$opts->{lib_paths}}) {
          for my $p (@pairs) {
            $found = 1 if ($Config{cc} =~ /gcc/ && -f "$dir/lib$p->[0].a" && -f "$dir/lib$p->[1].a");
            $found = 1 if ($Config{cc} =~ /cl/ && -f "$dir/$p->[0].lib" && -f "$dir/$p->[1].lib");
            if ($found) {
              $opts->{lib_links} = [$p->[0], $p->[1], 'crypt32']; # Some systems need this system lib crypt32 too
              $opts->{lib_paths} = [$dir];
              last;
            }
          }
        }
        if (!$found) {
          #fallback to the old behaviour
          push @{ $opts->{lib_links} }, qw( libeay32MD ssleay32MD libeay32 ssleay32 libssl32 crypt32);
        }
    }
    elsif ($^O eq 'VMS') {
        if (-r 'sslroot:[000000]openssl.cnf') {      # openssl.org source install
          @{ $opts->{lib_paths} } = 'SSLLIB';
          @{ $opts->{lib_links} } = qw( ssl_libssl32.olb ssl_libcrypto32.olb );
        }
        elsif (-r 'ssl1$root:[000000]openssl.cnf') {  # VSI or HPE SSL1 install
            @{ $opts->{lib_paths} } = 'SYS$SHARE';
            @{ $opts->{lib_links} } = qw( SSL1$LIBSSL_SHR32 SSL1$LIBCRYPTO_SHR32 );
        }
        elsif (-r 'ssl$root:[000000]openssl.cnf') {  # HP install
            @{ $opts->{lib_paths} } = 'SYS$SHARE';
            @{ $opts->{lib_links} } = qw( SSL$LIBSSL_SHR32 SSL$LIBCRYPTO_SHR32 );
        }
        @{ $opts->{lib_links} } = map { $_ =~ s/32\b//g } @{ $opts->{lib_links} } if $Config{use64bitall};
    }
    else {
        push @{ $opts->{lib_links} },
             ($rsaref
              ? qw( ssl crypto RSAglue rsaref z )
              : qw( ssl crypto z )
             );

        if (($Config{cc} =~ /aCC/i) && $^O eq 'hpux') {
            print "*** Enabling HPUX aCC options (+e)\n";
            $opts->{optimize} = '+e -O2 -g';
        }

        if ( (($Config{ccname} || $Config{cc}) eq 'gcc') && ($Config{cccdlflags} =~ /-fpic/) ) {
            print "*** Enabling gcc -fPIC optimization\n";
            $opts->{cccdlflags} .= '-fPIC';
        }
    }
    return $opts;
}

sub ssleay_is_rsaref {
    return $ENV{OPENSSL_RSAREF};
}

my $other_try = 0;
my @nopath;
sub check_no_path {            # On OS/2 it would be typically on default paths
    my $p;
    if (not($other_try++) and $] >= 5.008001) {
       use ExtUtils::MM;
       my $mm = MM->new();
       my ($list) = $mm->ext("-lssl");
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
    my ($dir) = @_;

    if (defined $ENV{OPENSSL_PREFIX}) {
        return $ENV{OPENSSL_PREFIX};
    }

    my @guesses = (
	'/home/linuxbrew/.linuxbrew/opt/openssl/bin/openssl' => '/home/linuxbrew/.linuxbrew/opt/openssl', # LinuxBrew openssl
	'/usr/local/opt/openssl/bin/openssl' => '/usr/local/opt/openssl', # OSX homebrew openssl
	'/usr/local/bin/openssl'         => '/usr/local', # OSX homebrew openssl
	'/opt/local/bin/openssl'         => '/opt/local', # Macports openssl
	'/usr/bin/openssl'               => '/usr',
	'/usr/sbin/openssl'              => '/usr',
	'/opt/ssl/bin/openssl'           => '/opt/ssl',
	'/opt/ssl/sbin/openssl'          => '/opt/ssl',
	'/usr/local/ssl/bin/openssl'     => '/usr/local/ssl',
	'/usr/local/openssl/bin/openssl' => '/usr/local/openssl',
	'/apps/openssl/std/bin/openssl'  => '/apps/openssl/std',
	'/usr/sfw/bin/openssl'           => '/usr/sfw', # Open Solaris
	'C:\OpenSSL\bin\openssl.exe'     => 'C:\OpenSSL',
	'C:\OpenSSL-Win32\bin\openssl.exe'        => 'C:\OpenSSL-Win32',
	$Config{prefix} . '\bin\openssl.exe'      => $Config{prefix},           # strawberry perl
	$Config{prefix} . '\..\c\bin\openssl.exe' => $Config{prefix} . '\..\c', # strawberry perl
	'/sslexe/openssl.exe'            => '/sslroot',  # VMS, openssl.org
	'/ssl1$exe/openssl.exe'          => '/ssl1$root',# VMS, VSI or HPE install
	'/ssl$exe/openssl.exe'           => '/ssl$root', # VMS, HP install
    );

    while (my $k = shift @guesses
           and my $v = shift @guesses) {
        if ( -x $k ) {
            return $v;
        }
    }
    (undef, $dir) = check_no_path()
       and return $dir;

    return;
}

sub find_openssl_exec {
    my ($prefix) = @_;

    my $exe_path;
    for my $subdir (qw( bin sbin out32dll ia64_exe alpha_exe )) {
        my $path = File::Spec->catfile($prefix, $subdir, "openssl$Config{_exe}");
        if ( -x $path ) {
            return $path;
        }
    }
    ($prefix) = check_no_path()
       and return $prefix;
    return;
}

sub check_openssl_version {
    my ($prefix, $exec) = @_;
    my ($output, $major, $minor, $letter);

    {
        my $pipe = gensym();
        open($pipe, qq{"$exec" version |})
            or die "Could not execute $exec";
        $output = <$pipe>;
        chomp $output;
        close $pipe;

	if ( ($major, $minor, $letter) = $output =~ /^OpenSSL\s+(\d+\.\d+)\.(\d+)([a-z]?)/ ) {
	    print "*** Found OpenSSL-${major}.${minor}${letter} installed in $prefix\n";
	} elsif ( ($major, $minor) = $output =~ /^LibreSSL\s+(\d+\.\d+)\.(\d+)/ ) {
	    print "*** Found LibreSSL-${major}.${minor} installed in $prefix\n";
	} else {
            die <<EOM
*** OpenSSL version test failed
    (`$output' has been returned)
    Either you have bogus OpenSSL or a new version has changed the version
    number format. Please inform the authors!
EOM
        }
    }

    if ($major < 0.9 || ($major == 0.9 && $minor < 3)) {
        print <<EOM;
*** That's too old!
    Please upgrade OpenSSL to the latest version (http://www.openssl.org/)
EOM
        exit 0; # according http://wiki.cpantesters.org/wiki/CPANAuthorNotes this is best-practice when "missing library"
    }

    # On Windows, 64-bit versions of OpenSSL from 1.0.0-beta1 to 1.0.0b are
    # known to malfunction when used in conjunction with pseudoforking processes
    # (see GH-189)
    if (    $Config{archname} =~ m{^MSWin32-x64}
         && $output =~ m{^OpenSSL \s+ 1\.0\.0 (?:-beta[1-5]|[ab])}x ) {
        print <<EOM;
*** 64-bit versions of OpenSSL from 1.0.0-beta1 to 1.0.0b are broken on Windows.
    Please upgrade to OpenSSL 1.0.0c or newer.
EOM
        exit 0;
    }

    if ($major == 1.1 && $minor > 1) {
        print <<EOM;
*** That's newer than what this module was tested with
    You should consider checking if there is a newer release of this module
    available. Everything will probably work OK, though.
EOM
    }
}

sub fixpath {
    my ($text) = @_;
    my $sep = File::Spec->catdir('');
    $text =~ s{\b/}{$sep}g;
    return $text;
}
