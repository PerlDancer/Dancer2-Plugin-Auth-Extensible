use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer2::Plugin::Auth::Extensible',
    AUTHOR              => q{David Precious <davidp@preshweb.co.uk>},
    VERSION_FROM        => 'lib/Dancer2/Plugin/Auth/Extensible.pm',
    ABSTRACT_FROM       => 'lib/Dancer2/Plugin/Auth/Extensible.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.48
      ? ('MIN_PERL_VERSION'=> '5.6.0')
      : ()),
    ($ExtUtils::MakeMaker::VERSION >= 6.48
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    BUILD_REQUIRES => {
        'DateTime' => 0,
        'HTTP::Cookies' => 0,
        'HTTP::Request::Common' => 0,
        'Path::Tiny' => '0.016',
        'Plack::Test' => 0,
        'Test::Deep' => 0,
        'Test::Exception' => 0,
        'Test::MockDateTime' => 0,
        'Test::More' => 0,
        'Test::Warnings' => 0,
    },
    PREREQ_PM => {
        'Carp'              => 0,
        'Dancer2'           => '0.200000',
        'Dancer2::Core::Types' => 0,
        'Dancer2::Plugin'   => 0,
        'Module::Runtime'   => 0,
        'Crypt::SaltedHash' => 0,
        'List::Util'        => 0,
        'Moo'               => '2.000000',
        'Moo::Role'         => 0,
        'namespace::clean'  => 0,
        'YAML'              => 0, # for config files and tests
        'Session::Token'    => 0,
        'Try::Tiny'         => 0,
        'Plack'             => '1.0029', # OO-style Plack::Test
    },
    EXE_FILES => [ 'bin/dancer2-generate-crypted-password' ],
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer2-Plugin-Auth-Extensible-*' },
    META_MERGE => {
        resources => {
            repository => 'https://github.com/PerlDancer/Dancer2-Plugin-Auth-Extensible',
            bugtracker => 'https://github.com/PerlDancer/Dancer2-Plugin-Auth-Extensible/issues',
            homepage   => 'https://github.com/PerlDancer/Dancer2-Plugin-Auth-Extensible/',
            IRC        => 'irc://irc.perl.org/#dancer',
        },
    },

);
