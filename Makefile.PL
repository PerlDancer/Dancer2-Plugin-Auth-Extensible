use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer2::Plugin::Auth::Extensible',
    AUTHOR              => q{David Precious <davidp@preshweb.co.uk>},
    VERSION_FROM        => 'lib/Dancer2/Plugin/Auth/Extensible.pm',
    ABSTRACT_FROM       => 'lib/Dancer2/Plugin/Auth/Extensible.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.48
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    BUILD_REQUIRES => {
        'Module::Load::Conditional' => 0,
        'Path::Tiny' => '0.016',
        'Test::Deep' => 0,
        'Test::More' => 0,
    },
    PREREQ_PM => {
        'Dancer2'           => 0.15,
        'Class::Load'       => 0,
        'Crypt::SaltedHash' => 0,
        'Moo'               => '2.000000',
        'namespace::clean'  => 0,
        'YAML'              => 0, # for config files and tests
        'Safe::Isa'         => 0,
        'Session::Token'    => 0,
        'Sub::Quote'        => 0,
        'Try::Tiny'         => 0,
    },
    EXE_FILES => [ 'bin/generate-crypted-password' ],
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
