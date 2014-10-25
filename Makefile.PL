use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer2::Plugin::Auth::Extensible',
    AUTHOR              => q{David Precious <davidp@preshweb.co.uk>},
    VERSION_FROM        => 'lib/Dancer2/Plugin/Auth/Extensible.pm',
    ABSTRACT_FROM       => 'lib/Dancer2/Plugin/Auth/Extensible.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Mock::Quick' => 0,
        'Dancer2'     => 0,
        'Crypt::SaltedHash' => 0,
        'YAML'       => 0, # for config files (TODO: make optional?)
        
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer2-Plugin-Auth-Extensible-*' },
    META_MERGE => {
        resources => {
            repository => 'https://github.com/racke/Dancer2-Plugin-Auth-Extensible',
            bugtracker => 'https://github.com/racke/Dancer2-Plugin-Auth-Extensible/issues',
            homepage   => 'https://github.com/racke/Dancer2-Plugin-Auth-Extensible/',
        },
    },

);
